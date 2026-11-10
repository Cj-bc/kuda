use super::{Backend, Request};
use crate::config::CodexBackend;
use crate::paths::create_private_dir;
use crate::process;
use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const LAST_MESSAGE_FILE: &str = "last-message.md";
const SCRATCH_PREFIX: &str = "codex-";
/// kuda が途中で殺されて残った一時ディレクトリを、これより古ければ消す
const STALE_AFTER: Duration = Duration::from_secs(24 * 60 * 60);

pub struct Codex(pub CodexBackend);

/// `codex-<pid>-<作成時刻 ns>-<連番>` から作成時刻を取り出す。形式が違えば None
fn scratch_created(name: &str) -> Option<u128> {
    let mut parts = name.strip_prefix(SCRATCH_PREFIX)?.split('-');
    let (pid, nanos, count) = (parts.next()?, parts.next()?, parts.next()?);
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if parts.next().is_some() || !digits(pid) || !digits(count) || !digits(nanos) {
        return None;
    }
    nanos.parse().ok()
}

/// kuda が作った形式の名前で、`now` より `STALE_AFTER` 以上前のディレクトリを消す。
/// シンボリックリンクは辿らず、失敗しても調査は続ける
fn remove_stale_scratches(parent: &Path, now: u128) {
    let entries = match std::fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(error) => {
            log::warn!("failed to list {}: {error}", parent.display());
            return;
        }
    };
    for entry in entries.flatten() {
        let Some(created) = entry.file_name().to_str().and_then(scratch_created) else {
            continue;
        };
        // DirEntry::file_type はリンクを辿らない
        if !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            continue;
        }
        if now.saturating_sub(created) < STALE_AFTER.as_nanos() {
            continue;
        }
        let path = entry.path();
        if let Err(error) = std::fs::remove_dir_all(&path) {
            log::warn!("failed to remove {}: {error}", path.display());
        }
    }
}

/// 最終メッセージの書き出し先として毎回新しく作るディレクトリ。破棄時に中身ごと消す。
/// 事件ディレクトリに書くと、仕込まれたシンボリックリンク経由で外へ書かされたり、
/// 事前に置かれたファイルをレポートとして読まされたりする
struct Scratch(PathBuf);

impl Scratch {
    /// 既にある名前は使い回さず、自分で作成に成功したディレクトリだけを使う
    fn create(parent: &Path) -> Result<Self> {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        create_private_dir(parent)?;
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos());
        remove_stale_scratches(parent, nanos);
        #[allow(unused_mut)]
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        loop {
            let count = COUNTER.fetch_add(1, Ordering::Relaxed);
            let pid = std::process::id();
            let dir = parent.join(format!("{SCRATCH_PREFIX}{pid}-{nanos}-{count}"));
            match builder.create(&dir) {
                Ok(()) => return Ok(Self(dir)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("failed to create {}", dir.display()));
                }
            }
        }
    }

    fn last_message(&self) -> PathBuf {
        self.0.join(LAST_MESSAGE_FILE)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_dir_all(&self.0) {
            log::warn!("failed to remove {}: {error}", self.0.display());
        }
    }
}

/// Codex にはコマンド単位の許可リストが無いので、read-only サンドボックスを境界にする。
/// サンドボックスの設定によっては実行コマンドのネットワークも止まる
fn args(incident_dir: &Path, last_message: &Path) -> Vec<String> {
    vec![
        "exec".to_string(),
        "--sandbox".to_string(),
        "read-only".to_string(),
        "--skip-git-repo-check".to_string(),
        "--ephemeral".to_string(),
        "--cd".to_string(),
        incident_dir.display().to_string(),
        "--output-last-message".to_string(),
        last_message.display().to_string(),
        "-".to_string(),
    ]
}

/// サンドボックスで強制できない分は指示として伝える。Codex はファイルもシェル経由で
/// 読むので、事件ディレクトリの読み取りは許可リストの外に置く
fn prompt_with_rules(prompt: &str, allowed_commands: &[String]) -> String {
    const READ_RULE: &str =
        "作業ディレクトリのファイルは、シェルの読み取りコマンドで自由に読んでかまいません。";
    if allowed_commands.is_empty() {
        return format!("{prompt}\n\n{READ_RULE}それ以外のコマンドは実行しないでください。");
    }
    format!(
        "{prompt}\n\n{READ_RULE}それ以外で実行してよいコマンドは次のものだけです: {}",
        allowed_commands.join(", ")
    )
}

impl Backend for Codex {
    fn available(&self) -> Result<String, String> {
        process::find_program(&self.0.command)
            .map(|path| path.display().to_string())
            .ok_or_else(|| format!("command not found: {}", self.0.command))
    }

    fn run(&self, request: &Request) -> Result<String> {
        let program = process::find_program(&self.0.command)
            .with_context(|| format!("command not found: {}", self.0.command))?;
        let scratch = Scratch::create(request.work_dir)?;
        let mut command = process::command(program);
        command
            .args(args(request.incident_dir, &scratch.last_message()))
            .current_dir(request.incident_dir);
        let prompt = prompt_with_rules(request.prompt, request.allowed_commands);
        let output = process::run(command, Some(&prompt), request.timeout)?;
        if output.timed_out {
            bail!("timed out after {:?}", request.timeout);
        }
        if !output.success() {
            bail!("exit code {:?}: {}", output.code, output.stderr.trim());
        }
        let text = std::fs::read_to_string(scratch.last_message()).unwrap_or(output.stdout);
        if text.trim().is_empty() {
            bail!("codex returned an empty result");
        }
        Ok(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runs_read_only_and_reads_prompt_from_stdin() {
        let args = args(Path::new("incident"), Path::new("last-message.md"));
        assert_eq!(args[0], "exec");
        assert!(args.join(" ").contains("--sandbox read-only"));
        assert_eq!(args.last().unwrap(), "-");
    }

    #[test]
    fn states_allowed_commands_in_the_prompt() {
        let allowed = ["ping".to_string(), "tracert".to_string()];
        assert!(prompt_with_rules("p", &allowed).contains("ping, tracert"));
        assert!(prompt_with_rules("p", &[]).contains("実行しないで"));
        assert!(prompt_with_rules("p", &allowed).contains("自由に読んで"));
    }

    #[test]
    fn parses_only_scratch_names_kuda_creates() {
        assert_eq!(scratch_created("codex-12-345-0"), Some(345));
        for name in [
            "codex-12-345",
            "codex-12-345-0-1",
            "codex-x-345-0",
            "codex--345-0",
            "other-12-345-0",
        ] {
            assert_eq!(scratch_created(name), None, "{name}");
        }
    }

    #[test]
    fn removes_only_stale_scratches_on_create() {
        let parent = std::env::temp_dir().join(format!("kuda-codex-stale-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&parent);
        let outside = parent.join("outside");
        std::fs::create_dir_all(outside.join("keep")).unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let recent = format!("codex-1-{}-0", now - Duration::from_secs(60).as_nanos());
        for name in ["codex-1-1-0", &recent, "codex-1-x-0", "notes-1-1-0"] {
            std::fs::create_dir_all(parent.join(name).join("inner")).unwrap();
        }
        std::fs::write(parent.join("codex-2-1-0"), "a file").unwrap();
        #[cfg(unix)]
        let _ = std::os::unix::fs::symlink(&outside, parent.join("codex-3-1-0"));
        #[cfg(windows)]
        let _ = std::os::windows::fs::symlink_dir(&outside, parent.join("codex-3-1-0"));

        let scratch = Scratch::create(&parent).unwrap();
        let exists = |name: &str| std::fs::symlink_metadata(parent.join(name)).is_ok();
        let results = (
            exists("codex-1-1-0"),
            [&recent, "codex-1-x-0", "notes-1-1-0", "codex-2-1-0"].map(exists),
            outside.join("keep").is_dir(),
        );
        drop(scratch);
        std::fs::remove_dir_all(&parent).unwrap();
        assert!(!results.0, "a stale scratch must be removed");
        assert_eq!(results.1, [true; 4], "other entries must be kept");
        assert!(results.2, "a symlink must not be followed");
    }

    /// `--output-last-message` の直後の引数へ `written` を書く偽の codex。
    /// `written` が None なら何も書かず、標準出力に stdout-body を出す
    fn fake_codex(dir: &Path, written: Option<&str>) -> PathBuf {
        let (path, script) = if cfg!(windows) {
            let write = written.map_or("echo stdout-body".to_string(), |text| {
                format!("(echo {text})> \"%out%\"")
            });
            let find = [
                "@echo off",
                ":next",
                "if \"%~1\"==\"\" goto done",
                "if \"%~1\"==\"--output-last-message\" set \"out=%~2\"",
                "shift",
                "goto next",
                ":done",
            ]
            .join("\r\n");
            (dir.join("fake-codex.cmd"), format!("{find}\r\n{write}\r\n"))
        } else {
            let write = written.map_or("echo stdout-body".to_string(), |text| {
                format!("echo {text} > \"$out\"")
            });
            let find = "while [ $# -gt 0 ]; do\n\
                [ \"$1\" = --output-last-message ] && out=\"$2\"\n\
                shift\n\
                done";
            (
                dir.join("fake-codex"),
                format!("#!/bin/sh\n{find}\n{write}\n"),
            )
        };
        std::fs::write(&path, script).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        path
    }

    /// 事件ディレクトリに出力ファイルと同名のファイルを仕込んだうえで codex を走らせる
    fn run_with_planted_file(name: &str, written: Option<&str>) -> (Result<String>, String) {
        let root = std::env::temp_dir().join(format!("kuda-codex-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (incident_dir, work_dir) = (root.join("incident"), root.join("work"));
        std::fs::create_dir_all(&incident_dir).unwrap();
        std::fs::create_dir_all(&work_dir).unwrap();
        let planted = incident_dir.join("codex-last-message.md");
        std::fs::write(&planted, "planted-body").unwrap();
        let codex = Codex(CodexBackend {
            command: fake_codex(&root, written).display().to_string(),
        });
        let result = codex.run(&Request {
            prompt: "p",
            incident_dir: &incident_dir,
            work_dir: &work_dir,
            allowed_commands: &[],
            timeout: Duration::from_secs(30),
        });
        let planted = std::fs::read_to_string(&planted).unwrap();
        let leftovers = std::fs::read_dir(&work_dir).unwrap().count();
        std::fs::remove_dir_all(&root).unwrap();
        assert_eq!(leftovers, 0, "the scratch directory must be removed");
        (result, planted)
    }

    #[test]
    fn writes_the_last_message_outside_the_incident() {
        let (result, planted) = run_with_planted_file("written", Some("fake-body"));
        assert_eq!(result.unwrap().trim(), "fake-body");
        assert_eq!(planted, "planted-body");
    }

    #[test]
    fn ignores_a_planted_last_message() {
        let (result, planted) = run_with_planted_file("planted", None);
        assert_eq!(result.unwrap().trim(), "stdout-body");
        assert_eq!(planted, "planted-body");
    }
}
