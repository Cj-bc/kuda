use super::{Backend, Request};
use crate::config::CodexBackend;
use crate::process;
use anyhow::{Context, Result, bail};
use std::path::Path;

const LAST_MESSAGE_FILE: &str = "codex-last-message.md";

pub struct Codex(pub CodexBackend);

/// Codex にはコマンド単位の許可リストが無いので、read-only サンドボックスを境界にする。
/// サンドボックスの設定によっては実行コマンドのネットワークも止まる
fn args(incident_dir: &Path) -> Vec<String> {
    vec![
        "exec".to_string(),
        "--sandbox".to_string(),
        "read-only".to_string(),
        "--skip-git-repo-check".to_string(),
        "--ephemeral".to_string(),
        "--cd".to_string(),
        incident_dir.display().to_string(),
        "--output-last-message".to_string(),
        incident_dir.join(LAST_MESSAGE_FILE).display().to_string(),
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
        let mut command = process::command(program);
        command
            .args(args(request.incident_dir))
            .current_dir(request.incident_dir);
        let prompt = prompt_with_rules(request.prompt, request.allowed_commands);
        let output = process::run(command, Some(&prompt), request.timeout)?;
        if output.timed_out {
            bail!("timed out after {:?}", request.timeout);
        }
        if !output.success() {
            bail!("exit code {:?}: {}", output.code, output.stderr.trim());
        }
        let text = std::fs::read_to_string(request.incident_dir.join(LAST_MESSAGE_FILE))
            .unwrap_or(output.stdout);
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
        let args = args(Path::new("incident"));
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
}
