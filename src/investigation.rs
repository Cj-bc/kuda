//! 実行中の調査（`kuda diagnose`）の記録。
//!
//! 調査プロセスは detach されるので、check からは親子関係でたどれない。
//! そこで調査の間だけ、状態ディレクトリに (PID, 起動時刻) を置き、
//! プロセスの監視が kuda 自身の仲間として除外できるようにする。

use crate::known_set;
use crate::os::Os;
use crate::paths::Paths;
use crate::probe::{self, ProcessInfo};
use anyhow::{Context, Result};
use std::path::PathBuf;

const PREFIX: &str = "investigating-";

/// 記録を、Drop で消す。異常終了で残っても、`running` が生きていないものとして無視する
pub struct Registration(PathBuf);

impl Drop for Registration {
    fn drop(&mut self) {
        // 消せなくても出来ることがない。残っても害はない（`running` が無視し、次の調査が上書きする）
        let _ = std::fs::remove_file(&self.0);
    }
}

/// 自プロセスを調査プロセスとして記録する。
/// `processes` は今の列挙結果で、自分の起動時刻を引くのに使う。引けなければ記録しない
pub fn register(
    paths: &Paths,
    watch: &str,
    processes: &[ProcessInfo],
) -> Result<Option<Registration>> {
    let Some((pid, started)) = known_set::own_root(processes) else {
        return Ok(None);
    };
    // 同じ watch の調査が重なっても（ロックを取る前の短い間など）、互いの記録を
    // 上書きしたり、Drop で消したりしないよう、PID ごとに分ける
    let path = paths.data_dir.join(format!("{PREFIX}{watch}-{pid}"));
    std::fs::write(&path, format!("{pid} {started}"))
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(Some(Registration(path)))
}

/// 生きている調査プロセスの (PID, 起動時刻)。
/// 一致するプロセスがいない記録は無視するだけで消さない。check の列挙の直後に始まった調査の
/// 記録も、列挙結果には一致しないので、消すと生きている調査を巻き込む
pub fn running(paths: &Paths, processes: &[ProcessInfo]) -> Vec<(u32, i64)> {
    let Ok(entries) = std::fs::read_dir(&paths.data_dir) else {
        return Vec::new();
    };
    let mut roots = Vec::new();
    for entry in entries.flatten() {
        if !entry.file_name().to_string_lossy().starts_with(PREFIX) {
            continue;
        }
        let Some(root) = std::fs::read_to_string(entry.path())
            .ok()
            .and_then(|text| parse(&text))
        else {
            // 書き込み途中かもしれないので、読めないものは触らない
            continue;
        };
        if processes
            .iter()
            .any(|p| p.pid == root.0 && probe::same_start(Os::current(), root.1, p.started))
        {
            roots.push(root);
        }
    }
    roots
}

/// プロセスの監視から除く根: kuda 自身と、実行中の調査プロセス。
/// 分類とスナップショットで同じ根を使わないと、事件の差分と分類が食い違う
pub fn excluded_roots(paths: &Paths, processes: &[ProcessInfo]) -> Vec<(u32, i64)> {
    let mut roots: Vec<_> = known_set::own_root(processes).into_iter().collect();
    roots.extend(running(paths, processes));
    roots
}

fn parse(text: &str) -> Option<(u32, i64)> {
    let (pid, started) = text.trim().split_once(' ')?;
    Some((pid.parse().ok()?, started.parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;

    /// 記録ファイルは data_dir に置かれるので、そこだけ用意する。
    /// 一時ディレクトリは Paths より長く生かす（返り値を `_dir` に受ける）
    fn paths(name: &str) -> (TempDir, Paths) {
        let dir = TempDir::new(&format!("inv-{name}"));
        let paths = dir.paths();
        std::fs::create_dir_all(&paths.data_dir).unwrap();
        (dir, paths)
    }

    fn me(started: i64) -> ProcessInfo {
        ProcessInfo {
            pid: std::process::id(),
            ppid: None,
            name: "kuda".to_string(),
            path: None,
            user: None,
            started: Some(started),
            kernel_thread: false,
            deleted: false,
        }
    }

    #[test]
    fn registration_is_visible_while_alive_and_removed_on_drop() {
        let (_dir, paths) = paths("live");
        let processes = [me(42)];
        let registration = register(&paths, "w", &processes).unwrap().unwrap();
        assert_eq!(running(&paths, &processes), [(std::process::id(), 42)]);
        drop(registration);
        assert!(running(&paths, &processes).is_empty());
    }

    #[test]
    fn stale_records_are_ignored_but_kept() {
        let (_dir, paths) = paths("stale");
        let registration = register(&paths, "w", &[me(42)]).unwrap().unwrap();
        // 同じ PID でも起動時刻が違えば、別のプロセスが PID を再利用している
        assert!(running(&paths, &[me(500)]).is_empty());
        // 消さない。列挙の直後に始まった調査の記録かもしれない
        assert!(registration.0.exists());
        assert_eq!(running(&paths, &[me(42)]).len(), 1);
        // Linux では列挙ごとに 1 秒ずれうる（btime）ので、1 秒差は同じプロセスとみなす
        let tolerated = usize::from(Os::current() == Os::Linux);
        assert_eq!(running(&paths, &[me(43)]).len(), tolerated);
        std::mem::forget(registration);
    }

    #[test]
    fn excluded_roots_cover_this_process_and_running_investigations() {
        let (_dir, paths) = paths("excluded");
        let investigator = ProcessInfo {
            pid: 7,
            started: Some(99),
            ..me(0)
        };
        std::fs::write(paths.data_dir.join(format!("{PREFIX}w")), "7 99").unwrap();
        let roots = excluded_roots(&paths, &[me(42), investigator]);
        assert_eq!(roots, [(std::process::id(), 42), (7, 99)]);
    }

    /// 同じ watch の別の調査（別の PID）の記録は、自分の Drop で消えない
    #[test]
    fn records_are_kept_per_process() {
        let (_dir, paths) = paths("per-pid");
        let other = paths.data_dir.join(format!("{PREFIX}w-7"));
        std::fs::write(&other, "7 99").unwrap();
        let investigator = ProcessInfo {
            pid: 7,
            started: Some(99),
            ..me(0)
        };
        let registration = register(&paths, "w", &[me(42)]).unwrap().unwrap();
        drop(registration);
        assert!(other.exists());
        assert_eq!(running(&paths, &[investigator]), [(7, 99)]);
    }

    #[test]
    fn nothing_is_recorded_without_a_start_time() {
        let (_dir, paths) = paths("nostart");
        let mut unknown = me(1);
        unknown.started = None;
        assert!(register(&paths, "w", &[unknown]).unwrap().is_none());
    }

    #[test]
    fn unreadable_records_are_left_alone() {
        let (_dir, paths) = paths("garbage");
        let file = paths.data_dir.join(format!("{PREFIX}w"));
        std::fs::write(&file, "12").unwrap();
        assert!(running(&paths, &[me(1)]).is_empty());
        assert!(file.exists());
    }
}
