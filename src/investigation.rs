//! 実行中の調査（`kuda diagnose`）の記録。
//!
//! 調査プロセスは detach されるので、check からは親子関係でたどれない。
//! そこで調査の間だけ、状態ディレクトリに (PID, 起動時刻) を置き、
//! プロセスの監視が kuda 自身の仲間として除外できるようにする。

use crate::known_set;
use crate::paths::Paths;
use crate::probe::ProcessInfo;
use anyhow::{Context, Result};
use std::path::PathBuf;

const PREFIX: &str = "investigating-";

/// 記録を、Drop で消す。異常終了で残っても、`running` が生きていないものとして掃除する
pub struct Registration(PathBuf);

impl Drop for Registration {
    fn drop(&mut self) {
        // 消せなくても出来ることがない。残っても次の check が掃除する
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
    let path = paths.data_dir.join(format!("{PREFIX}{watch}"));
    std::fs::write(&path, format!("{pid} {started}"))
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(Some(Registration(path)))
}

/// 生きている調査プロセスの (PID, 起動時刻)。
/// PID と起動時刻が一致するプロセスがいない記録は、前回の異常終了の残りなので消す
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
            .any(|p| p.pid == root.0 && p.started == Some(root.1))
        {
            roots.push(root);
        } else {
            let _ = std::fs::remove_file(entry.path());
        }
    }
    roots
}

fn parse(text: &str) -> Option<(u32, i64)> {
    let (pid, started) = text.trim().split_once(' ')?;
    Some((pid.parse().ok()?, started.parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(name: &str) -> Paths {
        let dir = std::env::temp_dir().join(format!("kuda-inv-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Paths {
            config_dir: dir.clone(),
            data_dir: dir.clone(),
            incidents_dir: dir.clone(),
            logs_dir: dir.clone(),
            reports_dir: dir.clone(),
            lock_dir: dir,
            lock_fallback: false,
        }
    }

    fn me(started: i64) -> ProcessInfo {
        ProcessInfo {
            pid: std::process::id(),
            ppid: None,
            name: "kuda".to_string(),
            path: None,
            user: None,
            started: Some(started),
        }
    }

    #[test]
    fn registration_is_visible_while_alive_and_removed_on_drop() {
        let paths = paths("live");
        let processes = [me(42)];
        let registration = register(&paths, "w", &processes).unwrap().unwrap();
        assert_eq!(running(&paths, &processes), [(std::process::id(), 42)]);
        drop(registration);
        assert!(running(&paths, &processes).is_empty());
        std::fs::remove_dir_all(&paths.data_dir).unwrap();
    }

    #[test]
    fn stale_records_are_ignored_and_cleaned_up() {
        let paths = paths("stale");
        let registration = register(&paths, "w", &[me(42)]).unwrap().unwrap();
        // 同じ PID でも起動時刻が違えば、別のプロセスが PID を再利用している
        assert!(running(&paths, &[me(43)]).is_empty());
        assert!(!registration.0.exists());
        std::mem::forget(registration);
        std::fs::remove_dir_all(&paths.data_dir).unwrap();
    }

    #[test]
    fn nothing_is_recorded_without_a_start_time() {
        let paths = paths("nostart");
        let mut unknown = me(1);
        unknown.started = None;
        assert!(register(&paths, "w", &[unknown]).unwrap().is_none());
        std::fs::remove_dir_all(&paths.data_dir).unwrap();
    }

    #[test]
    fn unreadable_records_are_left_alone() {
        let paths = paths("garbage");
        let file = paths.data_dir.join(format!("{PREFIX}w"));
        std::fs::write(&file, "12").unwrap();
        assert!(running(&paths, &[me(1)]).is_empty());
        assert!(file.exists());
        std::fs::remove_dir_all(&paths.data_dir).unwrap();
    }
}
