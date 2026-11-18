//! 単体テストが共有する足場。テストごとの一時ディレクトリ、`Paths`、probe の結果の組み立て

use crate::paths::Paths;
use crate::probe::{ProbeRun, ProcessInfo, TargetResult};
use std::ops::Deref;
use std::path::{Path, PathBuf};

/// テストごとの空の一時ディレクトリ。drop で片付ける。
/// 名前とプロセス ID で一意にするので、並行して走る他のテストとも、前回の残りとも衝突しない。
/// 中のファイルを握る DB 接続などより先に宣言する（ローカル変数は宣言の逆順に drop されるので、
/// 接続が先に閉じてからディレクトリが消える）
pub(crate) struct TempDir(PathBuf);

impl TempDir {
    pub(crate) fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("kuda-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    /// この一時ディレクトリを root にした、本物と同じ配置の `Paths`
    pub(crate) fn paths(&self) -> Paths {
        Paths::single_root(self.0.clone())
    }
}

impl Deref for TempDir {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// target "t" の結果。error と value は空
pub(crate) fn target_result(ok: bool, rtt_ms: Option<f64>) -> TargetResult {
    TargetResult {
        target: "t".to_string(),
        ok,
        rtt_ms,
        value: None,
        error: None,
    }
}

pub(crate) fn probe_run(ts: i64, results: Vec<TargetResult>) -> ProbeRun {
    ProbeRun {
        ts,
        results,
        processes: None,
    }
}

/// 起動時刻だけ持つプロセス。ppid と user は無い
pub(crate) fn process(pid: u32, name: &str, path: Option<&str>) -> ProcessInfo {
    ProcessInfo {
        pid,
        ppid: None,
        name: name.to_string(),
        path: path.map(str::to_string),
        user: None,
        started: Some(1),
    }
}

impl AsRef<Path> for TempDir {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}
