//! OS 別のディレクトリ解決。Linux は XDG Base Directory Specification に従う。

use anyhow::{Context, Result, anyhow};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq)]
pub struct Paths {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub incidents_dir: PathBuf,
    pub logs_dir: PathBuf,
    pub reports_dir: PathBuf,
    pub lock_dir: PathBuf,
    /// XDG_RUNTIME_DIR が無くロックを state 側へ退避したとき true
    pub lock_fallback: bool,
}

impl Paths {
    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join("config.toml")
    }

    pub fn db_file(&self) -> PathBuf {
        self.data_dir.join("kuda.db")
    }

    pub fn lock_file(&self) -> PathBuf {
        self.lock_dir.join("kuda.lock")
    }

    pub fn from_env() -> Result<Self> {
        Self::resolve(cfg!(windows), |key| std::env::var(key).ok())
    }

    fn resolve(windows: bool, env: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let var = |key: &str| env(key).filter(|v| !v.is_empty());

        if let Some(home) = var("KUDA_HOME") {
            let root =
                std::path::absolute(&home).with_context(|| format!("invalid KUDA_HOME: {home}"))?;
            return Ok(Self::single_root(root));
        }
        if windows {
            let local = var("LOCALAPPDATA").ok_or_else(|| anyhow!("LOCALAPPDATA is not set"))?;
            return Ok(Self::single_root(PathBuf::from(local).join("kuda")));
        }

        let home = var("HOME").ok_or_else(|| anyhow!("HOME is not set"))?;
        // 仕様どおり、相対パスの値は無効として既定値へ戻す
        let xdg = |key: &str, default: &str| {
            var(key)
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
                .unwrap_or_else(|| Path::new(&home).join(default))
                .join("kuda")
        };
        let state = xdg("XDG_STATE_HOME", ".local/state");
        let runtime = var("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute());

        Ok(Self {
            config_dir: xdg("XDG_CONFIG_HOME", ".config"),
            incidents_dir: state.join("incidents"),
            logs_dir: state.join("logs"),
            reports_dir: xdg("XDG_DATA_HOME", ".local/share").join("reports"),
            lock_fallback: runtime.is_none(),
            lock_dir: runtime.map_or_else(|| state.join("run"), |dir| dir.join("kuda")),
            data_dir: state,
        })
    }

    fn single_root(root: PathBuf) -> Self {
        Self {
            data_dir: root.join("data"),
            lock_dir: root.join("data"),
            incidents_dir: root.join("incidents"),
            logs_dir: root.join("logs"),
            reports_dir: root.join("reports"),
            config_dir: root,
            lock_fallback: false,
        }
    }

    /// 書き込み先のディレクトリを用意する
    pub fn ensure_dirs(&self) -> Result<()> {
        for dir in [
            &self.data_dir,
            &self.incidents_dir,
            &self.logs_dir,
            &self.reports_dir,
            &self.lock_dir,
        ] {
            create_private_dir(dir)?;
        }
        Ok(())
    }
}

/// 無ければ 0700 で作成する。既にあるディレクトリのパーミッションは変えない
pub fn create_private_dir(dir: &Path) -> Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(dir)
        .with_context(|| format!("failed to create {}", dir.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn resolve(windows: bool, vars: &[(&str, &str)]) -> Result<Paths> {
        let vars: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Paths::resolve(windows, |key| vars.get(key).cloned())
    }

    // Windows 上で実行しても比較が成り立つよう、期待値も join で組み立てる
    fn path(root: &str, rest: &[&str]) -> PathBuf {
        rest.iter().fold(PathBuf::from(root), |p, s| p.join(s))
    }

    #[test]
    fn linux_defaults_when_unset_or_empty() {
        let paths = resolve(false, &[("HOME", "/home/u"), ("XDG_STATE_HOME", "")]).unwrap();
        let state = path("/home/u", &[".local/state", "kuda"]);
        assert_eq!(
            paths.config_file(),
            path("/home/u", &[".config", "kuda", "config.toml"])
        );
        assert_eq!(paths.db_file(), state.join("kuda.db"));
        assert_eq!(paths.logs_dir, state.join("logs"));
        assert_eq!(paths.incidents_dir, state.join("incidents"));
        assert_eq!(
            paths.reports_dir,
            path("/home/u", &[".local/share", "kuda", "reports"])
        );
    }

    #[test]
    fn linux_honors_absolute_xdg_values() {
        // 絶対パス判定はビルド先 OS に依存するので Unix でのみ確かめる
        if cfg!(windows) {
            return;
        }
        let paths = resolve(
            false,
            &[
                ("HOME", "/home/u"),
                ("XDG_CONFIG_HOME", "/c"),
                ("XDG_STATE_HOME", "/s"),
                ("XDG_DATA_HOME", "/d"),
                ("XDG_RUNTIME_DIR", "/r"),
            ],
        )
        .unwrap();
        assert_eq!(paths.config_dir, Path::new("/c/kuda"));
        assert_eq!(paths.db_file(), Path::new("/s/kuda/kuda.db"));
        assert_eq!(paths.reports_dir, Path::new("/d/kuda/reports"));
        assert_eq!(paths.lock_file(), Path::new("/r/kuda/kuda.lock"));
        assert!(!paths.lock_fallback);
    }

    #[test]
    fn linux_ignores_relative_xdg_values() {
        let paths = resolve(
            false,
            &[
                ("HOME", "/home/u"),
                ("XDG_CONFIG_HOME", "relative/config"),
                ("XDG_RUNTIME_DIR", "relative/run"),
            ],
        )
        .unwrap();
        assert_eq!(paths.config_dir, path("/home/u", &[".config", "kuda"]));
        assert!(paths.lock_fallback);
    }

    #[test]
    fn linux_lock_falls_back_to_state_without_runtime_dir() {
        let paths = resolve(false, &[("HOME", "/home/u")]).unwrap();
        assert_eq!(
            paths.lock_file(),
            path("/home/u", &[".local/state", "kuda", "run", "kuda.lock"])
        );
        assert!(paths.lock_fallback);
    }

    #[test]
    fn windows_uses_localappdata() {
        let paths = resolve(true, &[("LOCALAPPDATA", "/appdata")]).unwrap();
        let root = Path::new("/appdata").join("kuda");
        assert_eq!(paths.config_file(), root.join("config.toml"));
        assert_eq!(paths.db_file(), root.join("data").join("kuda.db"));
        assert_eq!(paths.lock_file(), root.join("data").join("kuda.lock"));
        assert_eq!(paths.reports_dir, root.join("reports"));
    }

    #[test]
    fn kuda_home_overrides_every_os() {
        let home = std::env::temp_dir().join("kuda-home");
        let home_str = home.to_str().unwrap();
        for windows in [true, false] {
            let paths = resolve(windows, &[("KUDA_HOME", home_str), ("HOME", "/home/u")]).unwrap();
            assert_eq!(paths.config_file(), home.join("config.toml"));
            assert_eq!(paths.db_file(), home.join("data").join("kuda.db"));
            assert_eq!(paths.logs_dir, home.join("logs"));
        }
    }

    #[test]
    fn missing_home_is_an_error() {
        assert!(resolve(false, &[]).is_err());
        assert!(resolve(true, &[]).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn creates_dirs_0700_and_keeps_existing_mode() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!("kuda-perm-{}", std::process::id()));
        let dir = root.join("a");
        create_private_dir(&dir).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o750)).unwrap();
        create_private_dir(&dir).unwrap();
        assert_eq!(mode(&dir), 0o750);
        std::fs::remove_dir_all(root).unwrap();
    }
}
