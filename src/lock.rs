//! 多重起動防止。

use anyhow::{Context, Result};
use fd_lock::RwLock;
use std::fs::{File, OpenOptions};
use std::io::ErrorKind;
use std::path::Path;

/// ロックを取得し、プロセスの終了まで保持する。他のプロセスが保持中なら false を返す
pub fn hold_until_exit(path: &Path) -> Result<bool> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    // ガードは RwLock を借用する。プロセス終了まで手放さないので leak で寿命を延ばす
    let lock: &'static mut RwLock<File> = Box::leak(Box::new(RwLock::new(file)));
    match lock.try_write() {
        Ok(guard) => {
            std::mem::forget(guard);
            Ok(true)
        }
        Err(error) if error.kind() == ErrorKind::WouldBlock => Ok(false),
        Err(error) => Err(error).with_context(|| format!("failed to lock {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_holder_is_refused() {
        let path = std::env::temp_dir().join(format!("kuda-lock-{}.lock", std::process::id()));
        assert!(hold_until_exit(&path).unwrap());
        assert!(!hold_until_exit(&path).unwrap());
    }
}
