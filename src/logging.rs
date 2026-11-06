//! 日付ローテーションするファイルログ。GUI サブシステムのリリースビルドでは
//! 標準出力が見えないため、ログは必ずファイルへ出す。

use anyhow::{Context, Result};
use chrono::{Local, NaiveDate};
use log::{Level, LevelFilter, Log, Metadata, Record};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

struct FileLogger {
    dir: PathBuf,
    mirror_stderr: bool,
    /// 開いているファイルとその日付。日付が変わったら開き直す
    current: Mutex<Option<(NaiveDate, File)>>,
}

impl Log for FileLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.target().starts_with("kuda")
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let now = Local::now();
        let line = format!(
            "{} {:<5} [{}] {}\n",
            now.format("%Y-%m-%dT%H:%M:%S%:z"),
            record.level(),
            std::process::id(),
            record.args()
        );
        if self.mirror_stderr || record.level() == Level::Error {
            eprint!("{line}");
        }
        let Ok(mut current) = self.current.lock() else {
            return;
        };
        let today = now.date_naive();
        if current.as_ref().is_none_or(|(date, _)| *date != today) {
            let opened = OpenOptions::new()
                .create(true)
                .append(true)
                .open(self.dir.join(log_file_name(today)));
            *current = opened.ok().map(|file| (today, file));
        }
        if let Some((_, file)) = current.as_mut() {
            let _ = file.write_all(line.as_bytes());
        }
    }

    fn flush(&self) {}
}

fn log_file_name(date: NaiveDate) -> String {
    format!("kuda-{}.log", date.format("%Y-%m-%d"))
}

fn parse_log_date(file_name: &str) -> Option<NaiveDate> {
    let date = file_name.strip_prefix("kuda-")?.strip_suffix(".log")?;
    NaiveDate::parse_from_str(date, "%Y-%m-%d").ok()
}

pub fn init(dir: &Path, verbose: bool) -> Result<()> {
    log::set_boxed_logger(Box::new(FileLogger {
        dir: dir.to_path_buf(),
        mirror_stderr: verbose,
        current: Mutex::new(None),
    }))
    .context("logger is already initialized")?;
    set_level(LevelFilter::Info, verbose);
    Ok(())
}

/// 設定を読む前にもログを出せるよう、レベルは初期化と分けて後から設定する
pub fn set_level(level: LevelFilter, verbose: bool) {
    log::set_max_level(if verbose { LevelFilter::Debug } else { level });
}

/// `retention_days` より古いログを削除する
pub fn prune(dir: &Path, retention_days: u32, today: NaiveDate) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let Some(date) = entry.file_name().to_str().and_then(parse_log_date) else {
            continue;
        };
        if (today - date).num_days() > i64::from(retention_days) {
            std::fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prune_removes_only_expired_kuda_logs() {
        let dir = std::env::temp_dir().join(format!("kuda-logs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let today = NaiveDate::from_ymd_opt(2026, 11, 20).unwrap();
        for name in ["kuda-2026-11-06.log", "kuda-2026-11-05.log", "other.log"] {
            std::fs::write(dir.join(name), "").unwrap();
        }
        prune(&dir, 14, today).unwrap();
        assert!(dir.join("kuda-2026-11-06.log").exists());
        assert!(!dir.join("kuda-2026-11-05.log").exists());
        assert!(dir.join("other.log").exists());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
