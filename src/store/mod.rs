//! SQLite: メトリクス・集計・スナップショット・判定状態。
//!
//! `Store` のメソッドは扱うテーブルごとにサブモジュールへ分けている。

mod hist;
mod identities;
mod metrics;
mod schema;
mod snapshot;
mod state;
#[cfg(test)]
mod tests;

use anyhow::{Context, Result, bail};
#[cfg(test)]
use rusqlite::params;
use rusqlite::{Connection, TransactionBehavior};
use schema::*;
use std::path::Path;
use std::time::Duration;

pub use hist::V1Hist;
pub use identities::IdentityStatus;
pub use metrics::MetricRow;
pub use state::{ProbeState, SnapshotState};

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        let conn =
            Connection::open(path).with_context(|| format!("failed to open {}", path.display()))?;
        Self::init(conn, path)
    }

    #[cfg(test)]
    pub fn in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?, Path::new(":memory:"))
    }

    /// 版 1 のスキーマで `hist` (watch, series, bucket, bin, count) を記録した DB を開く
    #[cfg(test)]
    pub fn in_memory_v1(hist: &[(&str, &str, i64, i64, i64)]) -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(&format!("{SCHEMA_V1} PRAGMA user_version = 1;"))?;
        for row in hist {
            conn.execute(
                "INSERT INTO baseline_hist (watch, series, bucket, bin, count)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![row.0, row.1, row.2, row.3, row.4],
            )?;
        }
        Self::init(conn, Path::new(":memory:"))
    }

    /// `path` はエラーメッセージに出すためのもの
    fn init(conn: Connection, path: &Path) -> Result<Self> {
        // 調査プロセスと次の check が同時に開いても待ち合わせで済むようにする
        conn.busy_timeout(Duration::from_secs(10))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        let mut store = Self { conn };
        store.migrate(path)?;
        Ok(store)
    }

    fn version(conn: &Connection) -> Result<usize> {
        let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
        Ok(version as usize)
    }

    /// `user_version` の版から最新版まで 1 段ずつ上げる。
    /// 同時に開いた別プロセスと二重に適用しないよう、版の確認と適用を同じ書き込みトランザクションで行う。
    /// 新しい kuda が上げた DB は読み方が分からないので開かない（ダウングレードは非対応）
    fn migrate(&mut self, path: &Path) -> Result<()> {
        // 最新版なら書き込みロックを取らずに済ませる
        if Self::version(&self.conn)? == MIGRATIONS.len() {
            return Ok(());
        }
        loop {
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let version = Self::version(&tx)?;
            if version == MIGRATIONS.len() {
                return Ok(());
            }
            let Some(migration) = MIGRATIONS.get(version) else {
                bail!(
                    "{} has schema version {version}, but this kuda supports up to {}. \
                     Update kuda, or move the database aside to start over",
                    path.display(),
                    MIGRATIONS.len()
                );
            };
            tx.execute_batch(migration).with_context(|| {
                format!(
                    "failed to migrate {} to schema version {}",
                    path.display(),
                    version + 1
                )
            })?;
            tx.pragma_update(None, "user_version", (version + 1) as i64)?;
            tx.commit()?;
        }
    }
}
