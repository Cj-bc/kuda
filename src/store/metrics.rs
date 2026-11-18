//! probe の生データ（結果と指標）。

use super::Store;
use crate::probe::{ProbeRun, TargetResult};
use anyhow::Result;
use rusqlite::params;

#[derive(Debug, Clone, PartialEq)]
pub struct MetricRow {
    pub ts: i64,
    pub name: String,
    pub value: f64,
}

impl Store {
    pub fn record_run(&mut self, watch: &str, run: &ProbeRun) -> Result<()> {
        let tx = self.conn.transaction()?;
        for result in &run.results {
            tx.execute(
                "INSERT INTO probe_results (watch, ts, target, ok, rtt_ms, value, error)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    watch,
                    run.ts,
                    result.target,
                    result.ok,
                    result.rtt_ms,
                    result.value,
                    result.error
                ],
            )?;
        }
        for (name, value) in run.metrics() {
            tx.execute(
                "INSERT INTO metrics (watch, ts, name, value) VALUES (?1, ?2, ?3, ?4)",
                params![watch, run.ts, name, value],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// `before` より古い生データを削除する
    pub fn prune_metrics(&self, watch: &str, before: i64) -> Result<()> {
        for table in ["probe_results", "metrics"] {
            self.conn.execute(
                &format!("DELETE FROM {table} WHERE watch = ?1 AND ts < ?2"),
                params![watch, before],
            )?;
        }
        Ok(())
    }

    /// 新しいものから `limit` 回分の probe の指標を、古い順で返す
    pub fn recent_metrics(&self, watch: &str, limit: u32) -> Result<Vec<MetricRow>> {
        let mut statement = self.conn.prepare(
            "SELECT ts, name, value FROM metrics
             WHERE watch = ?1 AND ts IN (
                 SELECT DISTINCT ts FROM metrics WHERE watch = ?1 ORDER BY ts DESC LIMIT ?2
             )
             ORDER BY ts, name",
        )?;
        let rows = statement.query_map(params![watch, limit], |row| {
            Ok(MetricRow {
                ts: row.get(0)?,
                name: row.get(1)?,
                value: row.get(2)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// 保持期間内の probe 回数
    pub fn sample_count(&self, watch: &str) -> Result<u64> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(DISTINCT ts) FROM metrics WHERE watch = ?1",
            params![watch],
            |row| row.get(0),
        )?;
        Ok(count as u64)
    }

    /// 直近の probe の結果
    pub fn last_results(&self, watch: &str) -> Result<Vec<TargetResult>> {
        let mut statement = self.conn.prepare(
            "SELECT target, ok, rtt_ms, value, error FROM probe_results
             WHERE watch = ?1
               AND ts = (SELECT MAX(ts) FROM probe_results WHERE watch = ?1)
             ORDER BY rowid",
        )?;
        let rows = statement.query_map(params![watch], |row| {
            Ok(TargetResult {
                target: row.get(0)?,
                ok: row.get(1)?,
                rtt_ms: row.get(2)?,
                value: row.get(3)?,
                error: row.get(4)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
}
