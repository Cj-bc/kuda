//! SQLite: メトリクス・集計・スナップショット・判定状態。

use crate::probe::{ProbeRun, TargetResult};
use crate::trigger::TriggerState;
use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::Value;
use std::path::Path;
use std::time::Duration;

const SCHEMA: &str = "
    CREATE TABLE probe_results (
        watch TEXT NOT NULL,
        ts INTEGER NOT NULL,
        target TEXT NOT NULL,
        ok INTEGER NOT NULL,
        rtt_ms REAL,
        value REAL,
        error TEXT
    );
    CREATE INDEX probe_results_watch_ts ON probe_results (watch, ts);

    CREATE TABLE metrics (
        watch TEXT NOT NULL,
        ts INTEGER NOT NULL,
        name TEXT NOT NULL,
        value REAL NOT NULL
    );
    CREATE INDEX metrics_watch_ts ON metrics (watch, ts);

    -- 時間帯別の分布。metrics_retention を超えて蓄積する
    CREATE TABLE baseline_hist (
        watch TEXT NOT NULL,
        series TEXT NOT NULL,
        bucket INTEGER NOT NULL,
        bin INTEGER NOT NULL,
        count INTEGER NOT NULL,
        PRIMARY KEY (watch, series, bucket, bin)
    ) WITHOUT ROWID;

    CREATE TABLE snapshots (
        watch TEXT NOT NULL,
        ts INTEGER NOT NULL,
        data TEXT NOT NULL
    );
    CREATE INDEX snapshots_watch_ts ON snapshots (watch, ts);

    CREATE TABLE watch_state (
        watch TEXT PRIMARY KEY,
        last_probe INTEGER,
        last_snapshot INTEGER,
        streak INTEGER NOT NULL,
        since INTEGER,
        last_fired INTEGER,
        active INTEGER NOT NULL
    ) WITHOUT ROWID;
";

#[derive(Debug, Clone, Default, PartialEq)]
pub struct WatchState {
    pub last_probe: Option<i64>,
    pub last_snapshot: Option<i64>,
    pub trigger: TriggerState,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MetricRow {
    pub ts: i64,
    pub name: String,
    pub value: f64,
}

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        let conn =
            Connection::open(path).with_context(|| format!("failed to open {}", path.display()))?;
        Self::init(conn)
    }

    #[cfg(test)]
    pub fn in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        // 調査プロセスと次の check が同時に開いても待ち合わせで済むようにする
        conn.busy_timeout(Duration::from_secs(10))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version == 0 {
            conn.execute_batch(&format!("BEGIN; {SCHEMA} PRAGMA user_version = 1; COMMIT;"))?;
        }
        Ok(Self { conn })
    }

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

    pub fn hist_add(&self, watch: &str, series: &str, bucket: i64, bin: i64) -> Result<()> {
        self.conn.execute(
            "INSERT INTO baseline_hist (watch, series, bucket, bin, count)
             VALUES (?1, ?2, ?3, ?4, 1)
             ON CONFLICT (watch, series, bucket, bin) DO UPDATE SET count = count + 1",
            params![watch, series, bucket, bin],
        )?;
        Ok(())
    }

    /// (bin, 件数) を bin の昇順で返す。`bucket` が None なら全時間帯を合算する
    pub fn hist(&self, watch: &str, series: &str, bucket: Option<i64>) -> Result<Vec<(i64, u64)>> {
        let mut statement = self.conn.prepare(
            "SELECT bin, SUM(count) FROM baseline_hist
             WHERE watch = ?1 AND series = ?2 AND (?3 IS NULL OR bucket = ?3)
             GROUP BY bin ORDER BY bin",
        )?;
        let rows = statement.query_map(params![watch, series, bucket], |row| {
            Ok((row.get(0)?, row.get::<_, i64>(1)? as u64))
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// 正常時のスナップショットを保存し、新しい `keep` 件だけを残す
    pub fn save_snapshot(&self, watch: &str, ts: i64, data: &Value, keep: u32) -> Result<()> {
        self.conn.execute(
            "INSERT INTO snapshots (watch, ts, data) VALUES (?1, ?2, ?3)",
            params![watch, ts, data.to_string()],
        )?;
        self.conn.execute(
            "DELETE FROM snapshots WHERE watch = ?1 AND rowid NOT IN (
                 SELECT rowid FROM snapshots WHERE watch = ?1
                 ORDER BY ts DESC, rowid DESC LIMIT ?2
             )",
            params![watch, keep],
        )?;
        Ok(())
    }

    pub fn last_known_good(&self, watch: &str) -> Result<Option<(i64, Value)>> {
        let row: Option<(i64, String)> = self
            .conn
            .query_row(
                "SELECT ts, data FROM snapshots WHERE watch = ?1
                 ORDER BY ts DESC, rowid DESC LIMIT 1",
                params![watch],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        row.map(|(ts, data)| Ok((ts, serde_json::from_str(&data)?)))
            .transpose()
    }

    pub fn load_state(&self, watch: &str) -> Result<WatchState> {
        let state = self
            .conn
            .query_row(
                "SELECT last_probe, last_snapshot, streak, since, last_fired, active
                 FROM watch_state WHERE watch = ?1",
                params![watch],
                |row| {
                    Ok(WatchState {
                        last_probe: row.get(0)?,
                        last_snapshot: row.get(1)?,
                        trigger: TriggerState {
                            streak: row.get(2)?,
                            since: row.get(3)?,
                            last_fired: row.get(4)?,
                            active: row.get(5)?,
                        },
                    })
                },
            )
            .optional()?;
        Ok(state.unwrap_or_default())
    }

    pub fn save_state(&self, watch: &str, state: &WatchState) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO watch_state
             (watch, last_probe, last_snapshot, streak, since, last_fired, active)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                watch,
                state.last_probe,
                state.last_snapshot,
                state.trigger.streak,
                state.trigger.since,
                state.trigger.last_fired,
                state.trigger.active
            ],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn run(ts: i64, ok: bool) -> ProbeRun {
        ProbeRun {
            ts,
            results: vec![TargetResult {
                target: "t".to_string(),
                ok,
                rtt_ms: ok.then_some(10.0),
                value: None,
                error: (!ok).then(|| "boom".to_string()),
            }],
        }
    }

    #[test]
    fn records_and_reads_back_runs() {
        let mut store = Store::in_memory().unwrap();
        store.record_run("w", &run(100, true)).unwrap();
        store.record_run("w", &run(200, false)).unwrap();
        store.record_run("other", &run(300, true)).unwrap();

        assert_eq!(store.sample_count("w").unwrap(), 2);
        let last = store.last_results("w").unwrap();
        assert_eq!(last.len(), 1);
        assert!(!last[0].ok);
        assert_eq!(last[0].error.as_deref(), Some("boom"));
    }

    #[test]
    fn recent_metrics_limits_by_run_and_sorts_ascending() {
        let mut store = Store::in_memory().unwrap();
        for ts in [100, 200, 300] {
            store.record_run("w", &run(ts, true)).unwrap();
        }
        let rows = store.recent_metrics("w", 2).unwrap();
        assert_eq!(rows.first().unwrap().ts, 200);
        assert_eq!(rows.last().unwrap().ts, 300);
    }

    #[test]
    fn prune_keeps_recent_rows_and_baseline() {
        let mut store = Store::in_memory().unwrap();
        store.record_run("w", &run(100, true)).unwrap();
        store.record_run("w", &run(200, true)).unwrap();
        store.hist_add("w", "rtt", 1, 5).unwrap();
        store.prune_metrics("w", 150).unwrap();
        assert_eq!(store.sample_count("w").unwrap(), 1);
        assert_eq!(store.hist("w", "rtt", None).unwrap(), [(5, 1)]);
    }

    #[test]
    fn hist_counts_and_merges_buckets() {
        let store = Store::in_memory().unwrap();
        store.hist_add("w", "rtt", 1, 5).unwrap();
        store.hist_add("w", "rtt", 1, 5).unwrap();
        store.hist_add("w", "rtt", 2, 5).unwrap();
        store.hist_add("w", "rtt", 2, 3).unwrap();
        assert_eq!(store.hist("w", "rtt", Some(1)).unwrap(), [(5, 2)]);
        assert_eq!(store.hist("w", "rtt", None).unwrap(), [(3, 1), (5, 3)]);
    }

    #[test]
    fn snapshots_keep_only_the_newest() {
        let store = Store::in_memory().unwrap();
        assert!(store.last_known_good("w").unwrap().is_none());
        for ts in 1..=4 {
            store
                .save_snapshot("w", ts, &json!({ "n": ts }), 2)
                .unwrap();
        }
        let (ts, data) = store.last_known_good("w").unwrap().unwrap();
        assert_eq!(ts, 4);
        assert_eq!(data["n"], 4);
        let count: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM snapshots", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn state_round_trips_and_defaults_when_missing() {
        let store = Store::in_memory().unwrap();
        assert_eq!(store.load_state("w").unwrap(), WatchState::default());
        let state = WatchState {
            last_probe: Some(1),
            last_snapshot: Some(2),
            trigger: TriggerState {
                streak: 3,
                since: Some(4),
                last_fired: Some(5),
                active: true,
            },
        };
        store.save_state("w", &state).unwrap();
        assert_eq!(store.load_state("w").unwrap(), state);
    }

    #[test]
    fn reopening_keeps_data() {
        let dir = std::env::temp_dir().join(format!("kuda-store-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("kuda.db");
        Store::open(&path)
            .unwrap()
            .record_run("w", &run(100, true))
            .unwrap();
        assert_eq!(Store::open(&path).unwrap().sample_count("w").unwrap(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
