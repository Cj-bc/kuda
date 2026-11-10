//! SQLite: メトリクス・集計・スナップショット・判定状態。

use crate::probe::{ProbeRun, TargetResult};
use crate::trigger::TriggerState;
use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde_json::Value;
use std::path::Path;
use std::time::Duration;

/// `MIGRATIONS[i]` は版 i の DB を版 i + 1 へ上げる。新規 DB は版 0 から順に適用する。
/// 版を足すときは末尾に追加し、既存の要素は書き換えない
const MIGRATIONS: [&str; 2] = [SCHEMA_V1, HIST_BY_AGGREGATION];

/// 版 1 の分布に付ける `aggregate_by`。記録時の集計方式が分からない
const HIST_V1: &str = "v1";
/// 版 1 の分布のうち、現在の集計方式に合わず引き取れなかったもの。全体の統計にだけ使う
const HIST_UNKNOWN: &str = "unknown";

/// 版 2: bucket の意味は集計方式で変わるので、分布を集計方式ごとに分ける
const HIST_BY_AGGREGATION: &str = "
    CREATE TABLE baseline_hist_v2 (
        watch TEXT NOT NULL,
        aggregate_by TEXT NOT NULL,
        series TEXT NOT NULL,
        bucket INTEGER NOT NULL,
        bin INTEGER NOT NULL,
        count INTEGER NOT NULL,
        PRIMARY KEY (watch, aggregate_by, series, bucket, bin)
    ) WITHOUT ROWID;
    INSERT INTO baseline_hist_v2 (watch, aggregate_by, series, bucket, bin, count)
        SELECT watch, 'v1', series, bucket, bin, count FROM baseline_hist;
    DROP TABLE baseline_hist;
    ALTER TABLE baseline_hist_v2 RENAME TO baseline_hist;
";

const SCHEMA_V1: &str = "
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

/// 版 1 から引き継いだ分布の概要
#[derive(Debug, Clone, PartialEq)]
pub struct V1Hist {
    pub min_bucket: i64,
    pub max_bucket: i64,
    /// 系列ごとのサンプル数の最大値
    pub samples: u64,
}

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

    pub fn hist_add(
        &self,
        watch: &str,
        aggregate_by: &str,
        series: &str,
        bucket: i64,
        bin: i64,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO baseline_hist (watch, aggregate_by, series, bucket, bin, count)
             VALUES (?1, ?2, ?3, ?4, ?5, 1)
             ON CONFLICT (watch, aggregate_by, series, bucket, bin)
             DO UPDATE SET count = count + 1",
            params![watch, aggregate_by, series, bucket, bin],
        )?;
        Ok(())
    }

    /// (bin, 件数) を bin の昇順で返す。`bucket` は (集計方式, 時間帯) で、
    /// None なら集計方式も時間帯も問わず全体を合算する
    pub fn hist(
        &self,
        watch: &str,
        series: &str,
        bucket: Option<(&str, i64)>,
    ) -> Result<Vec<(i64, u64)>> {
        // 時間帯を指定するときは主キーの先頭 4 列で引けるよう、条件を分けた別のクエリにする
        let mut statement;
        let rows = match bucket {
            Some((aggregate_by, bucket)) => {
                statement = self.conn.prepare_cached(
                    "SELECT bin, SUM(count) FROM baseline_hist
                     WHERE watch = ?1 AND aggregate_by = ?2 AND series = ?3 AND bucket = ?4
                     GROUP BY bin ORDER BY bin",
                )?;
                statement.query(params![watch, aggregate_by, series, bucket])?
            }
            None => {
                statement = self.conn.prepare_cached(
                    "SELECT bin, SUM(count) FROM baseline_hist
                     WHERE watch = ?1 AND series = ?2
                     GROUP BY bin ORDER BY bin",
                )?;
                statement.query(params![watch, series])?
            }
        };
        Ok(rows
            .mapped(|row| Ok((row.get(0)?, row.get::<_, i64>(1)? as u64)))
            .collect::<rusqlite::Result<_>>()?)
    }

    /// 版 1 から引き継いだ集計方式不明の分布の概要。引き取り済みなら None
    pub fn v1_hist(&self, watch: &str) -> Result<Option<V1Hist>> {
        let row: (Option<i64>, Option<i64>, Option<i64>) = self.conn.query_row(
            "SELECT MIN(min_bucket), MAX(max_bucket), MAX(samples) FROM (
                 SELECT MIN(bucket) AS min_bucket, MAX(bucket) AS max_bucket,
                        SUM(count) AS samples
                 FROM baseline_hist WHERE watch = ?1 AND aggregate_by = ?2
                 GROUP BY series
             )",
            params![watch, HIST_V1],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        Ok(match row {
            (Some(min_bucket), Some(max_bucket), Some(samples)) => Some(V1Hist {
                min_bucket,
                max_bucket,
                samples: samples as u64,
            }),
            _ => None,
        })
    }

    /// 保持期間内の probe の 1 時間あたりの回数。間に止まっていた時間も含めて均すので、実際の間隔より少なめに出る
    pub fn probes_per_hour(&self, watch: &str) -> Result<f64> {
        let (count, first, last): (i64, Option<i64>, Option<i64>) = self.conn.query_row(
            "SELECT COUNT(DISTINCT ts), MIN(ts), MAX(ts) FROM metrics WHERE watch = ?1",
            params![watch],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        let hours = match (first, last) {
            (Some(first), Some(last)) => ((last - first) as f64 / 3600.0).max(1.0),
            _ => return Ok(0.0),
        };
        Ok(count as f64 / hours)
    }

    /// 版 1 の分布を `adopt_as` の集計方式で記録したものとして引き取る。
    /// None なら記録時の方式が分からないものとして、全体の統計にだけ残す
    pub fn resolve_v1_hist(&self, watch: &str, adopt_as: Option<&str>) -> Result<()> {
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO baseline_hist (watch, aggregate_by, series, bucket, bin, count)
             SELECT watch, ?3, series, bucket, bin, count FROM baseline_hist
             WHERE watch = ?1 AND aggregate_by = ?2
             ON CONFLICT (watch, aggregate_by, series, bucket, bin)
             DO UPDATE SET count = count + excluded.count",
            params![watch, HIST_V1, adopt_as.unwrap_or(HIST_UNKNOWN)],
        )?;
        tx.execute(
            "DELETE FROM baseline_hist WHERE watch = ?1 AND aggregate_by = ?2",
            params![watch, HIST_V1],
        )?;
        tx.commit()?;
        Ok(())
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

    /// last_snapshot だけを更新する。check と snapshot のどちらからも呼ばれるので、
    /// 他の列は読み込んだ時点の値で上書きしない。後から完了した側の収集開始が
    /// 早いこともあるので、時刻は戻さない
    pub fn set_last_snapshot(&self, watch: &str, ts: i64) -> Result<()> {
        self.conn.execute(
            "INSERT INTO watch_state (watch, last_snapshot, streak, active)
             VALUES (?1, ?2, 0, 0)
             ON CONFLICT (watch) DO UPDATE SET last_snapshot =
                 max(coalesce(last_snapshot, excluded.last_snapshot), excluded.last_snapshot)",
            params![watch, ts],
        )?;
        Ok(())
    }

    /// check が所有する probe と trigger の状態を保存する。`state.last_snapshot` は
    /// 書かない（snapshot と並行しても巻き戻さないよう、`set_last_snapshot` で更新する）
    pub fn save_state(&self, watch: &str, state: &WatchState) -> Result<()> {
        self.conn.execute(
            "INSERT INTO watch_state (watch, last_probe, streak, since, last_fired, active)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT (watch) DO UPDATE SET
                 last_probe = excluded.last_probe,
                 streak = excluded.streak,
                 since = excluded.since,
                 last_fired = excluded.last_fired,
                 active = excluded.active",
            params![
                watch,
                state.last_probe,
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
        store.hist_add("w", "hour", "rtt", 1, 5).unwrap();
        store.prune_metrics("w", 150).unwrap();
        assert_eq!(store.sample_count("w").unwrap(), 1);
        assert_eq!(store.hist("w", "rtt", None).unwrap(), [(5, 1)]);
    }

    #[test]
    fn hist_counts_and_merges_buckets() {
        let store = Store::in_memory().unwrap();
        store.hist_add("w", "hour", "rtt", 1, 5).unwrap();
        store.hist_add("w", "hour", "rtt", 1, 5).unwrap();
        store.hist_add("w", "hour", "rtt", 2, 5).unwrap();
        store.hist_add("w", "hour", "rtt", 2, 3).unwrap();
        assert_eq!(store.hist("w", "rtt", Some(("hour", 1))).unwrap(), [(5, 2)]);
        assert_eq!(store.hist("w", "rtt", None).unwrap(), [(3, 1), (5, 3)]);
    }

    #[test]
    fn hist_buckets_are_separated_by_aggregation() {
        let store = Store::in_memory().unwrap();
        store.hist_add("w", "weekday_hour", "rtt", 9, 5).unwrap();
        store.hist_add("w", "hour", "rtt", 9, 3).unwrap();
        assert_eq!(store.hist("w", "rtt", Some(("hour", 9))).unwrap(), [(3, 1)]);
        assert_eq!(
            store.hist("w", "rtt", Some(("weekday_hour", 9))).unwrap(),
            [(5, 1)]
        );
        // 全体の分布は集計方式に依らないので、方式を変える前のサンプルも数える
        assert_eq!(store.hist("w", "rtt", None).unwrap(), [(3, 1), (5, 1)]);
    }

    #[test]
    fn v1_hist_is_kept_without_an_aggregation() {
        let store = Store::in_memory_v1(&[
            ("w", "rtt", 9, 5, 2),
            ("w", "rtt", 30, 3, 1),
            ("w", "loss", 0, 0, 5),
        ])
        .unwrap();
        assert_eq!(Store::version(&store.conn).unwrap(), MIGRATIONS.len());
        // どの集計方式の時間帯としても読まないが、全体の分布には残る
        for aggregate_by in ["weekday_hour", "hour", "none"] {
            assert!(
                store
                    .hist("w", "rtt", Some((aggregate_by, 9)))
                    .unwrap()
                    .is_empty()
            );
        }
        assert_eq!(store.hist("w", "rtt", None).unwrap(), [(3, 1), (5, 2)]);
        assert_eq!(
            store.v1_hist("w").unwrap(),
            Some(V1Hist {
                min_bucket: 0,
                max_bucket: 30,
                samples: 5
            })
        );
        assert_eq!(store.v1_hist("other").unwrap(), None);
    }

    #[test]
    fn v1_hist_is_adopted_once() {
        let store =
            Store::in_memory_v1(&[("w", "rtt", 9, 5, 2), ("other", "rtt", 9, 5, 1)]).unwrap();
        store.hist_add("w", "hour", "rtt", 9, 5).unwrap();
        store.resolve_v1_hist("w", Some("hour")).unwrap();
        assert_eq!(store.hist("w", "rtt", Some(("hour", 9))).unwrap(), [(5, 3)]);
        assert_eq!(store.v1_hist("w").unwrap(), None);
        // 2 回目以降は引き取るものがない
        store.resolve_v1_hist("w", Some("weekday_hour")).unwrap();
        assert!(
            store
                .hist("w", "rtt", Some(("weekday_hour", 9)))
                .unwrap()
                .is_empty()
        );
        // 他の watch の分布はその watch が引き取るまで残る
        assert!(store.v1_hist("other").unwrap().is_some());
    }

    #[test]
    fn unresolved_v1_hist_counts_only_overall() {
        let store = Store::in_memory_v1(&[("w", "rtt", 9, 5, 2)]).unwrap();
        store.resolve_v1_hist("w", None).unwrap();
        assert_eq!(store.v1_hist("w").unwrap(), None);
        for aggregate_by in ["weekday_hour", "hour", "none"] {
            assert!(
                store
                    .hist("w", "rtt", Some((aggregate_by, 9)))
                    .unwrap()
                    .is_empty()
            );
        }
        assert_eq!(store.hist("w", "rtt", None).unwrap(), [(5, 2)]);
    }

    #[test]
    fn probes_per_hour_follows_the_recorded_runs() {
        let mut store = Store::in_memory().unwrap();
        assert_eq!(store.probes_per_hour("w").unwrap(), 0.0);
        // 5 分間隔で 2 時間
        for i in 0..24 {
            store.record_run("w", &run(i * 300, true)).unwrap();
        }
        let rate = store.probes_per_hour("w").unwrap();
        assert!((rate - 12.0).abs() < 0.6, "{rate}");
    }

    #[test]
    fn v1_file_database_is_migrated_on_open() {
        let dir = std::env::temp_dir().join(format!("kuda-store-v1-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("kuda.db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(&format!("{SCHEMA_V1} PRAGMA user_version = 1;"))
                .unwrap();
            conn.execute(
                "INSERT INTO baseline_hist (watch, series, bucket, bin, count)
                 VALUES ('w', 'rtt', 9, 5, 2)",
                [],
            )
            .unwrap();
        }
        let store = Store::open(&path).unwrap();
        assert_eq!(Store::version(&store.conn).unwrap(), MIGRATIONS.len());
        assert_eq!(store.hist("w", "rtt", None).unwrap(), [(5, 2)]);
        drop(store);
        // 開き直しても版は進まず、データも変わらない
        let store = Store::open(&path).unwrap();
        assert_eq!(Store::version(&store.conn).unwrap(), MIGRATIONS.len());
        assert!(store.v1_hist("w").unwrap().is_some());
        drop(store);
        std::fs::remove_dir_all(dir).unwrap();
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
        store.set_last_snapshot("w", 2).unwrap();
        assert_eq!(store.load_state("w").unwrap(), state);
    }

    #[test]
    fn last_snapshot_alone_creates_default_state() {
        let store = Store::in_memory().unwrap();
        store.set_last_snapshot("w", 2).unwrap();
        let expected = WatchState {
            last_snapshot: Some(2),
            ..WatchState::default()
        };
        assert_eq!(store.load_state("w").unwrap(), expected);
    }

    #[test]
    fn last_snapshot_never_moves_backwards() {
        let store = Store::in_memory().unwrap();
        // snapshot が 100 に収集を始め、その間に check が 110 で保存し、最後に snapshot が完了する
        store.set_last_snapshot("w", 110).unwrap();
        store.set_last_snapshot("w", 100).unwrap();
        assert_eq!(store.load_state("w").unwrap().last_snapshot, Some(110));
        store.set_last_snapshot("w", 120).unwrap();
        assert_eq!(store.load_state("w").unwrap().last_snapshot, Some(120));
    }

    /// 別プロセスの代わりに同じファイルを複数の接続で開くための DB。drop で片付ける
    struct TempDb {
        dir: std::path::PathBuf,
    }

    impl TempDb {
        fn new(name: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("kuda-store-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self { dir }
        }

        fn open(&self) -> Store {
            Store::open(&self.dir.join("kuda.db")).unwrap()
        }
    }

    impl Drop for TempDb {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn snapshot_does_not_roll_back_check_state() {
        // 接続より先に宣言し、接続を閉じてから片付ける
        let db = TempDb::new("snapshot-race");
        let snapshot = db.open();
        let check = db.open();

        // snapshot が収集している間に check が状態を進めて保存し、その後 snapshot が
        // 完了する。commands::snapshot は収集前に読んだ状態を書き戻さず、
        // set_last_snapshot だけを呼ぶ
        let mut checked = check.load_state("w").unwrap();
        checked.last_probe = Some(10);
        checked.trigger = TriggerState {
            streak: 3,
            since: Some(4),
            last_fired: Some(5),
            active: true,
        };
        check.save_state("w", &checked).unwrap();
        snapshot.set_last_snapshot("w", 20).unwrap();

        let state = check.load_state("w").unwrap();
        assert_eq!(state.last_probe, Some(10));
        assert_eq!(state.last_snapshot, Some(20));
        assert_eq!(state.trigger, checked.trigger);
    }

    #[test]
    fn check_does_not_roll_back_last_snapshot() {
        let db = TempDb::new("check-race");
        let snapshot = db.open();
        let check = db.open();

        // check が状態を読んだ後に snapshot が完了し、その後で check が保存する
        let mut state = check.load_state("w").unwrap();
        snapshot.set_last_snapshot("w", 20).unwrap();
        state.last_probe = Some(30);
        check.save_state("w", &state).unwrap();

        let state = snapshot.load_state("w").unwrap();
        assert_eq!(state.last_probe, Some(30));
        assert_eq!(state.last_snapshot, Some(20));
    }

    #[test]
    fn new_database_is_at_the_latest_version() {
        let store = Store::in_memory().unwrap();
        assert_eq!(Store::version(&store.conn).unwrap(), MIGRATIONS.len());
    }

    #[test]
    fn rejects_a_database_from_a_newer_kuda() {
        let dir = std::env::temp_dir().join(format!("kuda-store-newer-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("kuda.db");
        Connection::open(&path)
            .unwrap()
            .pragma_update(None, "user_version", MIGRATIONS.len() as i64 + 1)
            .unwrap();
        let error = Store::open(&path).err().unwrap().to_string();
        assert!(error.contains(&path.display().to_string()), "{error}");
        assert!(error.contains("Update kuda"), "{error}");
        // 拒否した DB は書き換えない
        let version = Store::version(&Connection::open(&path).unwrap()).unwrap();
        assert_eq!(version, MIGRATIONS.len() + 1);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn reopening_keeps_data() {
        let db = TempDb::new("reopen");
        db.open().record_run("w", &run(100, true)).unwrap();
        assert_eq!(db.open().sample_count("w").unwrap(), 1);
    }
}
