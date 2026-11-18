//! 時間帯別の分布（ヒストグラム）と、版 1 から引き継いだ分布の引き取り。

use super::Store;
use super::schema::{HIST_UNKNOWN, HIST_V1};
use anyhow::Result;
use rusqlite::{Transaction, TransactionBehavior, params};

/// 版 1 から引き継いだ分布の概要
#[derive(Debug, Clone, PartialEq)]
pub struct V1Hist {
    pub min_bucket: i64,
    pub max_bucket: i64,
    /// 系列ごとのサンプル数の最大値
    pub samples: u64,
}

impl Store {
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
}
