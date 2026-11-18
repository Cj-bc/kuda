//! 時間帯別 p50/p95 の統計ベースライン。
//!
//! weekday_hour の 1 区画は 5 分間隔でも週に 12 サンプルしか増えないので、
//! metrics_retention（既定 7 日）の生データからは min_samples に届かない。
//! そのため対数ビンのヒストグラムとして、保持期間と無関係に蓄積する。
//! 百分位数の誤差はビン幅の半分（約 ±2.5%）に収まる。

use crate::config::{AggregateBy, StatsConfig};
use crate::store::{Store, V1Hist};
use crate::trigger::Variables;
use anyhow::Result;
use chrono::{DateTime, Datelike, Local, TimeZone, Timelike};

/// (ヒストグラムの系列名, 元になる指標)。
/// 系列 rtt は probe ごとの中央値の分布で、`baseline.rtt_p95` はその 95 パーセンタイル
const SERIES: [(&str, &str); 3] = [("rtt", "rtt_p50"), ("loss", "loss"), ("value", "value")];

/// 隣り合うビンの比
const BIN_RATIO: f64 = 1.05;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Source {
    /// 同じ時間帯の統計
    Bucket,
    /// 時間帯のサンプルが足りず、全体の統計で代用した
    Overall,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SeriesStats {
    pub series: &'static str,
    pub source: Source,
    pub samples: u64,
    pub p50: f64,
    pub p95: f64,
}

/// 永続化する集計方式の名前。bucket の値は同じ方式の中でしか比べられない
fn aggregation_key(aggregate_by: AggregateBy) -> &'static str {
    match aggregate_by {
        AggregateBy::WeekdayHour => "weekday_hour",
        AggregateBy::Hour => "hour",
        AggregateBy::None => "none",
    }
}

/// 集計方式がとりうる bucket の最大値
fn max_bucket(aggregate_by: AggregateBy) -> i64 {
    match aggregate_by {
        AggregateBy::WeekdayHour => 7 * 24 - 1,
        AggregateBy::Hour => 23,
        AggregateBy::None => 0,
    }
}

/// 集計方式を記録していなかった版の分布を、移行後に初めて使う時点の方式で記録したものとして引き取る。
/// その方式で記録したとすると矛盾する分布は、時間帯別には使わず全体の統計にだけ残す
fn adopt_v1(store: &Store, watch: &str, aggregate_by: AggregateBy) -> Result<()> {
    let Some(v1) = store.v1_hist(watch)? else {
        return Ok(());
    };
    let plausible = v1_recorded_by(aggregate_by, &v1, store.probes_per_hour(watch)?);
    store.resolve_v1_hist(watch, plausible.then(|| aggregation_key(aggregate_by)))
}

/// 版 1 の分布が `aggregate_by` で記録されたとみて矛盾しないか。
/// `probes_per_hour` は保持期間内の probe の頻度で、止まっていた時間も均すので実際より少なめに出る
fn v1_recorded_by(aggregate_by: AggregateBy, v1: &V1Hist, probes_per_hour: f64) -> bool {
    if v1.min_bucket < 0 || v1.max_bucket > max_bucket(aggregate_by) {
        return false;
    }
    // bucket が範囲内でも、より粗い方式でも出る値（hour の 0..=23 や none の 0）しか無いと、
    // 範囲からは方式を区別できない。本当に `aggregate_by` で記録したなら、その bucket に当たる
    // 時刻にしか記録できていない（weekday_hour で 0..=23 だけなら月曜の 1 日、bucket 0 だけなら
    // 0 時台の 1 時間）。その 2 倍を超えるサンプルがあれば、粗い方式で何日分も記録したとみなす。
    // 頻度は少なめに出るので、迷う分布は引き取らない側に倒れる
    let hours = match aggregate_by {
        AggregateBy::WeekdayHour | AggregateBy::Hour if v1.max_bucket == 0 => 1.0,
        AggregateBy::WeekdayHour if v1.max_bucket <= 23 => 24.0,
        _ => return true,
    };
    v1.samples as f64 <= 2.0 * hours * probes_per_hour
}

fn bucket(aggregate_by: AggregateBy, time: DateTime<Local>) -> i64 {
    match aggregate_by {
        AggregateBy::WeekdayHour => {
            i64::from(time.weekday().num_days_from_monday()) * 24 + i64::from(time.hour())
        }
        AggregateBy::Hour => i64::from(time.hour()),
        AggregateBy::None => 0,
    }
}

fn local_time(ts: i64) -> DateTime<Local> {
    Local
        .timestamp_opt(ts, 0)
        .single()
        .unwrap_or_else(Local::now)
}

fn bin_of(value: f64) -> i64 {
    ((1.0 + value).ln() / BIN_RATIO.ln()).floor() as i64
}

/// ビンの中央値。ビン 0 はほぼ 0 の値（loss = 0 など）なので 0 に丸める
fn bin_value(bin: i64) -> f64 {
    if bin == 0 {
        return 0.0;
    }
    let lower = BIN_RATIO.powi(bin as i32);
    (lower + lower * BIN_RATIO) / 2.0 - 1.0
}

fn hist_percentile(hist: &[(i64, u64)], total: u64, fraction: f64) -> f64 {
    let rank = ((total as f64 * fraction).ceil() as u64).max(1);
    let mut seen = 0;
    for (bin, count) in hist {
        seen += count;
        if seen >= rank {
            return bin_value(*bin);
        }
    }
    hist.last().map_or(0.0, |(bin, _)| bin_value(*bin))
}

/// 正常時の 1 回分の指標を分布へ足す
pub fn update(
    store: &Store,
    watch: &str,
    config: &StatsConfig,
    metrics: &Variables,
    ts: i64,
) -> Result<()> {
    adopt_v1(store, watch, config.aggregate_by)?;
    let aggregate_by = aggregation_key(config.aggregate_by);
    let bucket = bucket(config.aggregate_by, local_time(ts));
    for (series, metric) in SERIES {
        // 対数ビンで表せない負の値（command の value）は統計に入れない
        if let Some(value) = metrics.get(metric).filter(|value| **value >= 0.0) {
            store.hist_add(watch, aggregate_by, series, bucket, bin_of(*value))?;
        }
    }
    Ok(())
}

/// `ts` の時間帯の統計を返す。全体でも min_samples に届かない系列は含まない。
/// 時間帯別には現在の aggregate_by で記録した分布だけを使い、
/// 全体の統計には方式を変える前の分布も含める（時間帯を問わないので意味が変わらない）
pub fn stats(
    store: &Store,
    watch: &str,
    config: &StatsConfig,
    ts: i64,
) -> Result<Vec<SeriesStats>> {
    adopt_v1(store, watch, config.aggregate_by)?;
    let bucket = (
        aggregation_key(config.aggregate_by),
        bucket(config.aggregate_by, local_time(ts)),
    );
    let mut result = Vec::new();
    for (series, _) in SERIES {
        let candidates = [(Source::Bucket, Some(bucket)), (Source::Overall, None)];
        for (source, bucket) in candidates {
            let hist = store.hist(watch, series, bucket)?;
            let samples: u64 = hist.iter().map(|(_, count)| count).sum();
            if samples > 0 && samples >= config.min_samples {
                result.push(SeriesStats {
                    series,
                    source,
                    samples,
                    p50: hist_percentile(&hist, samples, 0.50),
                    p95: hist_percentile(&hist, samples, 0.95),
                });
                break;
            }
        }
    }
    Ok(result)
}

/// 条件式の `baseline.*` 変数へ展開する
pub fn variables(stats: &[SeriesStats]) -> Variables {
    let mut variables = Variables::new();
    for stat in stats {
        variables.insert(format!("baseline.{}_p50", stat.series), stat.p50);
        variables.insert(format!("baseline.{}_p95", stat.series), stat.p95);
    }
    variables
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(min_samples: u64, aggregate_by: AggregateBy) -> StatsConfig {
        StatsConfig {
            min_samples,
            aggregate_by,
            ..StatsConfig::default()
        }
    }

    fn metrics(rtt: f64) -> Variables {
        [("rtt_p50".to_string(), rtt), ("loss".to_string(), 0.0)]
            .into_iter()
            .collect()
    }

    fn at(y: i32, mo: u32, d: u32, h: u32) -> i64 {
        Local
            .with_ymd_and_hms(y, mo, d, h, 30, 0)
            .single()
            .unwrap()
            .timestamp()
    }

    #[test]
    fn buckets_by_weekday_and_hour() {
        // 2026-11-02 は月曜、2026-11-03 は火曜
        let monday = local_time(at(2026, 11, 2, 9));
        let tuesday = local_time(at(2026, 11, 3, 9));
        assert_eq!(bucket(AggregateBy::WeekdayHour, monday), 9);
        assert_eq!(bucket(AggregateBy::WeekdayHour, tuesday), 33);
        assert_eq!(bucket(AggregateBy::Hour, tuesday), 9);
        assert_eq!(bucket(AggregateBy::None, tuesday), 0);
        // 2026-11-08 は日曜
        let sunday = local_time(at(2026, 11, 8, 23));
        for aggregate_by in [
            AggregateBy::WeekdayHour,
            AggregateBy::Hour,
            AggregateBy::None,
        ] {
            assert_eq!(bucket(aggregate_by, sunday), max_bucket(aggregate_by));
        }
    }

    #[test]
    fn changing_aggregate_by_does_not_reuse_old_buckets() {
        let weekday_hour = config(30, AggregateBy::WeekdayHour);
        let hour = config(30, AggregateBy::Hour);
        // weekday_hour の bucket 9 は月曜 9 時、hour の bucket 9 は毎日 9 時
        let (monday, tuesday) = (at(2026, 11, 2, 9), at(2026, 11, 3, 9));
        for (before, after, recorded, queried) in [
            (&weekday_hour, &hour, monday, tuesday),
            (&hour, &weekday_hour, tuesday, monday),
        ] {
            let store = Store::in_memory().unwrap();
            for _ in 0..30 {
                update(&store, "w", before, &metrics(100.0), recorded).unwrap();
            }
            let stats = stats(&store, "w", after, queried).unwrap();
            let rtt = stats.iter().find(|s| s.series == "rtt").unwrap();
            // 時間帯としては使わず、全体の統計としてだけ使う
            assert_eq!(rtt.source, Source::Overall);
            assert_eq!(rtt.samples, 30);
        }
    }

    const AGGREGATIONS: [AggregateBy; 3] = [
        AggregateBy::WeekdayHour,
        AggregateBy::Hour,
        AggregateBy::None,
    ];

    /// 版 1 の kuda が `aggregate_by` で `start` から `hours` 時間、5 分おきに記録した DB
    fn v1_store(aggregate_by: AggregateBy, start: i64, hours: i64) -> Store {
        let times: Vec<i64> = (0..hours * 12).map(|i| start + i * 300).collect();
        let mut counts = std::collections::BTreeMap::new();
        for ts in &times {
            *counts
                .entry(bucket(aggregate_by, local_time(*ts)))
                .or_insert(0) += 1;
        }
        let bin = bin_of(10.0);
        let hist: Vec<_> = counts
            .into_iter()
            .map(|(bucket, count)| ("w", "rtt", bucket, bin, count))
            .collect();
        let mut store = Store::in_memory_v1(&hist).unwrap();
        for ts in times {
            let run = crate::probe::ProbeRun {
                processes: None,
                ts,
                results: vec![crate::probe::TargetResult {
                    target: "t".to_string(),
                    ok: true,
                    rtt_ms: Some(10.0),
                    value: None,
                    error: None,
                }],
            };
            store.record_run("w", &run).unwrap();
        }
        store
    }

    #[test]
    fn v1_buckets_are_adopted_only_by_the_aggregation_that_recorded_them() {
        // 月曜 0 時から 3 日分。月曜 0 時台はどの方式でも bucket 0 なので、
        // 別の方式で記録した分布を引き取ると時間帯別の統計として使われてしまう
        let start = at(2026, 11, 2, 0) - 30 * 60;
        for recorded in AGGREGATIONS {
            for current in AGGREGATIONS {
                let store = v1_store(recorded, start, 72);
                let stats = stats(&store, "w", &config(1, current), start).unwrap();
                let rtt = stats.iter().find(|s| s.series == "rtt").unwrap();
                let expected = if recorded == current {
                    Source::Bucket
                } else {
                    Source::Overall
                };
                assert_eq!(rtt.source, expected, "{recorded:?} -> {current:?}");
                if recorded != current {
                    assert_eq!(rtt.samples, 3 * 24 * 12);
                }
            }
        }
    }

    #[test]
    fn short_v1_history_is_adopted_by_weekday_hour() {
        // 月曜の 1 日分だけなら bucket は 0..=23 に収まるが、weekday_hour の記録として矛盾しない
        let monday = at(2026, 11, 2, 0) - 30 * 60;
        let store = v1_store(AggregateBy::WeekdayHour, monday, 24);
        let config = config(1, AggregateBy::WeekdayHour);
        let stats = stats(&store, "w", &config, at(2026, 11, 2, 9)).unwrap();
        let rtt = stats.iter().find(|s| s.series == "rtt").unwrap();
        assert_eq!(rtt.source, Source::Bucket);
        assert_eq!(rtt.samples, 12);
    }

    #[test]
    fn v1_check_needs_a_known_probe_rate() {
        // 頻度が分からなければ、範囲から区別できない分布は引き取らない
        let v1 = V1Hist {
            min_bucket: 0,
            max_bucket: 23,
            samples: 1,
        };
        assert!(!v1_recorded_by(AggregateBy::WeekdayHour, &v1, 0.0));
        assert!(v1_recorded_by(AggregateBy::Hour, &v1, 0.0));
    }

    #[test]
    fn buckets_accumulate_again_after_changing_aggregate_by() {
        let store = Store::in_memory().unwrap();
        let ts = at(2026, 11, 3, 9);
        for _ in 0..30 {
            update(
                &store,
                "w",
                &config(1, AggregateBy::WeekdayHour),
                &metrics(10.0),
                ts,
            )
            .unwrap();
        }
        let hour = config(1, AggregateBy::Hour);
        update(&store, "w", &hour, &metrics(100.0), ts).unwrap();
        let stats = stats(&store, "w", &hour, ts).unwrap();
        let rtt = stats.iter().find(|s| s.series == "rtt").unwrap();
        assert_eq!(rtt.source, Source::Bucket);
        assert_eq!(rtt.samples, 1);
        assert!((rtt.p50 - 100.0).abs() < 5.0, "{}", rtt.p50);
    }

    #[test]
    fn bins_round_trip_within_tolerance() {
        for value in [0.5, 1.0, 3.3, 20.0, 150.0, 2500.0] {
            let approx = bin_value(bin_of(value));
            assert!(
                (approx - value).abs() / value < 0.06 || (approx - value).abs() < 0.05,
                "{value} -> {approx}"
            );
        }
        assert_eq!(bin_value(bin_of(0.0)), 0.0);
    }

    #[test]
    fn insufficient_samples_yield_no_baseline() {
        let store = Store::in_memory().unwrap();
        let config = config(30, AggregateBy::WeekdayHour);
        let ts = at(2026, 11, 2, 9);
        for _ in 0..29 {
            update(&store, "w", &config, &metrics(10.0), ts).unwrap();
        }
        let stats = stats(&store, "w", &config, ts).unwrap();
        assert!(stats.is_empty());
        assert!(variables(&stats).is_empty());
    }

    #[test]
    fn bucket_stats_are_used_when_available() {
        let store = Store::in_memory().unwrap();
        let config = config(30, AggregateBy::WeekdayHour);
        let (busy, quiet) = (at(2026, 11, 2, 9), at(2026, 11, 2, 3));
        for _ in 0..30 {
            update(&store, "w", &config, &metrics(100.0), busy).unwrap();
            update(&store, "w", &config, &metrics(10.0), quiet).unwrap();
        }
        let stats = stats(&store, "w", &config, busy).unwrap();
        let rtt = stats.iter().find(|s| s.series == "rtt").unwrap();
        assert_eq!(rtt.source, Source::Bucket);
        assert_eq!(rtt.samples, 30);
        assert!((rtt.p50 - 100.0).abs() < 5.0, "{}", rtt.p50);
    }

    #[test]
    fn falls_back_to_overall_for_thin_buckets() {
        let store = Store::in_memory().unwrap();
        let config = config(30, AggregateBy::WeekdayHour);
        for _ in 0..30 {
            update(&store, "w", &config, &metrics(10.0), at(2026, 11, 2, 3)).unwrap();
        }
        let stats = stats(&store, "w", &config, at(2026, 11, 2, 9)).unwrap();
        let rtt = stats.iter().find(|s| s.series == "rtt").unwrap();
        assert_eq!(rtt.source, Source::Overall);
    }

    #[test]
    fn percentiles_reflect_the_distribution() {
        let store = Store::in_memory().unwrap();
        let config = config(1, AggregateBy::None);
        let ts = at(2026, 11, 2, 9);
        for i in 1..=100 {
            update(&store, "w", &config, &metrics(f64::from(i)), ts).unwrap();
        }
        let stats = stats(&store, "w", &config, ts).unwrap();
        let rtt = stats.iter().find(|s| s.series == "rtt").unwrap();
        assert!((rtt.p50 - 50.0).abs() < 3.0, "{}", rtt.p50);
        assert!((rtt.p95 - 95.0).abs() < 5.0, "{}", rtt.p95);
    }

    #[test]
    fn exposes_condition_variables() {
        let store = Store::in_memory().unwrap();
        let config = config(1, AggregateBy::None);
        let ts = at(2026, 11, 2, 9);
        update(&store, "w", &config, &metrics(10.0), ts).unwrap();
        let variables = variables(&stats(&store, "w", &config, ts).unwrap());
        for name in variables.keys() {
            let available = crate::trigger::variables_for(crate::config::ProbeKind::Tcp);
            assert!(available.contains(&name.as_str()), "{name}");
        }
        assert!(variables.contains_key("baseline.rtt_p95"));
        assert_eq!(variables["baseline.loss_p95"], 0.0);
    }

    #[test]
    fn negative_values_are_not_counted() {
        let store = Store::in_memory().unwrap();
        let config = config(1, AggregateBy::None);
        let values: Variables = [("value".to_string(), -1.0)].into_iter().collect();
        update(&store, "w", &config, &values, 0).unwrap();
        assert!(store.hist("w", "value", None).unwrap().is_empty());
    }
}
