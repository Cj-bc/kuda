//! 時間帯別 p50/p95 の統計ベースライン。
//!
//! weekday_hour の 1 区画は 5 分間隔でも週に 12 サンプルしか増えないので、
//! metrics_retention（既定 7 日）の生データからは min_samples に届かない。
//! そのため対数ビンのヒストグラムとして、保持期間と無関係に蓄積する。
//! 百分位数の誤差はビン幅の半分（約 ±2.5%）に収まる。

use crate::config::{AggregateBy, Baseline};
use crate::store::Store;
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
    config: &Baseline,
    metrics: &Variables,
    ts: i64,
) -> Result<()> {
    let bucket = bucket(config.aggregate_by, local_time(ts));
    for (series, metric) in SERIES {
        // 対数ビンで表せない負の値（command の value）は統計に入れない
        if let Some(value) = metrics.get(metric).filter(|value| **value >= 0.0) {
            store.hist_add(watch, series, bucket, bin_of(*value))?;
        }
    }
    Ok(())
}

/// `ts` の時間帯の統計を返す。全体でも min_samples に届かない系列は含まない
pub fn stats(store: &Store, watch: &str, config: &Baseline, ts: i64) -> Result<Vec<SeriesStats>> {
    let bucket = bucket(config.aggregate_by, local_time(ts));
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

    fn config(min_samples: u64, aggregate_by: AggregateBy) -> Baseline {
        Baseline {
            min_samples,
            aggregate_by,
            ..Baseline::default()
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
            assert!(crate::trigger::VARIABLES.contains(&name.as_str()), "{name}");
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
