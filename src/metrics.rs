//! 指標と条件式の変数の名前。
//!
//! 名前は probe の集計、分類、ベースライン、条件式の許可リスト、事件の表で
//! 同じ文字列を指す。文字列のまま散らすと、どれかを変えたときに照合が黙って外れるので、
//! ここに集める。

use crate::config::ProbeKind;
use std::collections::BTreeMap;

/// 条件式の変数名から値への対応
pub type Variables = BTreeMap<String, f64>;

pub const LOSS: &str = "loss";
pub const RTT_P50: &str = "rtt_p50";
pub const RTT_P95: &str = "rtt_p95";
pub const RTT_MAX: &str = "rtt_max";
/// kind = "command" が標準出力に出した数値
pub const VALUE: &str = "value";

pub const UNKNOWN: &str = "unknown";
pub const UNKNOWN_USER_WRITABLE: &str = "unknown_user_writable";
pub const MASQUERADE: &str = "masquerade";
pub const MISSING: &str = "missing";
pub const PROCESS_COUNT: &str = "process_count";

/// ベースラインの変数名の接頭辞。`baseline.rtt_p95` のように系列名と百分位が続く
pub const BASELINE_PREFIX: &str = "baseline.";

/// ベースラインの系列名
pub const SERIES_RTT: &str = "rtt";
pub const SERIES_LOSS: &str = "loss";
pub const SERIES_VALUE: &str = "value";

/// (ヒストグラムの系列名, 元になる指標)。
/// 系列 rtt は probe ごとの中央値の分布で、`baseline.rtt_p95` はその 95 パーセンタイル
pub const SERIES: [(&str, &str); 3] = [
    (SERIES_RTT, RTT_P50),
    (SERIES_LOSS, LOSS),
    (SERIES_VALUE, VALUE),
];

/// 系列の元になる指標から、系列名を引く。系列の無い指標は同じ名前を返す
pub fn series_of(metric: &str) -> &str {
    SERIES
        .iter()
        .find(|(_, source)| *source == metric)
        .map_or(metric, |(series, _)| series)
}

/// probe の種類ごとに、条件式で使える変数。
///
/// 式のパースでは検査しない。変数は probe の種類で決まり、パースの時点では
/// どの probe の式か分からないので、`RawWatch::into_watch`（config.rs）が照合する。
/// 網羅的に match しているのは、probe の種類を足したときに許可リストの決め忘れを防ぐため。
/// `baseline.*` は `&'static` で返すためにここだけ文字列で書く。SERIES との食い違いは
/// テストで検出する
pub fn variables_for(kind: ProbeKind) -> &'static [&'static str] {
    match kind {
        ProbeKind::Tcp
        | ProbeKind::Icmp
        | ProbeKind::Dns
        | ProbeKind::Http
        | ProbeKind::Command => &[
            LOSS,
            RTT_P50,
            RTT_P95,
            RTT_MAX,
            VALUE,
            "baseline.rtt_p50",
            "baseline.rtt_p95",
            "baseline.loss_p50",
            "baseline.loss_p95",
            "baseline.value_p50",
            "baseline.value_p95",
        ],
        // baseline.* は無い。時間帯の統計ではなく、既知の集合と比べる
        ProbeKind::Process => &[
            LOSS,
            UNKNOWN,
            UNKNOWN_USER_WRITABLE,
            MASQUERADE,
            MISSING,
            PROCESS_COUNT,
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::{ProbeRun, TargetResult};

    #[test]
    fn series_table_matches_the_baseline_variables() {
        let available = variables_for(ProbeKind::Tcp);
        for (series, metric) in SERIES {
            assert!(available.contains(&metric), "{metric}");
            for percentile in ["p50", "p95"] {
                let name = format!("{BASELINE_PREFIX}{series}_{percentile}");
                assert!(available.contains(&name.as_str()), "{name}");
            }
        }
        // 系列の無い指標は、そのままの名前で引く
        assert_eq!(series_of(RTT_P50), SERIES_RTT);
        assert_eq!(series_of(LOSS), SERIES_LOSS);
        assert_eq!(series_of(RTT_MAX), RTT_MAX);
    }

    /// すべての指標が出る probe の結果。出し得る名前が許可リストに載っていることを確かめる
    #[test]
    fn probe_metrics_are_listed_for_every_kind_that_emits_them() {
        let run = ProbeRun {
            ts: 0,
            processes: None,
            results: vec![TargetResult {
                target: "t".to_string(),
                ok: true,
                rtt_ms: Some(1.0),
                value: Some(2.0),
                error: None,
            }],
        };
        let metrics = run.metrics();
        assert_eq!(metrics.len(), 5, "{metrics:?}");
        for kind in [
            ProbeKind::Tcp,
            ProbeKind::Icmp,
            ProbeKind::Dns,
            ProbeKind::Http,
            ProbeKind::Command,
        ] {
            for name in metrics.keys() {
                assert!(variables_for(kind).contains(&name.as_str()), "{name}");
            }
        }
        // process でも loss だけは probe の集計から出る
        assert!(variables_for(ProbeKind::Process).contains(&LOSS));
    }
}
