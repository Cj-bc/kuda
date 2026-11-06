//! watch の疎通確認。1 回の実行で各ターゲットを 1 度ずつ試す。

mod dns;
mod http;
mod tcp;

use crate::collector;
use crate::config::{Probe, ProbeKind};
use crate::trigger::Variables;
use serde::Serialize;
use std::net::IpAddr;

/// ターゲット 1 件の成功時の測定値
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Sample {
    pub rtt_ms: Option<f64>,
    /// kind = "command" が標準出力に出した数値
    pub value: Option<f64>,
}

impl Sample {
    fn rtt(rtt_ms: f64) -> Self {
        Self {
            rtt_ms: Some(rtt_ms),
            value: None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetResult {
    pub target: String,
    pub ok: bool,
    pub rtt_ms: Option<f64>,
    pub value: Option<f64>,
    pub error: Option<String>,
}

impl TargetResult {
    fn new(target: &str, result: Result<Sample, String>) -> Self {
        let (sample, error) = match result {
            Ok(sample) => (Some(sample), None),
            Err(error) => (None, Some(error)),
        };
        Self {
            target: target.to_string(),
            ok: error.is_none(),
            rtt_ms: sample.as_ref().and_then(|s| s.rtt_ms),
            value: sample.as_ref().and_then(|s| s.value),
            error,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProbeRun {
    pub ts: i64,
    pub results: Vec<TargetResult>,
}

impl ProbeRun {
    /// 条件式の変数になる集計値。値の無い指標はキーごと省く
    pub fn metrics(&self) -> Variables {
        let mut metrics = Variables::new();
        let failed = self.results.iter().filter(|r| !r.ok).count();
        metrics.insert(
            "loss".to_string(),
            failed as f64 / self.results.len().max(1) as f64,
        );

        let mut rtts: Vec<f64> = self.results.iter().filter_map(|r| r.rtt_ms).collect();
        rtts.sort_by(f64::total_cmp);
        if let Some(max) = rtts.last() {
            metrics.insert("rtt_max".to_string(), *max);
            metrics.insert("rtt_p50".to_string(), percentile(&rtts, 0.50));
            metrics.insert("rtt_p95".to_string(), percentile(&rtts, 0.95));
        }
        if let Some(value) = self.results.iter().find_map(|r| r.value) {
            metrics.insert("value".to_string(), value);
        }
        metrics
    }
}

/// ソート済みの値から nearest-rank 法で百分位数を取る
fn percentile(sorted: &[f64], fraction: f64) -> f64 {
    let rank = (sorted.len() as f64 * fraction).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

fn run_target(probe: &Probe, target: &str, gateway: Option<IpAddr>) -> Result<Sample, String> {
    match probe.kind {
        ProbeKind::Tcp => tcp::check(target, gateway, probe.timeout),
        ProbeKind::Dns => dns::check(target, probe.server.as_deref(), probe.timeout),
        ProbeKind::Http => http::check(target, probe.expect_status, probe.timeout),
        ProbeKind::Icmp | ProbeKind::Command => {
            Err("probe kind is not supported yet".to_string())
        }
    }
}

fn expand_gateway(target: &str, gateway: Option<IpAddr>) -> Result<String, String> {
    if target != "gateway" {
        return Ok(target.to_string());
    }
    gateway
        .map(|ip| ip.to_string())
        .ok_or_else(|| "no default gateway".to_string())
}

/// 全ターゲットを並列に試す。所要時間は最も遅いターゲットで決まる
pub fn run(probe: &Probe, ts: i64) -> ProbeRun {
    let gateway = collector::default_gateway();
    let targets = match probe.kind {
        ProbeKind::Command => probe.command[..1].to_vec(),
        _ => probe.targets.clone(),
    };
    let results = std::thread::scope(|scope| {
        let handles: Vec<_> = targets
            .iter()
            .map(|target| {
                scope.spawn(move || TargetResult::new(target, run_target(probe, target, gateway)))
            })
            .collect();
        handles
            .into_iter()
            .zip(&targets)
            .map(|(handle, target)| {
                handle.join().unwrap_or_else(|_| {
                    TargetResult::new(target, Err("probe thread panicked".to_string()))
                })
            })
            .collect()
    });
    ProbeRun { ts, results }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(ok: bool, rtt_ms: Option<f64>) -> TargetResult {
        TargetResult {
            target: "t".to_string(),
            ok,
            rtt_ms,
            value: None,
            error: None,
        }
    }

    #[test]
    fn metrics_aggregate_across_targets() {
        let run = ProbeRun {
            ts: 0,
            results: vec![
                result(true, Some(30.0)),
                result(true, Some(10.0)),
                result(true, Some(20.0)),
                result(false, None),
            ],
        };
        let metrics = run.metrics();
        assert_eq!(metrics["loss"], 0.25);
        assert_eq!(metrics["rtt_p50"], 20.0);
        assert_eq!(metrics["rtt_p95"], 30.0);
        assert_eq!(metrics["rtt_max"], 30.0);
    }

    #[test]
    fn total_loss_has_no_rtt_metrics() {
        let run = ProbeRun {
            ts: 0,
            results: vec![result(false, None), result(false, None)],
        };
        let metrics = run.metrics();
        assert_eq!(metrics["loss"], 1.0);
        assert!(!metrics.contains_key("rtt_p50"));
    }

    #[test]
    fn percentile_uses_nearest_rank() {
        assert_eq!(percentile(&[1.0], 0.5), 1.0);
        assert_eq!(percentile(&[1.0, 2.0], 0.5), 1.0);
        assert_eq!(percentile(&[1.0, 2.0, 3.0, 4.0], 0.95), 4.0);
    }

    #[test]
    fn gateway_target_without_a_route_is_a_failure() {
        assert_eq!(
            expand_gateway("gateway", None),
            Err("no default gateway".to_string())
        );
        assert_eq!(expand_gateway("host", None), Ok("host".to_string()));
    }
}
