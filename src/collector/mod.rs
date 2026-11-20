//! スナップショットを構成する、システム状態の収集。

mod adapters;
mod dns_config;
mod listening_ports;
mod processes;
mod routes;
mod snapshot;
mod traceroute;

use crate::config::CollectorSpec;
use anyhow::Result;
use serde_json::Value;
use std::collections::BTreeMap;

pub use routes::default_gateway;
pub use snapshot::{CollectorResult, KnownGood, KnownGoodEntry, Snapshot};

/// 配列の要素を同定するキー。添字で比べると 1 件の増減で後続がすべて差分になる。
/// 並び順は差分のパスに出る。collector を足したら、その出力の識別キーをここへ連ねる
pub fn identity_keys() -> impl Iterator<Item = &'static str> {
    adapters::IDENTITY_KEYS
        .iter()
        .chain(routes::IDENTITY_KEYS)
        .copied()
}

/// 毎回変わるので差分で比べないキー
pub fn is_volatile_key(key: &str) -> bool {
    traceroute::VOLATILE_KEYS.contains(&key)
}

fn collect(spec: &CollectorSpec) -> Result<Value> {
    match spec {
        CollectorSpec::Adapters => adapters::collect(),
        CollectorSpec::Routes => routes::collect(),
        CollectorSpec::DnsConfig => dns_config::collect(),
        CollectorSpec::Processes => processes::collect(),
        CollectorSpec::ListeningPorts => listening_ports::collect(),
        CollectorSpec::Traceroute(target) => traceroute::collect(target),
    }
}

/// 全 collector を並列に実行する。個別の失敗はスナップショット内に記録して続行する
pub fn take_snapshot(specs: &[CollectorSpec], taken_at: i64) -> Snapshot {
    take_snapshot_with(specs, taken_at, collect)
}

/// `collect` で各 collector を実行する。panic も失敗として記録する。
/// 結果から落とすと、全 collector が成功した取得に見えてしまう
fn take_snapshot_with(
    specs: &[CollectorSpec],
    taken_at: i64,
    collect: fn(&CollectorSpec) -> Result<Value>,
) -> Snapshot {
    let collectors: BTreeMap<String, CollectorResult> = std::thread::scope(|scope| {
        let handles: Vec<_> = specs
            .iter()
            .map(|spec| (spec.name(), scope.spawn(move || collect(spec))))
            .collect();
        handles
            .into_iter()
            .map(|(name, handle)| {
                let result = handle
                    .join()
                    .unwrap_or_else(|_| Err(anyhow::anyhow!("collector panicked")));
                match result {
                    Ok(data) => (name, CollectorResult::Ok(data)),
                    Err(error) => {
                        log::warn!("collector {name} failed: {error:#}");
                        (name, CollectorResult::Failed(format!("{error:#}")))
                    }
                }
            })
            .collect()
    });
    Snapshot {
        taken_at,
        collectors,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_failing_collector_does_not_lose_the_others() {
        let specs = [
            CollectorSpec::DnsConfig,
            // 不正な宛先でも snapshot 全体は成立する
            CollectorSpec::Traceroute("kuda.invalid".to_string()),
        ];
        let snapshot = take_snapshot(&specs, 42);
        assert_eq!(snapshot.taken_at, 42);
        assert!(snapshot.collectors.contains_key("dns_config"));
        assert!(snapshot.collectors.contains_key("traceroute:kuda.invalid"));
    }

    #[test]
    fn a_panicking_collector_is_recorded_as_failed() {
        fn collect(spec: &CollectorSpec) -> Result<Value> {
            match spec {
                CollectorSpec::Routes => panic!("boom"),
                _ => Ok(json!([])),
            }
        }
        let specs = [CollectorSpec::Routes, CollectorSpec::DnsConfig];
        let snapshot = take_snapshot_with(&specs, 42, collect);
        assert_eq!(
            snapshot.collectors["routes"],
            CollectorResult::Failed("collector panicked".to_string())
        );
        assert!(snapshot.collectors["dns_config"].is_ok());
        assert_eq!(snapshot.failed(), ["routes"]);
    }

    #[test]
    fn keys_are_taken_from_the_collectors() {
        assert_eq!(
            identity_keys().collect::<Vec<_>>(),
            ["name", "adapter", "destination", "next_hop", "interface"]
        );
        assert!(is_volatile_key("raw"));
        assert!(!is_volatile_key("hops"));
    }
}
