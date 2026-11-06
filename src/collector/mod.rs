//! スナップショットを構成する、システム状態の収集。

mod adapters;
mod dns_config;
mod routes;
mod traceroute;

use crate::config::CollectorSpec;
use anyhow::Result;
use serde_json::{Map, Value, json};

pub use routes::default_gateway;

fn collect(spec: &CollectorSpec) -> Result<Value> {
    match spec {
        CollectorSpec::Adapters => adapters::collect(),
        CollectorSpec::Routes => routes::collect(),
        CollectorSpec::DnsConfig => dns_config::collect(),
        CollectorSpec::Traceroute(target) => traceroute::collect(target),
    }
}

/// 全 collector を並列に実行する。個別の失敗はスナップショット内に記録して続行する
pub fn take_snapshot(specs: &[CollectorSpec], taken_at: i64) -> Value {
    let results: Vec<(String, Value)> = std::thread::scope(|scope| {
        let handles: Vec<_> = specs
            .iter()
            .map(|spec| scope.spawn(move || (spec.name(), collect(spec))))
            .collect();
        handles
            .into_iter()
            .filter_map(|handle| handle.join().ok())
            .map(|(name, result)| match result {
                Ok(data) => (name, json!({ "ok": true, "data": data })),
                Err(error) => {
                    log::warn!("collector {name} failed: {error:#}");
                    (name, json!({ "ok": false, "error": format!("{error:#}") }))
                }
            })
            .collect()
    });
    let collectors: Map<String, Value> = results.into_iter().collect();
    json!({ "taken_at": taken_at, "collectors": collectors })
}

/// 失敗した collector の名前を返す
pub fn failed_collectors(snapshot: &Value) -> Vec<String> {
    snapshot["collectors"]
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(_, result)| result["ok"] != Value::Bool(true))
        .map(|(name, _)| name.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failing_collector_does_not_lose_the_others() {
        let specs = [
            CollectorSpec::DnsConfig,
            // 不正な宛先でも snapshot 全体は成立する
            CollectorSpec::Traceroute("kuda.invalid".to_string()),
        ];
        let snapshot = take_snapshot(&specs, 42);
        assert_eq!(snapshot["taken_at"], 42);
        assert!(snapshot["collectors"].get("dns_config").is_some());
        assert!(
            snapshot["collectors"]
                .get("traceroute:kuda.invalid")
                .is_some()
        );
    }

    #[test]
    fn reports_failed_collectors() {
        let snapshot = json!({ "collectors": {
            "a": { "ok": true, "data": 1 },
            "b": { "ok": false, "error": "x" },
        }});
        assert_eq!(failed_collectors(&snapshot), ["b"]);
    }
}
