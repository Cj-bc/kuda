//! スナップショットの比較。collector ごとの JSON を平坦化して、変更・追加・削除を並べる。

use crate::time::format_time;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt::Write as _;

/// 配列の要素を同定するキー。添字で比べると 1 件の増減で後続がすべて差分になる
const IDENTITY_KEYS: [&str; 5] = ["name", "adapter", "destination", "next_hop", "interface"];

/// 毎回変わるので比較しないキー
const VOLATILE_KEYS: [&str; 2] = ["raw", "truncated"];

/// 比較基準の取得時刻。collector ごとに異なりうるので、異なれば範囲で示す
fn baseline_time(last_good: &Value) -> String {
    let times: Vec<i64> = last_good["collectors"]
        .as_object()
        .into_iter()
        .flatten()
        .filter_map(|(_, entry)| entry["taken_at"].as_i64())
        .collect();
    match (times.iter().min(), times.iter().max()) {
        (Some(first), Some(last)) if first == last => format_time(*first),
        (Some(first), Some(last)) => format!(
            "{} 〜 {}（collector ごとに最後に成功した時点）",
            format_time(*first),
            format_time(*last)
        ),
        _ => "?".to_string(),
    }
}

fn scalar(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => "*".to_string(),
        other => other.to_string(),
    }
}

fn identity(item: &Value) -> Option<String> {
    let parts: Vec<String> = IDENTITY_KEYS
        .iter()
        .filter_map(|key| item.get(key).filter(|v| !v.is_null()).map(scalar))
        .collect();
    (!parts.is_empty()).then(|| parts.join(" "))
}

/// JSON をパスと値の組へ平坦化する
fn flatten(path: &str, value: &Value, out: &mut BTreeMap<String, String>) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                if !VOLATILE_KEYS.contains(&key.as_str()) {
                    flatten(&format!("{path}.{key}"), value, out);
                }
            }
        }
        Value::Array(items) if items.iter().all(Value::is_object) && !items.is_empty() => {
            for (index, item) in items.iter().enumerate() {
                let id = identity(item).unwrap_or_else(|| index.to_string());
                flatten(&format!("{path}[{id}]"), item, out);
            }
        }
        // アドレス一覧や traceroute のホップは 1 つの値として並びごと比べる
        Value::Array(items) => {
            let joined: Vec<String> = items.iter().map(scalar).collect();
            out.insert(path.to_string(), joined.join(" → "));
        }
        other => {
            out.insert(path.to_string(), scalar(other));
        }
    }
}

fn collector_data(snapshot: &Value, name: &str) -> Option<BTreeMap<String, String>> {
    let entry = snapshot["collectors"].get(name)?;
    if entry["ok"] != Value::Bool(true) {
        return None;
    }
    let mut flat = BTreeMap::new();
    flatten(name, &entry["data"], &mut flat);
    Some(flat)
}

pub(super) fn collector_names(snapshot: &Value) -> Vec<String> {
    snapshot["collectors"]
        .as_object()
        .map(|map| map.keys().cloned().collect())
        .unwrap_or_default()
}

pub(super) fn render_diff(last_good: Option<&Value>, current: &Value) -> String {
    let mut text = "# 正常時との差分\n\n".to_string();
    let Some(last_good) = last_good else {
        text.push_str("比較できる正常時のスナップショットがありません。\n");
        return text;
    };
    let _ = writeln!(
        text,
        "基準: {} / 現在: {}\n",
        baseline_time(last_good),
        current["taken_at"]
            .as_i64()
            .map_or_else(|| "?".to_string(), format_time),
    );

    let mut names = collector_names(last_good);
    names.extend(collector_names(current));
    names.sort();
    names.dedup();

    let (mut changed, mut added, mut removed, mut failed) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for name in names {
        let (Some(old), Some(new)) = (
            collector_data(last_good, &name),
            collector_data(current, &name),
        ) else {
            // 片方で取得できていないと全項目が差分に見えるので、1 行にまとめる
            let error = match current["collectors"][&name]["error"].as_str() {
                Some(error) => error,
                None if current["collectors"].get(&name).is_none() => {
                    "現在のスナップショットに含まれていません"
                }
                None => "正常時に取得に成功したことがありません",
            };
            failed.push(format!("- `{name}`: {error}"));
            continue;
        };
        for (path, value) in &new {
            match old.get(path) {
                None => added.push(format!("- `{path}`: {value}")),
                Some(previous) if previous != value => {
                    changed.push(format!("- `{path}`: {previous} ⇒ {value}"));
                }
                Some(_) => {}
            }
        }
        for (path, value) in &old {
            if !new.contains_key(path) {
                removed.push(format!("- `{path}`: {value}"));
            }
        }
    }

    if changed.is_empty() && added.is_empty() && removed.is_empty() && failed.is_empty() {
        text.push_str("差分はありません。\n");
    }
    for (heading, lines) in [
        ("変更", changed),
        ("追加", added),
        ("削除", removed),
        ("比較できなかった項目", failed),
    ] {
        if !lines.is_empty() {
            let _ = writeln!(text, "## {heading}\n\n{}\n", lines.join("\n"));
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn snapshot(routes: Value) -> Value {
        json!({ "taken_at": 100, "collectors": {
            "routes": { "ok": true, "data": routes },
        }})
    }

    fn route(destination: &str, next_hop: &str, metric: u32) -> Value {
        json!({ "destination": destination, "next_hop": next_hop, "metric": metric })
    }

    #[test]
    fn identical_snapshots_have_no_diff() {
        let data = snapshot(json!([route("0.0.0.0/0", "192.168.1.1", 10)]));
        assert!(render_diff(Some(&data), &data).contains("差分はありません"));
    }

    #[test]
    fn inserted_route_does_not_shift_the_others() {
        let old = snapshot(json!([route("10.0.0.0/8", "10.0.0.1", 1)]));
        let new = snapshot(json!([
            route("0.0.0.0/0", "192.168.1.1", 10),
            route("10.0.0.0/8", "10.0.0.1", 1)
        ]));
        let diff = render_diff(Some(&old), &new);
        assert!(diff.contains("## 追加"));
        assert!(!diff.contains("## 変更"));
        assert!(!diff.contains("## 削除"));
    }

    #[test]
    fn changed_value_shows_both_sides() {
        let old = snapshot(json!([route("0.0.0.0/0", "192.168.1.1", 10)]));
        let new = snapshot(json!([route("0.0.0.0/0", "192.168.1.1", 50)]));
        let diff = render_diff(Some(&old), &new);
        assert!(diff.contains("10 ⇒ 50"), "{diff}");
    }

    #[test]
    fn removed_gateway_is_reported() {
        let old = snapshot(json!([route("0.0.0.0/0", "192.168.1.1", 10)]));
        let diff = render_diff(Some(&old), &snapshot(json!([])));
        assert!(diff.contains("## 削除"), "{diff}");
    }

    #[test]
    fn hop_changes_compare_as_a_path_and_ignore_raw_text() {
        let trace = |hops: Value, raw: &str| {
            json!({ "taken_at": 1, "collectors": {
                "traceroute:x": { "ok": true, "data": { "hops": hops, "raw": raw } },
            }})
        };
        let old = trace(json!(["10.0.0.1", null]), "1 ms");
        assert!(
            render_diff(Some(&old), &trace(json!(["10.0.0.1", null]), "9 ms"))
                .contains("差分はありません")
        );
        let diff = render_diff(Some(&old), &trace(json!(["10.0.0.2", null]), "1 ms"));
        assert!(diff.contains("10.0.0.1 → * ⇒ 10.0.0.2 → *"), "{diff}");
    }

    #[test]
    fn failed_collector_is_one_line_not_a_mass_removal() {
        let old = snapshot(json!([route("0.0.0.0/0", "192.168.1.1", 10)]));
        let new = json!({ "taken_at": 2, "collectors": {
            "routes": { "ok": false, "error": "ip not found" },
        }});
        let diff = render_diff(Some(&old), &new);
        assert!(diff.contains("ip not found"));
        assert!(!diff.contains("## 削除"));
    }

    #[test]
    fn missing_baseline_snapshot_is_stated() {
        assert!(render_diff(None, &snapshot(json!([]))).contains("ありません"));
    }
}
