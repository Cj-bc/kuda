//! スナップショットの比較。collector ごとの JSON を平坦化して、変更・追加・削除を並べる。

use crate::collector::{self, CollectorResult, KnownGood, Snapshot};
use crate::time::format_time;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

/// 比較基準の取得時刻。collector ごとに異なりうるので、異なれば範囲で示す
fn baseline_time(last_good: &KnownGood) -> String {
    let times: Vec<i64> = last_good
        .collectors
        .values()
        .map(|entry| entry.taken_at)
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
    let parts: Vec<String> = collector::identity_keys()
        .filter_map(|key| item.get(key).filter(|v| !v.is_null()).map(scalar))
        .collect();
    (!parts.is_empty()).then(|| parts.join(" "))
}

/// JSON をパスと値の組へ平坦化する
fn flatten(path: &str, value: &Value, out: &mut BTreeMap<String, String>) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                if !collector::is_volatile_key(key) {
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

/// 差分の 1 行に載せる文字列。プロセス名やパスは攻撃者が決められるので、改行で見出しや
/// 偽の項目を作られないよう、制御文字と向きを変える書式文字を `\u{..}` の形で見せる。
/// 生の値は current.json と last_known_good.json に残る
fn printable(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_control() || super::unknown::is_bidi_control(c) {
                format!("\\u{{{:x}}}", c as u32)
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// コードの外に置く値。制御文字を見える形にし、リンクや画像になる記号を逃がす
fn literal(text: &str) -> String {
    super::cell(&printable(text))
}

/// インラインコードにする。中のバッククォートより長い区切りで囲み、途中で閉じさせない
fn code(text: &str) -> String {
    let text = printable(text);
    let mut longest = 0;
    let mut run = 0;
    for c in text.chars() {
        run = if c == '`' { run + 1 } else { 0 };
        longest = longest.max(run);
    }
    let fence = "`".repeat(longest + 1);
    // 区切りに接するバッククォートは、空白を挟まないと区切りの一部と読まれる
    if longest > 0 {
        format!("{fence} {text} {fence}")
    } else {
        format!("{fence}{text}{fence}")
    }
}

fn flat_data(name: &str, data: &Value) -> BTreeMap<String, String> {
    let mut flat = BTreeMap::new();
    flatten(name, data, &mut flat);
    flat
}

pub(super) fn render_diff(last_good: Option<&KnownGood>, current: &Snapshot) -> String {
    let mut text = "# 正常時との差分\n\n".to_string();
    let Some(last_good) = last_good else {
        text.push_str("比較できる正常時のスナップショットがありません。\n");
        return text;
    };
    let _ = writeln!(
        text,
        "基準: {} / 現在: {}\n",
        baseline_time(last_good),
        format_time(current.taken_at),
    );

    let names: BTreeSet<&String> = last_good
        .collectors
        .keys()
        .chain(current.collectors.keys())
        .collect();

    let (mut changed, mut added, mut removed, mut failed) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for name in names {
        let baseline = last_good.collectors.get(name).map(|entry| &entry.data);
        let now = match current.collectors.get(name) {
            Some(CollectorResult::Ok(data)) => Some(data),
            _ => None,
        };
        let (Some(old), Some(new)) = (baseline, now) else {
            // 片方で取得できていないと全項目が差分に見えるので、1 行にまとめる
            let error = match current.collectors.get(name) {
                Some(CollectorResult::Failed(error)) => error.as_str(),
                None => "現在のスナップショットに含まれていません",
                Some(CollectorResult::Ok(_)) => "正常時に取得に成功したことがありません",
            };
            failed.push(format!("- {}: {}", code(name), literal(error)));
            continue;
        };
        let (old, new) = (flat_data(name, old), flat_data(name, new));
        for (path, value) in &new {
            match old.get(path) {
                None => added.push(format!("- {}: {}", code(path), literal(value))),
                Some(previous) if previous != value => {
                    changed.push(format!(
                        "- {}: {} ⇒ {}",
                        code(path),
                        literal(previous),
                        literal(value)
                    ));
                }
                Some(_) => {}
            }
        }
        for (path, value) in &old {
            if !new.contains_key(path) {
                removed.push(format!("- {}: {}", code(path), literal(value)));
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

    fn snapshot(routes: Value) -> Snapshot {
        serde_json::from_value(json!({ "taken_at": 100, "collectors": {
            "routes": { "ok": true, "data": routes },
        }}))
        .unwrap()
    }

    /// 成功した collector だけを、全部この時刻に取れた比較基準として使う
    fn known_good(snapshot: &Snapshot) -> KnownGood {
        let collectors = snapshot
            .collectors
            .iter()
            .filter_map(|(name, result)| match result {
                CollectorResult::Ok(data) => Some((
                    name.clone(),
                    collector::KnownGoodEntry {
                        taken_at: snapshot.taken_at,
                        data: data.clone(),
                    },
                )),
                CollectorResult::Failed(_) => None,
            })
            .collect();
        KnownGood { collectors }
    }

    fn route(destination: &str, next_hop: &str, metric: u32) -> Value {
        json!({ "destination": destination, "next_hop": next_hop, "metric": metric })
    }

    #[test]
    fn identical_snapshots_have_no_diff() {
        let data = snapshot(json!([route("0.0.0.0/0", "192.168.1.1", 10)]));
        assert!(render_diff(Some(&known_good(&data)), &data).contains("差分はありません"));
    }

    #[test]
    fn inserted_route_does_not_shift_the_others() {
        let old = snapshot(json!([route("10.0.0.0/8", "10.0.0.1", 1)]));
        let new = snapshot(json!([
            route("0.0.0.0/0", "192.168.1.1", 10),
            route("10.0.0.0/8", "10.0.0.1", 1)
        ]));
        let diff = render_diff(Some(&known_good(&old)), &new);
        assert!(diff.contains("## 追加"));
        assert!(!diff.contains("## 変更"));
        assert!(!diff.contains("## 削除"));
    }

    #[test]
    fn changed_value_shows_both_sides() {
        let old = snapshot(json!([route("0.0.0.0/0", "192.168.1.1", 10)]));
        let new = snapshot(json!([route("0.0.0.0/0", "192.168.1.1", 50)]));
        let diff = render_diff(Some(&known_good(&old)), &new);
        assert!(diff.contains("10 ⇒ 50"), "{diff}");
    }

    #[test]
    fn removed_gateway_is_reported() {
        let old = snapshot(json!([route("0.0.0.0/0", "192.168.1.1", 10)]));
        let diff = render_diff(Some(&known_good(&old)), &snapshot(json!([])));
        assert!(diff.contains("## 削除"), "{diff}");
    }

    #[test]
    fn hop_changes_compare_as_a_path_and_ignore_raw_text() {
        let trace = |hops: Value, raw: &str| -> Snapshot {
            serde_json::from_value(json!({ "taken_at": 1, "collectors": {
                "traceroute:x": { "ok": true, "data": { "hops": hops, "raw": raw } },
            }}))
            .unwrap()
        };
        let old = trace(json!(["10.0.0.1", null]), "1 ms");
        assert!(
            render_diff(
                Some(&known_good(&old)),
                &trace(json!(["10.0.0.1", null]), "9 ms")
            )
            .contains("差分はありません")
        );
        let diff = render_diff(
            Some(&known_good(&old)),
            &trace(json!(["10.0.0.2", null]), "1 ms"),
        );
        assert!(diff.contains("10.0.0.1 → * ⇒ 10.0.0.2 → *"), "{diff}");
    }

    #[test]
    fn failed_collector_is_one_line_not_a_mass_removal() {
        let old = snapshot(json!([route("0.0.0.0/0", "192.168.1.1", 10)]));
        let new: Snapshot = serde_json::from_value(json!({ "taken_at": 2, "collectors": {
            "routes": { "ok": false, "error": "ip not found" },
        }}))
        .unwrap();
        let diff = render_diff(Some(&known_good(&old)), &new);
        assert!(diff.contains("ip not found"));
        assert!(!diff.contains("## 削除"));
    }

    #[test]
    fn missing_baseline_snapshot_is_stated() {
        assert!(render_diff(None, &snapshot(json!([]))).contains("ありません"));
    }

    /// プロセスが決められる名前に改行やバッククォートがあっても、見出しや項目を作れない
    #[test]
    fn hostile_names_cannot_forge_lines() {
        let processes = |data: Value| -> Snapshot {
            serde_json::from_value(json!({ "taken_at": 100, "collectors": {
                "processes": { "ok": true, "data": data },
            }}))
            .unwrap()
        };
        let before = processes(json!({}));
        let hostile = "/tmp/x\n## 変更\n- `ok`: \u{202e}fake`";
        let after = processes(json!({ hostile: { "name": "x\r\n# 見出し" } }));
        let diff = render_diff(Some(&known_good(&before)), &after);
        assert!(!diff.lines().any(|l| l.starts_with("# 見出し")), "{diff}");
        assert!(!diff.lines().any(|l| l.starts_with("## 変更")), "{diff}");
        assert!(!diff.contains('\u{202e}'), "{diff}");
        assert!(diff.contains("\\u{a}## 変更"), "{diff}");
        // 項目は 1 行で、パスはバッククォートを含んでも閉じない区切りで囲まれている
        let line = diff.lines().find(|l| l.contains("/tmp/x")).unwrap();
        assert!(line.starts_with("- `` processes./tmp/x"), "{line}");
    }

    /// 値に画像やリンクの記法があっても、文字どおりに見える（開いただけで外部を読まない）
    #[test]
    fn values_cannot_load_images_or_links() {
        let processes = |name: &str| -> Snapshot {
            serde_json::from_value(json!({ "taken_at": 100, "collectors": {
                "processes": { "ok": true, "data": { "/x": { "name": name } } },
            }}))
            .unwrap()
        };
        let diff = render_diff(
            Some(&known_good(&processes("x"))),
            &processes("![a](https://evil.invalid/p.png)"),
        );
        assert!(
            diff.contains(r"x ⇒ \!\[a\](https://evil.invalid/p.png)"),
            "{diff}"
        );
    }

    #[test]
    fn code_spans_outlast_the_backticks_inside() {
        assert_eq!(code("plain"), "`plain`");
        assert_eq!(code("a`b"), "`` a`b ``");
        assert_eq!(code("a``b"), "``` a``b ```");
    }
}
