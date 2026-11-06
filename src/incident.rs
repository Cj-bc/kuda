//! 事件ディレクトリ（現在のスナップショット、正常時との差分、メトリクス）の生成。

use crate::baseline::{SeriesStats, Source};
use crate::paths::create_private_dir;
use crate::probe::ProbeRun;
use crate::store::MetricRow;
use anyhow::{Context, Result};
use chrono::{Local, TimeZone};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

const META_FILE: &str = "incident.json";

/// 配列の要素を同定するキー。添字で比べると 1 件の増減で後続がすべて差分になる
const IDENTITY_KEYS: [&str; 5] = ["name", "adapter", "destination", "next_hop", "interface"];

/// 毎回変わるので比較しないキー
const VOLATILE_KEYS: [&str; 2] = ["raw", "truncated"];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub watch: String,
    pub id: String,
    pub created: i64,
    pub since: i64,
    #[serde(skip)]
    pub dir: PathBuf,
}

pub struct Evidence<'a> {
    pub watch: &'a str,
    pub reason: &'a str,
    pub since: i64,
    pub run: &'a ProbeRun,
    pub stats: &'a [SeriesStats],
    pub history: &'a [MetricRow],
    pub current: &'a Value,
    pub last_good: Option<&'a (i64, Value)>,
}

pub fn format_time(ts: i64) -> String {
    Local.timestamp_opt(ts, 0).single().map_or_else(
        || ts.to_string(),
        |time| time.format("%Y-%m-%d %H:%M:%S %:z").to_string(),
    )
}

/// 秒単位の時刻から一意なディレクトリを作る。同じ秒に重なったら連番を付ける
fn create_unique_dir(parent: &Path, created: i64) -> Result<(String, PathBuf)> {
    create_private_dir(parent)?;
    let base = Local.timestamp_opt(created, 0).single().map_or_else(
        || created.to_string(),
        |time| time.format("%Y%m%d-%H%M%S").to_string(),
    );
    for attempt in 1..100 {
        let id = match attempt {
            1 => base.clone(),
            n => format!("{base}-{n}"),
        };
        let dir = parent.join(&id);
        if !dir.exists() {
            create_private_dir(&dir)?;
            return Ok((id, dir));
        }
    }
    anyhow::bail!("too many incidents at {base}");
}

pub fn create(incidents_dir: &Path, evidence: &Evidence, created: i64) -> Result<Incident> {
    let (id, dir) = create_unique_dir(&incidents_dir.join(evidence.watch), created)?;
    let incident = Incident {
        watch: evidence.watch.to_string(),
        id,
        created,
        since: evidence.since,
        dir,
    };
    let write = |name: &str, contents: String| {
        let path = incident.dir.join(name);
        std::fs::write(&path, contents).with_context(|| format!("failed to write {name}"))
    };
    write("summary.md", render_summary(evidence, created))?;
    write(
        "diff.md",
        render_diff(evidence.last_good.map(|(_, data)| data), evidence.current),
    )?;
    write(
        "current.json",
        serde_json::to_string_pretty(evidence.current)?,
    )?;
    if let Some((_, data)) = evidence.last_good {
        write("last_known_good.json", serde_json::to_string_pretty(data)?)?;
    }
    write("metrics.csv", render_metrics(evidence))?;
    write(META_FILE, serde_json::to_string_pretty(&incident)?)?;
    Ok(incident)
}

pub fn load(dir: &Path) -> Result<Incident> {
    let path = dir.join(META_FILE);
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let mut incident: Incident = serde_json::from_str(&text)?;
    incident.dir = dir.to_path_buf();
    Ok(incident)
}

/// 保持期間を過ぎた事件ディレクトリを削除する
pub fn prune(incidents_dir: &Path, retention_days: u32, now: i64) -> Result<()> {
    let cutoff = now - i64::from(retention_days) * 86400;
    for watch_dir in std::fs::read_dir(incidents_dir)? {
        let watch_dir = watch_dir?.path();
        if !watch_dir.is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(&watch_dir)? {
            let dir = entry?.path();
            if load(&dir).is_ok_and(|incident| incident.created < cutoff) {
                std::fs::remove_dir_all(&dir)
                    .with_context(|| format!("failed to remove {}", dir.display()))?;
            }
        }
    }
    Ok(())
}

/// Markdown の表を壊す文字を取り除く
fn cell(text: &str) -> String {
    text.replace('|', "\\|").replace(['\r', '\n'], " ")
}

fn format_ms(value: Option<f64>) -> String {
    value.map_or_else(|| "-".to_string(), |ms| format!("{ms:.1} ms"))
}

fn render_summary(evidence: &Evidence, created: i64) -> String {
    let mut text = String::new();
    let _ = writeln!(text, "# 事件サマリ: {}\n", evidence.watch);
    let _ = writeln!(text, "- 検出時刻: {}", format_time(created));
    let _ = writeln!(text, "- 発生開始: {}", format_time(evidence.since));
    let _ = writeln!(text, "- 理由: {}", evidence.reason);
    let _ = writeln!(text, "- OS: {}", std::env::consts::OS);

    text.push_str("\n## 現在の指標\n\n| 指標 | 値 |\n| --- | --- |\n");
    for (name, value) in evidence.run.metrics() {
        let _ = writeln!(text, "| {name} | {value:.3} |");
    }

    text.push_str(
        "\n## ターゲット別の結果\n\n| ターゲット | 結果 | RTT | エラー |\n| --- | --- | --- | --- |\n",
    );
    for result in &evidence.run.results {
        let _ = writeln!(
            text,
            "| {} | {} | {} | {} |",
            cell(&result.target),
            if result.ok { "成功" } else { "失敗" },
            format_ms(result.rtt_ms),
            cell(result.error.as_deref().unwrap_or("-")),
        );
    }

    text.push_str("\n## ベースライン\n\n");
    if evidence.stats.is_empty() {
        text.push_str("データ不足のため、まだありません。\n");
    } else {
        text.push_str(
            "| 系列 | 集計 | サンプル数 | p50 | p95 |\n| --- | --- | --- | --- | --- |\n",
        );
        for stat in evidence.stats {
            let source = match stat.source {
                Source::Bucket => "同時間帯",
                Source::Overall => "全体",
            };
            let _ = writeln!(
                text,
                "| {} | {source} | {} | {:.3} | {:.3} |",
                stat.series, stat.samples, stat.p50, stat.p95
            );
        }
    }

    text.push_str("\n## 最後の正常時スナップショット\n\n");
    match evidence.last_good {
        Some((ts, _)) => {
            let _ = writeln!(text, "{}", format_time(*ts));
        }
        None => text.push_str("ありません。\n"),
    }
    text
}

fn render_metrics(evidence: &Evidence) -> String {
    let baseline = |metric: &str| {
        let series = match metric {
            "rtt_p50" => "rtt",
            other => other,
        };
        let stat = evidence.stats.iter().find(|stat| stat.series == series);
        stat.map_or_else(
            || ",".to_string(),
            |stat| format!("{:.3},{:.3}", stat.p50, stat.p95),
        )
    };
    let mut text = "time,metric,value,baseline_p50,baseline_p95\n".to_string();
    for row in evidence.history {
        let _ = writeln!(
            text,
            "{},{},{:.3},{}",
            format_time(row.ts),
            row.name,
            row.value,
            baseline(&row.name)
        );
    }
    text
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

fn collector_names(snapshot: &Value) -> Vec<String> {
    snapshot["collectors"]
        .as_object()
        .map(|map| map.keys().cloned().collect())
        .unwrap_or_default()
}

fn render_diff(last_good: Option<&Value>, current: &Value) -> String {
    let mut text = "# 正常時との差分\n\n".to_string();
    let Some(last_good) = last_good else {
        text.push_str("比較できる正常時のスナップショットがありません。\n");
        return text;
    };
    let _ = writeln!(
        text,
        "基準: {} / 現在: {}\n",
        last_good["taken_at"]
            .as_i64()
            .map_or_else(|| "?".to_string(), format_time),
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
            let error = current["collectors"][&name]["error"]
                .as_str()
                .or(last_good["collectors"][&name]["error"].as_str())
                .unwrap_or("片方のスナップショットに含まれていません");
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
    use crate::probe::TargetResult;
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

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kuda-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn run() -> ProbeRun {
        ProbeRun {
            ts: 1000,
            results: vec![TargetResult {
                target: "192.0.2.1:443".to_string(),
                ok: false,
                rtt_ms: None,
                value: None,
                error: Some("timed | out".to_string()),
            }],
        }
    }

    fn evidence<'a>(
        run: &'a ProbeRun,
        current: &'a Value,
        history: &'a [MetricRow],
    ) -> Evidence<'a> {
        Evidence {
            watch: "w",
            reason: "loss >= 0.5",
            since: 900,
            run,
            stats: &[],
            history,
            current,
            last_good: None,
        }
    }

    #[test]
    fn creates_all_files_and_can_be_reloaded() {
        let root = temp_dir("incident");
        let run = run();
        let current = snapshot(json!([]));
        let history = [MetricRow {
            ts: 1000,
            name: "loss".to_string(),
            value: 1.0,
        }];
        let incident = create(&root, &evidence(&run, &current, &history), 1000).unwrap();

        for file in ["summary.md", "diff.md", "current.json", "metrics.csv"] {
            assert!(incident.dir.join(file).is_file(), "{file}");
        }
        assert!(!incident.dir.join("last_known_good.json").exists());
        let summary = std::fs::read_to_string(incident.dir.join("summary.md")).unwrap();
        assert!(summary.contains("192.0.2.1:443"));
        assert!(summary.contains("timed \\| out"));
        let csv = std::fs::read_to_string(incident.dir.join("metrics.csv")).unwrap();
        assert!(csv.lines().nth(1).unwrap().ends_with(",loss,1.000,,"));

        let loaded = load(&incident.dir).unwrap();
        assert_eq!(loaded.since, 900);
        assert_eq!(loaded.watch, "w");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn same_second_incidents_get_distinct_dirs() {
        let root = temp_dir("incident-dup");
        let run = run();
        let current = snapshot(json!([]));
        let first = create(&root, &evidence(&run, &current, &[]), 1000).unwrap();
        let second = create(&root, &evidence(&run, &current, &[]), 1000).unwrap();
        assert_ne!(first.dir, second.dir);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn prune_removes_only_expired_incidents() {
        let root = temp_dir("incident-prune");
        let run = run();
        let current = snapshot(json!([]));
        let old = create(&root, &evidence(&run, &current, &[]), 1000).unwrap();
        let recent = create(&root, &evidence(&run, &current, &[]), 90 * 86400).unwrap();
        prune(&root, 30, 91 * 86400).unwrap();
        assert!(!old.dir.exists());
        assert!(recent.dir.exists());
        std::fs::remove_dir_all(root).unwrap();
    }
}
