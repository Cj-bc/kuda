//! 事件ディレクトリ（現在のスナップショット、正常時との差分、メトリクス）の生成。

mod diff;

use crate::baseline::{SeriesStats, Source};
use crate::collector::{KnownGood, Snapshot};
use crate::metrics::{Variables, series_of};
use crate::paths::{create_private_dir, is_safe_name};
use crate::probe::ProbeRun;
use crate::store::MetricRow;
use crate::time::format_time;
use anyhow::{Context, Result, ensure};
use chrono::{Local, TimeZone};
use diff::render_diff;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

const META_FILE: &str = "incident.json";

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
    /// `run.metrics()` に分類の指標を足したもの。`run` だけでは process の指標が欠ける
    pub metrics: &'a Variables,
    pub stats: &'a [SeriesStats],
    pub history: &'a [MetricRow],
    pub current: &'a Snapshot,
    /// collector ごとの最後の成功データ（`Store::last_known_good`）
    pub last_good: Option<&'a KnownGood>,
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
    write("diff.md", render_diff(evidence.last_good, evidence.current))?;
    write(
        "current.json",
        serde_json::to_string_pretty(evidence.current)?,
    )?;
    if let Some(data) = evidence.last_good {
        write("last_known_good.json", serde_json::to_string_pretty(data)?)?;
    }
    write("metrics.csv", render_metrics(evidence))?;
    write(META_FILE, serde_json::to_string_pretty(&incident)?)?;
    Ok(incident)
}

/// create_unique_dir が付ける形の id（時刻と連番）か。英字を通さないので
/// `-recovered` の回復レポートや Windows の予約名（NUL など）と重ならない
fn is_incident_id(id: &str) -> bool {
    !id.is_empty() && id.chars().all(|c| c.is_ascii_digit() || c == '-')
}

pub fn load(dir: &Path) -> Result<Incident> {
    let path = dir.join(META_FILE);
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let mut incident: Incident = serde_json::from_str(&text)?;
    // watch と id はレポートの保存先パスに使う。他人から受け取った事件でも外へ書かせない
    ensure!(
        is_safe_name(&incident.watch),
        "{} has an invalid watch: {:?}",
        path.display(),
        incident.watch
    );
    ensure!(
        is_incident_id(&incident.id),
        "{} has an invalid id: {:?}",
        path.display(),
        incident.id
    );
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
    for (name, value) in evidence.metrics {
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
    text.push_str("collector ごとに、最後に取得に成功した時点のデータと比べます。\n\n");
    let mut names: BTreeSet<&String> = evidence.current.collectors.keys().collect();
    if let Some(last_good) = evidence.last_good {
        names.extend(last_good.collectors.keys());
    }
    if names.is_empty() {
        text.push_str("ありません。\n");
    }
    for name in names {
        let taken_at = evidence
            .last_good
            .and_then(|last_good| last_good.collectors.get(name))
            .map(|entry| entry.taken_at);
        let time = taken_at.map_or_else(|| "成功した取得がありません".to_string(), format_time);
        let _ = writeln!(text, "- `{name}`: {time}");
    }
    text
}

fn render_metrics(evidence: &Evidence) -> String {
    let baseline = |metric: &str| {
        let series = series_of(metric);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::TargetResult;
    use serde_json::{Value, json};

    fn snapshot(routes: Value) -> Snapshot {
        serde_json::from_value(json!({ "taken_at": 100, "collectors": {
            "routes": { "ok": true, "data": routes },
        }}))
        .unwrap()
    }

    fn route(destination: &str, next_hop: &str, metric: u32) -> Value {
        json!({ "destination": destination, "next_hop": next_hop, "metric": metric })
    }

    #[test]
    fn per_collector_baseline_is_compared_with_its_own_time() {
        // routes は 1 時間前、dns_config は 7 時間前が最後の成功
        let last_good: KnownGood = serde_json::from_value(json!({ "collectors": {
            "routes": { "ok": true, "taken_at": 3600, "data": [route("0.0.0.0/0", "192.168.1.1", 10)] },
            "dns_config": { "ok": true, "taken_at": 0, "data": { "servers": ["192.168.1.1"] } },
        }}))
        .unwrap();
        let current: Snapshot = serde_json::from_value(json!({ "taken_at": 7200, "collectors": {
            "routes": { "ok": true, "data": [route("0.0.0.0/0", "192.168.1.1", 50)] },
            "dns_config": { "ok": true, "data": { "servers": ["192.168.1.1"] } },
            "adapters": { "ok": true, "data": [] },
        }}))
        .unwrap();
        let diff = render_diff(Some(&last_good), &current);
        assert!(
            diff.contains(&format!("{} 〜 {}", format_time(0), format_time(3600))),
            "{diff}"
        );
        assert!(diff.contains("10 ⇒ 50"), "{diff}");
        assert!(
            diff.contains("`adapters`: 正常時に取得に成功したことがありません"),
            "{diff}"
        );

        let run = run();
        let metrics = run.metrics();
        let evidence = Evidence {
            last_good: Some(&last_good),
            ..evidence(&run, &metrics, &current, &[])
        };
        let summary = render_summary(&evidence, 7200);
        assert!(
            summary.contains(&format!("- `dns_config`: {}", format_time(0))),
            "{summary}"
        );
        assert!(
            summary.contains(&format!("- `routes`: {}", format_time(3600))),
            "{summary}"
        );
        assert!(
            summary.contains("- `adapters`: 成功した取得がありません"),
            "{summary}"
        );
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kuda-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn run() -> ProbeRun {
        ProbeRun {
            processes: None,
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
        metrics: &'a Variables,
        current: &'a Snapshot,
        history: &'a [MetricRow],
    ) -> Evidence<'a> {
        Evidence {
            watch: "w",
            reason: "loss >= 0.5",
            since: 900,
            run,
            metrics,
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
        let metrics = run.metrics();
        let current = snapshot(json!([]));
        let history = [MetricRow {
            ts: 1000,
            name: "loss".to_string(),
            value: 1.0,
        }];
        let incident = create(&root, &evidence(&run, &metrics, &current, &history), 1000).unwrap();

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

    /// 分類の指標は ProbeRun からは作り直せない。summary.md には渡された指標を載せる
    #[test]
    fn summary_lists_the_given_metrics_including_classification() {
        let run = run();
        let mut metrics = run.metrics();
        metrics.insert(crate::metrics::UNKNOWN.to_string(), 3.0);
        let current = snapshot(json!([]));
        let summary = render_summary(&evidence(&run, &metrics, &current, &[]), 1000);
        assert!(summary.contains("| unknown | 3.000 |"), "{summary}");
        assert!(summary.contains("| loss | 1.000 |"), "{summary}");
    }

    #[test]
    fn same_second_incidents_get_distinct_dirs() {
        let root = temp_dir("incident-dup");
        let run = run();
        let metrics = run.metrics();
        let current = snapshot(json!([]));
        let first = create(&root, &evidence(&run, &metrics, &current, &[]), 1000).unwrap();
        let second = create(&root, &evidence(&run, &metrics, &current, &[]), 1000).unwrap();
        assert_ne!(first.dir, second.dir);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn prune_removes_only_expired_incidents() {
        let root = temp_dir("incident-prune");
        let run = run();
        let metrics = run.metrics();
        let current = snapshot(json!([]));
        let old = create(&root, &evidence(&run, &metrics, &current, &[]), 1000).unwrap();
        let recent = create(&root, &evidence(&run, &metrics, &current, &[]), 90 * 86400).unwrap();
        prune(&root, 30, 91 * 86400).unwrap();
        assert!(!old.dir.exists());
        assert!(recent.dir.exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn load_rejects_names_unsafe_for_a_report_path() {
        let root = temp_dir("incident-unsafe");
        std::fs::create_dir_all(&root).unwrap();
        for (watch, id) in [
            ("w", "../../escaped"),
            ("w", "a/b"),
            ("w", "a\\b"),
            ("w", ""),
            ("w", "20260101-000000-recovered"),
            ("w", "NUL"),
            ("..", "20260101-000000"),
            ("/abs", "20260101-000000"),
            ("C:", "20260101-000000"),
        ] {
            let meta = json!({"watch": watch, "id": id, "created": 1000, "since": 900});
            std::fs::write(root.join(META_FILE), meta.to_string()).unwrap();
            assert!(load(&root).is_err(), "{watch:?} {id:?}");
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}
