//! サブコマンドの本体。

use crate::baseline::{self, SeriesStats, Source};
use crate::collector;
use crate::config::{BackendKind, Config, Watch};
use crate::detach;
use crate::diagnosis;
use crate::incident::{self, Evidence, Incident, format_time};
use crate::lock;
use crate::logging;
use crate::paths::{Paths, create_private_dir};
use crate::probe::{self, ProbeRun};
use crate::process;
use crate::store::{Store, WatchState};
use crate::trigger::{self, Outcome, Variables};
use anyhow::{Context, Result, bail};
use chrono::Local;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// 事件の metrics.csv に載せる probe の回数（5 分間隔で 24 時間分）
const INCIDENT_HISTORY_RUNS: u32 = 288;

fn now() -> i64 {
    Local::now().timestamp()
}

/// スケジューラの起動はぴったり interval おきとは限らない。わずかに早い起動で
/// 1 周まるごと飛ばさないよう、interval の 1 割（最大 30 秒）の早まりを許す
fn is_due(last: Option<i64>, now: i64, interval: Duration) -> bool {
    let Some(last) = last else {
        return true;
    };
    let interval = interval.as_secs() as i64;
    now - last >= interval - (interval / 10).min(30)
}

pub fn check(config: &Config, paths: &Paths, force: bool) -> Result<()> {
    if !lock::hold_until_exit(&paths.lock_file())? {
        log::info!("another check is running; skipping");
        return Ok(());
    }
    let mut store = Store::open(&paths.db_file())?;
    let mut failures = 0;
    for watch in &config.watches {
        // 1 つの watch の失敗で他の監視を止めない
        if let Err(error) = check_watch(&mut store, paths, watch, force, now()) {
            failures += 1;
            log::error!("watch {}: {error:#}", watch.name);
        }
    }

    logging::prune(
        &paths.logs_dir,
        config.general.log_retention_days,
        Local::now().date_naive(),
    )?;
    incident::prune(
        &paths.incidents_dir,
        config.general.incident_retention_days,
        now(),
    )?;
    if failures > 0 {
        bail!("{failures} watch(es) failed");
    }
    Ok(())
}

fn check_watch(
    store: &mut Store,
    paths: &Paths,
    watch: &Watch,
    force: bool,
    now: i64,
) -> Result<()> {
    let mut state = store.load_state(&watch.name)?;
    if !force && !is_due(state.last_probe, now, watch.interval) {
        log::debug!("{}: interval has not elapsed", watch.name);
        return Ok(());
    }

    let run = probe::run(&watch.probe, now);
    let metrics = run.metrics();
    log_run(watch, &run, &metrics);

    let stats = baseline::stats(store, &watch.name, &watch.baseline, now)?;
    let mut variables = metrics.clone();
    variables.extend(baseline::variables(&stats));
    let matched = watch
        .trigger
        .as_ref()
        .is_some_and(|trigger| trigger.when.matches(&variables));

    store.record_run(&watch.name, &run)?;
    let retention = watch.baseline.metrics_retention.as_secs() as i64;
    store.prune_metrics(&watch.name, now - retention)?;
    state.last_probe = Some(now);

    // 異常時の値でベースラインと last_known_good を汚さない
    let healthy = !matched && metrics["loss"] < 1.0;
    if healthy {
        baseline::update(store, &watch.name, &watch.baseline, &metrics, now)?;
        let due = is_due(state.last_snapshot, now, watch.baseline.snapshot_interval);
        if due && !watch.baseline.snapshot_collectors.is_empty() {
            let snapshot = collector::take_snapshot(&watch.baseline.snapshot_collectors, now);
            let keep = watch.baseline.keep_good_snapshots;
            store.save_snapshot(&watch.name, now, &snapshot, keep)?;
            state.last_snapshot = Some(now);
        }
    }

    let Some(trigger) = &watch.trigger else {
        store.save_state(&watch.name, &state)?;
        return Ok(());
    };
    let since = state.trigger.since;
    let outcome = trigger::advance(&mut state.trigger, matched, trigger, now);
    // 発火の処理で失敗しても二重に発火しないよう、先に状態を保存する
    store.save_state(&watch.name, &state)?;
    log::debug!("{}: trigger outcome {outcome:?}", watch.name);

    match outcome {
        Outcome::Fired => {
            let since = state.trigger.since.unwrap_or(now);
            let reason = format!(
                "{} が {} 回連続で成立",
                trigger.when.source(),
                state.trigger.streak
            );
            fire(store, paths, watch, &run, &stats, since, &reason)
        }
        Outcome::Suppressed => {
            log::info!("{}: in cooldown, not firing", watch.name);
            Ok(())
        }
        Outcome::Recovered if trigger.recover_notify => {
            write_recovery(paths, &watch.name, since.unwrap_or(now), now)
        }
        Outcome::Recovered => {
            log::info!("{}: recovered", watch.name);
            Ok(())
        }
        Outcome::Normal | Outcome::Pending => Ok(()),
    }
}

fn log_run(watch: &Watch, run: &ProbeRun, metrics: &Variables) {
    log::info!("{}: {metrics:?}", watch.name);
    for result in &run.results {
        log::debug!(
            "{}: {} ok={} rtt_ms={:?} error={:?}",
            watch.name,
            result.target,
            result.ok,
            result.rtt_ms,
            result.error
        );
    }
}

fn build_incident(
    store: &Store,
    paths: &Paths,
    watch: &Watch,
    run: &ProbeRun,
    stats: &[SeriesStats],
    since: i64,
    reason: &str,
) -> Result<Incident> {
    let created = now();
    let current = collector::take_snapshot(&watch.baseline.snapshot_collectors, created);
    let last_good = store.last_known_good(&watch.name)?;
    let history = store.recent_metrics(&watch.name, INCIDENT_HISTORY_RUNS)?;
    let evidence = Evidence {
        watch: &watch.name,
        reason,
        since,
        run,
        stats,
        history: &history,
        current: &current,
        last_good: last_good.as_ref(),
    };
    incident::create(&paths.incidents_dir, &evidence, created)
}

fn fire(
    store: &Store,
    paths: &Paths,
    watch: &Watch,
    run: &ProbeRun,
    stats: &[SeriesStats],
    since: i64,
    reason: &str,
) -> Result<()> {
    let incident = build_incident(store, paths, watch, run, stats, since, reason)?;
    log::warn!(
        "{}: fired ({reason}); incident {}",
        watch.name,
        incident.dir.display()
    );
    if watch.diagnose.is_some() {
        detach::spawn_diagnose(&watch.name, &incident.dir)?;
    }
    Ok(())
}

fn write_recovery(paths: &Paths, watch: &str, since: i64, now: i64) -> Result<()> {
    let dir = paths.reports_dir.join(watch);
    create_private_dir(&dir)?;
    let stamp = Local::now().format("%Y%m%d-%H%M%S");
    let path = dir.join(format!("{stamp}-recovered.md"));
    let text = format!(
        "# 回復: {watch}\n\n- 発生開始: {}\n- 回復確認: {}\n",
        format_time(since),
        format_time(now)
    );
    std::fs::write(&path, text).with_context(|| format!("failed to write {}", path.display()))?;
    log::info!("{watch}: recovered; {}", path.display());
    Ok(())
}

pub fn snapshot(config: &Config, paths: &Paths, force: bool, only: Option<&str>) -> Result<()> {
    if let Some(name) = only {
        config.watch(name)?;
    }
    let store = Store::open(&paths.db_file())?;
    let mut failed = 0;
    let selected = config
        .watches
        .iter()
        .filter(|watch| only.is_none_or(|name| name == watch.name));
    for watch in selected {
        let collectors = &watch.baseline.snapshot_collectors;
        if collectors.is_empty() {
            println!("{}: no snapshot_collectors configured", watch.name);
            continue;
        }
        let mut state = store.load_state(&watch.name)?;
        let now = now();
        if !force && !is_due(state.last_snapshot, now, watch.baseline.snapshot_interval) {
            println!("{}: snapshot_interval has not elapsed", watch.name);
            continue;
        }
        let snapshot = collector::take_snapshot(collectors, now);
        print_collectors(&watch.name, &snapshot);
        failed += collector::failed_collectors(&snapshot).len();
        store.save_snapshot(
            &watch.name,
            now,
            &snapshot,
            watch.baseline.keep_good_snapshots,
        )?;
        state.last_snapshot = Some(now);
        store.save_state(&watch.name, &state)?;
    }
    if failed > 0 {
        bail!("{failed} collector(s) failed");
    }
    Ok(())
}

fn print_collectors(watch: &str, snapshot: &Value) {
    let collectors = snapshot["collectors"].as_object().into_iter().flatten();
    for (name, result) in collectors {
        match result["error"].as_str() {
            None => println!("{watch}: {name}: ok"),
            Some(error) => println!("{watch}: {name}: FAILED: {error}"),
        }
    }
}

pub struct DiagnoseOptions {
    pub watch: String,
    pub dry_run: bool,
    pub backend: Option<String>,
    pub incident: Option<PathBuf>,
}

pub fn diagnose(config: &Config, paths: &Paths, options: DiagnoseOptions) -> Result<()> {
    let watch = config.watch(&options.watch)?;
    let override_kind = options
        .backend
        .as_deref()
        .map(BackendKind::parse)
        .transpose()?;

    let incident = match &options.incident {
        Some(dir) => incident::load(dir)?,
        None => manual_incident(paths, watch)?,
    };
    println!("incident: {}", incident.dir.display());
    if options.dry_run {
        return Ok(());
    }

    let diagnose = watch
        .diagnose
        .as_ref()
        .with_context(|| format!("watch {} has no [watch.diagnose]", watch.name))?;
    let lock_path = paths
        .lock_dir
        .join(format!("kuda-diagnose-{}.lock", watch.name));
    if !lock::hold_until_exit(&lock_path)? {
        log::info!("{}: an investigation is already running", watch.name);
        println!("an investigation for {} is already running", watch.name);
        return Ok(());
    }
    let report = diagnosis::investigate(config, paths, diagnose, &incident, override_kind)?;
    log::info!("{}: report {}", watch.name, report.display());
    println!("report: {}", report.display());
    Ok(())
}

/// 手動の調査用に、今の状態から事件を作る。ベースラインには記録しない
fn manual_incident(paths: &Paths, watch: &Watch) -> Result<Incident> {
    let store = Store::open(&paths.db_file())?;
    let now = now();
    let run = probe::run(&watch.probe, now);
    let stats = baseline::stats(&store, &watch.name, &watch.baseline, now)?;
    let since = store.load_state(&watch.name)?.trigger.since.unwrap_or(now);
    build_incident(&store, paths, watch, &run, &stats, since, "手動実行")
}

pub fn status(config: &Config, paths: &Paths) -> Result<()> {
    let store = Store::open(&paths.db_file())?;
    for watch in &config.watches {
        let state = store.load_state(&watch.name)?;
        println!("{}", watch.name);
        print_probe_status(&store, watch, &state)?;
        let stats = baseline::stats(&store, &watch.name, &watch.baseline, now())?;
        print_baseline(&stats);
        let last_snapshot = state.last_snapshot.map_or("none".to_string(), format_time);
        println!("  last snapshot: {last_snapshot}");
        print_trigger_status(watch, &state, now());
    }
    Ok(())
}

fn print_probe_status(store: &Store, watch: &Watch, state: &WatchState) -> Result<()> {
    let last_probe = state.last_probe.map_or("never".to_string(), format_time);
    println!("  last probe: {last_probe}");
    println!("  samples: {}", store.sample_count(&watch.name)?);
    for result in store.last_results(&watch.name)? {
        let outcome = match (&result.error, result.rtt_ms) {
            (Some(error), _) => format!("FAILED: {error}"),
            (None, Some(rtt)) => format!("ok ({rtt:.1} ms)"),
            (None, None) => "ok".to_string(),
        };
        println!("    {}: {outcome}", result.target);
    }
    Ok(())
}

fn print_baseline(stats: &[SeriesStats]) {
    if stats.is_empty() {
        println!("  baseline: not enough samples yet");
    }
    for stat in stats {
        let source = match stat.source {
            Source::Bucket => "this time slot",
            Source::Overall => "overall",
        };
        println!(
            "  baseline {}: p50={:.3} p95={:.3} ({source}, {} samples)",
            stat.series, stat.p50, stat.p95, stat.samples
        );
    }
}

fn print_trigger_status(watch: &Watch, state: &WatchState, now: i64) {
    let Some(trigger) = &watch.trigger else {
        println!("  trigger: none");
        return;
    };
    let cooldown = trigger.cooldown.as_secs() as i64;
    let remaining = state
        .trigger
        .last_fired
        .map_or(0, |fired| fired + cooldown - now)
        .max(0);
    println!(
        "  trigger: streak {}/{}, {}, cooldown remaining {remaining}s",
        state.trigger.streak,
        trigger.consecutive,
        if state.trigger.active {
            "active"
        } else {
            "idle"
        },
    );
}

pub fn check_config(config: &Config, paths: &Paths) -> Result<()> {
    let mut problems = Vec::new();
    for watch in &config.watches {
        let Some(diagnose) = &watch.diagnose else {
            continue;
        };
        let prompt = paths.config_dir.join(&diagnose.prompt_file);
        if !prompt.is_file() {
            problems.push(format!(
                "{}: prompt file not found: {}",
                watch.name,
                prompt.display()
            ));
        }
        for kind in std::iter::once(diagnose.backend).chain(diagnose.fallback) {
            if let Some(command) = backend_command(config, kind)
                && process::find_program(command).is_none()
            {
                problems.push(format!(
                    "{}: {} command not found: {command}",
                    watch.name,
                    kind.name()
                ));
            }
        }
    }
    if !problems.is_empty() {
        for problem in &problems {
            println!("{problem}");
        }
        bail!("{} problem(s) found", problems.len());
    }
    println!("config ok: {} watch(es)", config.watches.len());
    Ok(())
}

/// ローカル LLM はサーバーが常駐とは限らないので、ここでは調べない
fn backend_command(config: &Config, kind: BackendKind) -> Option<&str> {
    match kind {
        BackendKind::ClaudeCode => Some(&config.backends.claude_code.as_ref()?.command),
        BackendKind::Codex => Some(&config.backends.codex.as_ref()?.command),
        BackendKind::Local => None,
    }
}

pub fn check_backends(config: &Config) -> Result<()> {
    for kind in BackendKind::ALL {
        let Ok(backend) = diagnosis::backend(config, kind) else {
            println!("{}: not configured", kind.name());
            continue;
        };
        match backend.available() {
            Ok(detail) => println!("{}: available ({detail})", kind.name()),
            Err(reason) => println!("{}: unavailable: {reason}", kind.name()),
        }
    }
    Ok(())
}

pub fn log_paths(paths: &Paths, config_path: &Path) {
    log::info!(
        "kuda {}: config={} db={} incidents={} reports={} lock={}",
        env!("CARGO_PKG_VERSION"),
        config_path.display(),
        paths.db_file().display(),
        paths.incidents_dir.display(),
        paths.reports_dir.display(),
        paths.lock_file().display(),
    );
    if paths.lock_fallback {
        log::warn!("XDG_RUNTIME_DIR is not available; using the state directory for locks");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_probed_is_due() {
        assert!(is_due(None, 0, Duration::from_secs(300)));
    }

    #[test]
    fn slightly_early_scheduler_runs_are_still_due() {
        let interval = Duration::from_secs(300);
        assert!(is_due(Some(1000), 1299, interval));
        assert!(is_due(Some(1000), 1270, interval));
        assert!(!is_due(Some(1000), 1269, interval));
    }

    #[test]
    fn slack_is_capped_for_long_intervals() {
        let interval = Duration::from_secs(21600);
        assert!(!is_due(Some(0), 21569, interval));
        assert!(is_due(Some(0), 21570, interval));
    }
}
