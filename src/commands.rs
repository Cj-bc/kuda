//! サブコマンドの本体。

use crate::baseline::{self, SeriesStats, Source};
use crate::collector::{self, CollectorResult, Snapshot};
use crate::config::{BackendKind, Config, ProbeSpec, ProcessSpec, Watch};
use crate::detach;
use crate::diagnosis;
use crate::exec;
use crate::incident::{self, Evidence, Incident};
use crate::investigation;
use crate::known_set::{self, Classification, Roots};
use crate::lock;
use crate::logging;
use crate::metrics::{self, Variables};
use crate::notify::{self, Event};
use crate::paths::{Paths, create_private_dir};
use crate::probe::{self, ProbeRun, ProcessInfo};
use crate::store::{Store, WatchState};
use crate::time::format_time;
use crate::trigger::{self, Outcome};
use anyhow::{Context, Result, bail, ensure};
use chrono::Local;
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

/// collector が失敗した取得の後は、snapshot_interval を待たずにこの間隔で取り直す
const SNAPSHOT_RETRY_INTERVAL: Duration = Duration::from_secs(30 * 60);

/// スナップショットを取る時期か。最後の取得で全 collector が成功していれば snapshot_interval、
/// 失敗した collector があれば再試行の間隔（snapshot_interval が短ければそちら）を、
/// 最後の取得から空ける
fn is_snapshot_due(state: &WatchState, now: i64, interval: Duration) -> bool {
    let wait = if state.last_snapshot_complete == Some(true) {
        interval
    } else {
        interval.min(SNAPSHOT_RETRY_INTERVAL)
    };
    is_due(state.last_snapshot, now, wait)
}

/// スナップショットを取り、取得履歴と比較基準に記録する
fn take_snapshot(store: &Store, watch: &Watch, now: i64) -> Result<Snapshot> {
    let snapshot = collector::take_snapshot(&watch.snapshots.collectors, now);
    let keep = watch.snapshots.keep_good;
    store.record_snapshot(&watch.name, now, &snapshot, keep)?;
    Ok(snapshot)
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
    let mut metrics = run.metrics();
    let classification = match (&watch.probe, &run.processes) {
        (ProbeSpec::Process(spec), Some(processes)) => {
            let classification =
                classify_processes(store, paths, watch, spec, processes, &metrics, now)?;
            metrics.extend(classification.metrics.clone());
            Some(classification)
        }
        _ => None,
    };
    log_run(watch, &run, &metrics);

    let stats = baseline::stats(store, &watch.name, &watch.stats, now)?;
    let mut variables = metrics.clone();
    variables.extend(baseline::variables(&stats));
    let matched = trigger_matches(watch, &variables);

    store.record_run(&watch.name, &run)?;
    if let Some(classification) = &classification {
        classification.record(store, &watch.name, now)?;
    }
    let retention = watch.stats.metrics_retention.as_secs() as i64;
    store.prune_metrics(&watch.name, now - retention)?;
    state.last_probe = Some(now);

    // 異常時の値でベースラインと last_known_good を汚さない
    let healthy = !matched && metrics[metrics::LOSS] < 1.0;
    if healthy {
        baseline::update(store, &watch.name, &watch.stats, &metrics, now)?;
        if is_snapshot_due(&state, now, watch.snapshots.interval)
            && !watch.snapshots.collectors.is_empty()
        {
            take_snapshot(store, watch, now)?;
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
            let pending = classification
                .as_ref()
                .map(Classification::pending_identities)
                .unwrap_or_default();
            fire(store, paths, watch, &run, &stats, since, &reason, &pending)
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
    let current = collector::take_snapshot(&watch.snapshots.collectors, created);
    let collectors: Vec<String> = watch
        .snapshots
        .collectors
        .iter()
        .map(|spec| spec.name())
        .collect();
    let last_good = store.last_known_good(&watch.name, &collectors)?;
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

fn register_investigation(paths: &Paths, watch: &str) -> Option<investigation::Registration> {
    let result =
        probe::enumerate().and_then(|processes| investigation::register(paths, watch, &processes));
    result.unwrap_or_else(|error| {
        log::warn!("{watch}: could not record the investigation: {error:#}");
        None
    })
}

fn trigger_matches(watch: &Watch, variables: &Variables) -> bool {
    watch
        .trigger
        .as_ref()
        .is_some_and(|trigger| trigger.when.matches(variables))
}

/// プロセスを既知の集合と照らして分類する。
///
/// 学習してよいのは正常な回だけ。正常かどうかは条件式の成否で決まるが、その式の変数は
/// 分類の結果に依存する。そこで、まず学習する前提で分類し、式が成立したら（異常なら）
/// 何も学習しない前提でやり直す。やり直すと pending が増えるだけなので、成立したままになる
fn classify_processes(
    store: &Store,
    paths: &Paths,
    watch: &Watch,
    spec: &ProcessSpec,
    processes: &[ProcessInfo],
    metrics: &Variables,
    now: i64,
) -> Result<Classification> {
    let roots = Roots::from_env();
    // kuda 自身と、実行中の調査プロセス（detach されていて親子ではたどれない）
    let mut excluded: Vec<_> = known_set::own_root(processes).into_iter().collect();
    excluded.extend(investigation::running(paths, processes));
    let classify = |learn| {
        known_set::classify(
            store,
            &watch.name,
            spec,
            processes,
            &excluded,
            &roots,
            now,
            learn,
        )
    };
    let classification = classify(true)?;
    if classification.learned == 0 {
        return Ok(classification);
    }
    let mut variables = metrics.clone();
    variables.extend(classification.metrics.clone());
    if trigger_matches(watch, &variables) {
        return classify(false);
    }
    Ok(classification)
}

#[allow(clippy::too_many_arguments)]
fn fire(
    store: &mut Store,
    paths: &Paths,
    watch: &Watch,
    run: &ProbeRun,
    stats: &[SeriesStats],
    since: i64,
    reason: &str,
    pending: &[String],
) -> Result<()> {
    let incident = build_incident(store, paths, watch, run, stats, since, reason)?;
    log::warn!(
        "{}: fired ({reason}); incident {}",
        watch.name,
        incident.dir.display()
    );
    // 事件に含めた分は報告済みにする。同じプロセスでは、クールダウンが明けても再発火しない
    store.mark_reported(&watch.name, pending)?;
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
        let collectors = &watch.snapshots.collectors;
        if collectors.is_empty() {
            println!("{}: no snapshot_collectors configured", watch.name);
            continue;
        }
        // check のロックは取らない。check と並行してよいよう、スナップショットの記録以外は
        // 書かない。ここで読んだ状態を save_state で書き戻すと、収集中に check が保存した状態を巻き戻す
        let state = store.load_state(&watch.name)?;
        let now = now();
        if !force && !is_snapshot_due(&state, now, watch.snapshots.interval) {
            println!(
                "{}: not due yet (snapshot_interval, or the retry interval after a failure)",
                watch.name
            );
            continue;
        }
        let snapshot = take_snapshot(&store, watch, now)?;
        print_collectors(&watch.name, &snapshot);
        failed += snapshot.failed().len();
    }
    if failed > 0 {
        bail!("{failed} collector(s) failed");
    }
    Ok(())
}

fn print_collectors(watch: &str, snapshot: &Snapshot) {
    for (name, result) in &snapshot.collectors {
        match result {
            CollectorResult::Ok(_) => println!("{watch}: {name}: ok"),
            CollectorResult::Failed(error) => println!("{watch}: {name}: FAILED: {error}"),
        }
    }
}

pub struct DiagnoseOptions {
    pub watch: String,
    pub dry_run: bool,
    pub backend: Option<String>,
    pub incident: Option<PathBuf>,
    pub notify: bool,
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
    // 別の watch の事件を、この watch の設定やロックのまま調べない
    ensure!(
        incident.watch == watch.name,
        "incident {} belongs to watch {:?}, not {:?}",
        incident.dir.display(),
        incident.watch,
        watch.name
    );
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
    // 調査の間だけ記録し、check のプロセス監視が調査プロセスを未知として数えないようにする
    let _registration = register_investigation(paths, &watch.name);
    let notify = options.notify && config.general.notify;
    if notify {
        notify::send(&Event::Started { watch: &watch.name });
    }
    let result = diagnosis::investigate(config, paths, diagnose, &incident, override_kind);
    if notify {
        let failed_report = diagnosis::report_path(paths, &incident).ok();
        notify::send(&match &result {
            Ok(report) => Event::Finished {
                watch: &watch.name,
                report,
            },
            Err(_) => Event::Failed {
                watch: &watch.name,
                report: failed_report.as_deref().filter(|path| path.is_file()),
            },
        });
    }
    let report = result?;
    log::info!("{}: report {}", watch.name, report.display());
    println!("report: {}", report.display());
    Ok(())
}

/// 手動の調査用に、今の状態から事件を作る。ベースラインには記録しない
fn manual_incident(paths: &Paths, watch: &Watch) -> Result<Incident> {
    let store = Store::open(&paths.db_file())?;
    let now = now();
    let run = probe::run(&watch.probe, now);
    let stats = baseline::stats(&store, &watch.name, &watch.stats, now)?;
    let since = store.load_state(&watch.name)?.trigger.since.unwrap_or(now);
    build_incident(&store, paths, watch, &run, &stats, since, "手動実行")
}

pub fn status(config: &Config, paths: &Paths) -> Result<()> {
    let store = Store::open(&paths.db_file())?;
    for watch in &config.watches {
        let state = store.load_state(&watch.name)?;
        println!("{}", watch.name);
        print_probe_status(&store, watch, &state)?;
        let stats = baseline::stats(&store, &watch.name, &watch.stats, now())?;
        print_baseline(&stats);
        println!("  last snapshot: {}", snapshot_status(&state));
        print_trigger_status(watch, &state, now());
    }
    Ok(())
}

/// 最後の取得時刻と、そのとき失敗した collector があったか。
/// 成否の記録が無いとき（版 3 へ上げた直後）は、失敗とは言い切らない
fn snapshot_status(state: &WatchState) -> String {
    let Some(last) = state.last_snapshot else {
        return "none".to_string();
    };
    match state.last_snapshot_complete {
        Some(true) => format_time(last),
        Some(false) => format!(
            "{} (some collectors failed; last complete: {})",
            format_time(last),
            state
                .last_complete_snapshot
                .map_or("none".to_string(), format_time)
        ),
        None => format!("{} (no complete snapshot recorded yet)", format_time(last)),
    }
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
                && exec::find_program(command).is_none()
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

    /// 最後の取得の成否は、全 collector が成功した時刻と一致するかで決める。
    /// 成功した時刻が無ければ、版 3 へ上げた直後の成否不明とする
    fn snapshot_state(last: Option<i64>, complete: Option<i64>) -> WatchState {
        WatchState {
            last_snapshot: last,
            last_complete_snapshot: complete,
            last_snapshot_complete: complete.map(|complete| Some(complete) == last),
            ..WatchState::default()
        }
    }

    #[test]
    fn failure_at_the_same_second_as_a_success_is_retried() {
        let interval = Duration::from_secs(6 * 3600);
        // 同じ秒に始めた成功と失敗の取得が重なり、時刻は全 collector の成功と一致している
        let state = WatchState {
            last_snapshot_complete: Some(false),
            ..snapshot_state(Some(100), Some(100))
        };
        assert!(is_snapshot_due(&state, 100 + 1800, interval));
        let status = snapshot_status(&state);
        assert!(status.contains("some collectors failed"), "{status}");
    }

    #[test]
    fn snapshot_status_tells_failures_from_unknown() {
        assert_eq!(snapshot_status(&snapshot_state(None, None)), "none");
        assert_eq!(
            snapshot_status(&snapshot_state(Some(100), Some(100))),
            format_time(100)
        );
        let failed = snapshot_status(&snapshot_state(Some(200), Some(100)));
        assert!(failed.contains("some collectors failed"), "{failed}");
        assert!(failed.contains(&format_time(100)), "{failed}");
        // 版 3 へ上げた直後は成否の記録が無いので、失敗とは表示しない
        let unknown = snapshot_status(&snapshot_state(Some(200), None));
        assert!(!unknown.contains("failed"), "{unknown}");
        assert!(
            unknown.contains("no complete snapshot recorded yet"),
            "{unknown}"
        );
    }

    #[test]
    fn complete_snapshot_waits_for_the_full_interval() {
        let interval = Duration::from_secs(6 * 3600);
        let state = snapshot_state(Some(0), Some(0));
        assert!(!is_snapshot_due(&state, 3 * 3600, interval));
        assert!(is_snapshot_due(&state, 6 * 3600, interval));
    }

    #[test]
    fn failed_snapshot_is_retried_sooner() {
        let interval = Duration::from_secs(6 * 3600);
        // 0 に全 collector が成功し、6 時間後の取得で一部が失敗した
        let state = snapshot_state(Some(6 * 3600), Some(0));
        assert!(!is_snapshot_due(&state, 6 * 3600 + 600, interval));
        assert!(is_snapshot_due(&state, 6 * 3600 + 1800, interval));
        // 一度も全 collector が成功していなくても、毎回の check で取り直しはしない
        let never = snapshot_state(Some(100), None);
        assert!(!is_snapshot_due(&never, 400, interval));
        assert!(is_snapshot_due(&never, 1900, interval));
        assert!(is_snapshot_due(&snapshot_state(None, None), 0, interval));
    }

    #[test]
    fn early_forced_failure_is_retried_without_waiting_for_the_interval() {
        let interval = Duration::from_secs(6 * 3600);
        // 0 に全 collector が成功し、1 時間後の snapshot --force で一部が失敗した
        let state = snapshot_state(Some(3600), Some(0));
        assert!(!is_snapshot_due(&state, 3600 + 600, interval));
        assert!(is_snapshot_due(&state, 3600 + 1800, interval));
    }

    #[test]
    fn early_forced_success_restarts_the_interval() {
        let interval = Duration::from_secs(6 * 3600);
        let state = snapshot_state(Some(3600), Some(3600));
        assert!(!is_snapshot_due(&state, 6 * 3600, interval));
        assert!(is_snapshot_due(&state, 7 * 3600, interval));
    }

    #[test]
    fn retry_never_waits_longer_than_the_interval() {
        let interval = Duration::from_secs(600);
        let state = snapshot_state(Some(1000), Some(0));
        assert!(is_snapshot_due(&state, 1600, interval));
    }

    #[test]
    fn slack_is_capped_for_long_intervals() {
        let interval = Duration::from_secs(21600);
        assert!(!is_due(Some(0), 21569, interval));
        assert!(is_due(Some(0), 21570, interval));
    }

    /// 実際に列挙して check_watch を通す。学習期間が無い watch なので、初回に見えたものは
    /// すべて pending になって発火し、報告済みになる。次の回でも報告済みのまま残る
    #[test]
    fn process_watch_reports_unknown_processes_once() {
        let dir = std::env::temp_dir().join(format!("kuda-check-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("config.toml");
        std::fs::write(
            &config_path,
            "[[watch]]\nname = \"p\"\n[watch.probe]\nkind = \"process\"\n\
             [watch.baseline]\nlearn_for = \"0s\"\n\
             [watch.trigger]\nwhen = \"unknown >= 1\"\nconsecutive = 1\ncooldown = \"0s\"\n",
        )
        .unwrap();
        let config = Config::load(&config_path).unwrap();
        let watch = config.watch("p").unwrap();
        let paths = Paths {
            config_dir: dir.clone(),
            data_dir: dir.clone(),
            incidents_dir: dir.join("incidents"),
            logs_dir: dir.join("logs"),
            reports_dir: dir.join("reports"),
            lock_dir: dir.clone(),
            lock_fallback: false,
        };
        let mut store = Store::in_memory().unwrap();

        check_watch(&mut store, &paths, watch, true, 1000).unwrap();
        let statuses = store.identity_statuses("p").unwrap();
        assert!(!statuses.is_empty());
        assert!(
            statuses
                .values()
                .all(|s| *s == crate::store::IdentityStatus::Reported)
        );
        let incidents = || {
            std::fs::read_dir(paths.incidents_dir.join("p"))
                .unwrap()
                .count()
        };
        assert_eq!(incidents(), 1);

        check_watch(&mut store, &paths, watch, true, 2000).unwrap();
        // 並行するテストが新しいプロセスを起こすので、事件の数は数えない。報告済みは戻らない
        let after = store.identity_statuses("p").unwrap();
        assert!(
            statuses
                .keys()
                .all(|key| after[key] == crate::store::IdentityStatus::Reported)
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
