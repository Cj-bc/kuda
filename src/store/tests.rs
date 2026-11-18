use super::*;
use crate::probe::{ProbeRun, TargetResult};
use crate::trigger::TriggerState;
use serde_json::{Value, json};

fn run(ts: i64, ok: bool) -> ProbeRun {
    ProbeRun {
        processes: None,
        ts,
        results: vec![TargetResult {
            target: "t".to_string(),
            ok,
            rtt_ms: ok.then_some(10.0),
            value: None,
            error: (!ok).then(|| "boom".to_string()),
        }],
    }
}

#[test]
fn records_and_reads_back_runs() {
    let mut store = Store::in_memory().unwrap();
    store.record_run("w", &run(100, true)).unwrap();
    store.record_run("w", &run(200, false)).unwrap();
    store.record_run("other", &run(300, true)).unwrap();

    assert_eq!(store.sample_count("w").unwrap(), 2);
    let last = store.last_results("w").unwrap();
    assert_eq!(last.len(), 1);
    assert!(!last[0].ok);
    assert_eq!(last[0].error.as_deref(), Some("boom"));
}

#[test]
fn recent_metrics_limits_by_run_and_sorts_ascending() {
    let mut store = Store::in_memory().unwrap();
    for ts in [100, 200, 300] {
        store.record_run("w", &run(ts, true)).unwrap();
    }
    let rows = store.recent_metrics("w", 2).unwrap();
    assert_eq!(rows.first().unwrap().ts, 200);
    assert_eq!(rows.last().unwrap().ts, 300);
}

#[test]
fn prune_keeps_recent_rows_and_baseline() {
    let mut store = Store::in_memory().unwrap();
    store.record_run("w", &run(100, true)).unwrap();
    store.record_run("w", &run(200, true)).unwrap();
    store.hist_add("w", "hour", "rtt", 1, 5).unwrap();
    store.prune_metrics("w", 150).unwrap();
    assert_eq!(store.sample_count("w").unwrap(), 1);
    assert_eq!(store.hist("w", "rtt", None).unwrap(), [(5, 1)]);
}

#[test]
fn hist_counts_and_merges_buckets() {
    let store = Store::in_memory().unwrap();
    store.hist_add("w", "hour", "rtt", 1, 5).unwrap();
    store.hist_add("w", "hour", "rtt", 1, 5).unwrap();
    store.hist_add("w", "hour", "rtt", 2, 5).unwrap();
    store.hist_add("w", "hour", "rtt", 2, 3).unwrap();
    assert_eq!(store.hist("w", "rtt", Some(("hour", 1))).unwrap(), [(5, 2)]);
    assert_eq!(store.hist("w", "rtt", None).unwrap(), [(3, 1), (5, 3)]);
}

#[test]
fn hist_buckets_are_separated_by_aggregation() {
    let store = Store::in_memory().unwrap();
    store.hist_add("w", "weekday_hour", "rtt", 9, 5).unwrap();
    store.hist_add("w", "hour", "rtt", 9, 3).unwrap();
    assert_eq!(store.hist("w", "rtt", Some(("hour", 9))).unwrap(), [(3, 1)]);
    assert_eq!(
        store.hist("w", "rtt", Some(("weekday_hour", 9))).unwrap(),
        [(5, 1)]
    );
    // 全体の分布は集計方式に依らないので、方式を変える前のサンプルも数える
    assert_eq!(store.hist("w", "rtt", None).unwrap(), [(3, 1), (5, 1)]);
}

#[test]
fn v1_hist_is_kept_without_an_aggregation() {
    let store = Store::in_memory_v1(&[
        ("w", "rtt", 9, 5, 2),
        ("w", "rtt", 30, 3, 1),
        ("w", "loss", 0, 0, 5),
    ])
    .unwrap();
    assert_eq!(Store::version(&store.conn).unwrap(), MIGRATIONS.len());
    // どの集計方式の時間帯としても読まないが、全体の分布には残る
    for aggregate_by in ["weekday_hour", "hour", "none"] {
        assert!(
            store
                .hist("w", "rtt", Some((aggregate_by, 9)))
                .unwrap()
                .is_empty()
        );
    }
    assert_eq!(store.hist("w", "rtt", None).unwrap(), [(3, 1), (5, 2)]);
    assert_eq!(
        store.v1_hist("w").unwrap(),
        Some(V1Hist {
            min_bucket: 0,
            max_bucket: 30,
            samples: 5
        })
    );
    assert_eq!(store.v1_hist("other").unwrap(), None);
}

#[test]
fn v1_hist_is_adopted_once() {
    let store = Store::in_memory_v1(&[("w", "rtt", 9, 5, 2), ("other", "rtt", 9, 5, 1)]).unwrap();
    store.hist_add("w", "hour", "rtt", 9, 5).unwrap();
    store.resolve_v1_hist("w", Some("hour")).unwrap();
    assert_eq!(store.hist("w", "rtt", Some(("hour", 9))).unwrap(), [(5, 3)]);
    assert_eq!(store.v1_hist("w").unwrap(), None);
    // 2 回目以降は引き取るものがない
    store.resolve_v1_hist("w", Some("weekday_hour")).unwrap();
    assert!(
        store
            .hist("w", "rtt", Some(("weekday_hour", 9)))
            .unwrap()
            .is_empty()
    );
    // 他の watch の分布はその watch が引き取るまで残る
    assert!(store.v1_hist("other").unwrap().is_some());
}

#[test]
fn unresolved_v1_hist_counts_only_overall() {
    let store = Store::in_memory_v1(&[("w", "rtt", 9, 5, 2)]).unwrap();
    store.resolve_v1_hist("w", None).unwrap();
    assert_eq!(store.v1_hist("w").unwrap(), None);
    for aggregate_by in ["weekday_hour", "hour", "none"] {
        assert!(
            store
                .hist("w", "rtt", Some((aggregate_by, 9)))
                .unwrap()
                .is_empty()
        );
    }
    assert_eq!(store.hist("w", "rtt", None).unwrap(), [(5, 2)]);
}

#[test]
fn probes_per_hour_follows_the_recorded_runs() {
    let mut store = Store::in_memory().unwrap();
    assert_eq!(store.probes_per_hour("w").unwrap(), 0.0);
    // 5 分間隔で 2 時間
    for i in 0..24 {
        store.record_run("w", &run(i * 300, true)).unwrap();
    }
    let rate = store.probes_per_hour("w").unwrap();
    assert!((rate - 12.0).abs() < 0.6, "{rate}");
}

#[test]
fn v1_file_database_is_migrated_on_open() {
    let db = TempDb::new("v1");
    {
        let conn = Connection::open(db.path()).unwrap();
        conn.execute_batch(&format!("{SCHEMA_V1} PRAGMA user_version = 1;"))
            .unwrap();
        conn.execute(
            "INSERT INTO baseline_hist (watch, series, bucket, bin, count)
             VALUES ('w', 'rtt', 9, 5, 2)",
            [],
        )
        .unwrap();
    }
    let store = db.open();
    assert_eq!(Store::version(&store.conn).unwrap(), MIGRATIONS.len());
    assert_eq!(store.hist("w", "rtt", None).unwrap(), [(5, 2)]);
    drop(store);
    // 開き直しても版は進まず、データも変わらない
    let store = db.open();
    assert_eq!(Store::version(&store.conn).unwrap(), MIGRATIONS.len());
    assert!(store.v1_hist("w").unwrap().is_some());
}

fn ok(data: Value) -> Value {
    json!({ "ok": true, "data": data })
}

fn failed() -> Value {
    json!({ "ok": false, "error": "command not found" })
}

fn snapshot(ts: i64, routes: Value, dns: Value) -> Value {
    json!({ "taken_at": ts, "collectors": { "routes": routes, "dns_config": dns } })
}

fn names() -> Vec<String> {
    vec!["routes".to_string(), "dns_config".to_string()]
}

fn history_count(store: &Store) -> i64 {
    store
        .conn
        .query_row("SELECT COUNT(*) FROM snapshots", [], |row| row.get(0))
        .unwrap()
}

#[test]
fn snapshot_history_keeps_only_the_newest() {
    let store = Store::in_memory().unwrap();
    assert!(store.last_known_good("w", &names()).unwrap().is_none());
    for ts in 1..=4 {
        let data = snapshot(ts, ok(json!({ "n": ts })), ok(json!([])));
        store.record_snapshot("w", ts, &data, 2).unwrap();
    }
    let good = store.last_known_good("w", &names()).unwrap().unwrap();
    assert_eq!(good["collectors"]["routes"]["data"]["n"], 4);
    assert_eq!(good["collectors"]["routes"]["taken_at"], 4);
    assert_eq!(history_count(&store), 2);
}

#[test]
fn failed_collectors_keep_the_last_good_data() {
    let store = Store::in_memory().unwrap();
    let good = snapshot(100, ok(json!({ "n": 1 })), ok(json!({ "s": "a" })));
    store.record_snapshot("w", 100, &good, 5).unwrap();
    let state = store.load_state("w").unwrap();
    assert_eq!(state.last_snapshot, Some(100));
    assert_eq!(state.last_complete_snapshot, Some(100));

    // 部分失敗: 成功した routes だけが新しくなり、dns_config は前回の成功を使い続ける
    let partial = snapshot(200, ok(json!({ "n": 2 })), failed());
    store.record_snapshot("w", 200, &partial, 5).unwrap();
    let baseline = store.last_known_good("w", &names()).unwrap().unwrap();
    assert_eq!(baseline["collectors"]["routes"]["data"]["n"], 2);
    assert_eq!(baseline["collectors"]["routes"]["taken_at"], 200);
    assert_eq!(baseline["collectors"]["dns_config"]["data"]["s"], "a");
    assert_eq!(baseline["collectors"]["dns_config"]["taken_at"], 100);
    let state = store.load_state("w").unwrap();
    assert_eq!(state.last_snapshot, Some(200));
    assert_eq!(state.last_complete_snapshot, Some(100));

    // 全失敗: 比較基準は変わらない
    store
        .record_snapshot("w", 300, &snapshot(300, failed(), failed()), 5)
        .unwrap();
    assert_eq!(
        store.last_known_good("w", &names()).unwrap().unwrap(),
        baseline
    );
    let state = store.load_state("w").unwrap();
    assert_eq!(state.last_snapshot, Some(300));
    assert_eq!(state.last_complete_snapshot, Some(100));
    // 取得履歴には失敗も残る
    assert_eq!(history_count(&store), 3);
}

#[test]
fn baseline_outlives_the_snapshot_history() {
    let store = Store::in_memory().unwrap();
    let good = snapshot(100, ok(json!({ "n": 1 })), ok(json!({ "s": "a" })));
    store.record_snapshot("w", 100, &good, 2).unwrap();
    // 失敗が keep 件を超えて続き、成功した取得が履歴から消えても基準は残る
    for ts in [200, 300, 400] {
        store
            .record_snapshot("w", ts, &snapshot(ts, failed(), failed()), 2)
            .unwrap();
    }
    assert_eq!(history_count(&store), 2);
    let baseline = store.last_known_good("w", &names()).unwrap().unwrap();
    assert_eq!(baseline["collectors"]["routes"]["data"]["n"], 1);
    assert_eq!(baseline["collectors"]["dns_config"]["data"]["s"], "a");
}

#[test]
fn baseline_is_limited_to_the_requested_collectors() {
    let store = Store::in_memory().unwrap();
    let data = snapshot(100, ok(json!(1)), failed());
    store.record_snapshot("w", 100, &data, 5).unwrap();
    // 設定から外した collector の古い基準は比較に出さない
    let only_dns = ["dns_config".to_string()];
    assert!(store.last_known_good("w", &only_dns).unwrap().is_none());
    let baseline = store.last_known_good("w", &names()).unwrap().unwrap();
    assert_eq!(baseline["collectors"]["routes"]["data"], 1);
    assert!(baseline["collectors"].get("dns_config").is_none());
    assert!(store.last_known_good("other", &names()).unwrap().is_none());
}

#[test]
fn a_snapshot_at_the_same_second_replaces_the_baseline() {
    let store = Store::in_memory().unwrap();
    let first = snapshot(100, ok(json!({ "n": 1 })), ok(json!({ "s": "a" })));
    let second = snapshot(100, ok(json!({ "n": 2 })), failed());
    store.record_snapshot("w", 100, &first, 5).unwrap();
    store.record_snapshot("w", 100, &second, 5).unwrap();
    // 同じ秒なら後から記録した方を新しいものとする
    let baseline = store.last_known_good("w", &names()).unwrap().unwrap();
    assert_eq!(baseline["collectors"]["routes"]["data"]["n"], 2);
    assert_eq!(baseline["collectors"]["dns_config"]["data"]["s"], "a");
}

#[test]
fn a_failure_at_the_same_second_as_a_success_is_not_hidden() {
    let complete = snapshot(100, ok(json!(1)), ok(json!(2)));
    let partial = snapshot(100, ok(json!(1)), failed());
    // 成功と失敗のどちらが後に完了しても、その秒の取得は失敗として扱う
    for order in [[&complete, &partial], [&partial, &complete]] {
        let store = Store::in_memory().unwrap();
        for data in order {
            store.record_snapshot("w", 100, data, 5).unwrap();
        }
        let state = store.load_state("w").unwrap();
        assert_eq!(state.last_snapshot, Some(100));
        assert_eq!(state.last_complete_snapshot, Some(100));
        assert_eq!(state.last_snapshot_complete, Some(false));
    }
}

#[test]
fn latest_attempt_decides_whether_the_snapshot_was_complete() {
    let store = Store::in_memory().unwrap();
    let complete = snapshot(100, ok(json!(1)), ok(json!(2)));
    let partial = snapshot(200, ok(json!(1)), failed());
    store.record_snapshot("w", 100, &complete, 5).unwrap();
    assert_eq!(
        store.load_state("w").unwrap().last_snapshot_complete,
        Some(true)
    );
    store.record_snapshot("w", 200, &partial, 5).unwrap();
    assert_eq!(
        store.load_state("w").unwrap().last_snapshot_complete,
        Some(false)
    );
    // 収集開始の早い取得が後から完了しても、最後の取得の成否は変えない
    store.record_snapshot("w", 150, &complete, 5).unwrap();
    assert_eq!(
        store.load_state("w").unwrap().last_snapshot_complete,
        Some(false)
    );
    store.record_snapshot("w", 300, &complete, 5).unwrap();
    assert_eq!(
        store.load_state("w").unwrap().last_snapshot_complete,
        Some(true)
    );
}

#[test]
fn an_earlier_snapshot_finishing_later_does_not_roll_back_the_baseline() {
    let store = Store::in_memory().unwrap();
    let newer = snapshot(200, ok(json!({ "n": 2 })), ok(json!({ "s": "b" })));
    let older = snapshot(100, ok(json!({ "n": 1 })), ok(json!({ "s": "a" })));
    store.record_snapshot("w", 200, &newer, 5).unwrap();
    store.record_snapshot("w", 100, &older, 5).unwrap();
    let baseline = store.last_known_good("w", &names()).unwrap().unwrap();
    assert_eq!(baseline["collectors"]["routes"]["data"]["n"], 2);
    let state = store.load_state("w").unwrap();
    assert_eq!(state.last_snapshot, Some(200));
    assert_eq!(state.last_complete_snapshot, Some(200));
}

/// watch `w` の取得履歴に `snapshots` (ts, data の文字列) を記録した、版 2 の DB
fn v2_db(name: &str, snapshots: &[(i64, String)]) -> TempDb {
    let db = TempDb::new(name);
    let conn = Connection::open(db.path()).unwrap();
    conn.execute_batch(&format!(
        "{SCHEMA_V1} {HIST_BY_AGGREGATION} PRAGMA user_version = 2;"
    ))
    .unwrap();
    for (ts, data) in snapshots {
        conn.execute(
            "INSERT INTO snapshots (watch, ts, data) VALUES ('w', ?1, ?2)",
            params![ts, data],
        )
        .unwrap();
    }
    db
}

#[test]
fn v2_file_database_is_migrated_to_a_per_collector_baseline() {
    // 版 2 では失敗した取得も最新の正常時として保存されていた
    let db = v2_db(
        "v2",
        &[
            (
                100,
                snapshot(100, ok(json!({ "n": 1 })), ok(json!({ "s": "a" }))).to_string(),
            ),
            (
                200,
                snapshot(200, ok(json!({ "n": 2 })), failed()).to_string(),
            ),
            (300, snapshot(300, failed(), failed()).to_string()),
        ],
    );
    Connection::open(db.path())
        .unwrap()
        .execute(
            "INSERT INTO watch_state (watch, last_probe, last_snapshot, streak, active)
             VALUES ('w', 310, 300, 0, 0)",
            [],
        )
        .unwrap();
    let store = db.open();
    assert_eq!(Store::version(&store.conn).unwrap(), MIGRATIONS.len());
    let baseline = store.last_known_good("w", &names()).unwrap().unwrap();
    assert_eq!(baseline["collectors"]["routes"]["data"]["n"], 2);
    assert_eq!(baseline["collectors"]["routes"]["taken_at"], 200);
    assert_eq!(baseline["collectors"]["dns_config"]["data"]["s"], "a");
    assert_eq!(baseline["collectors"]["dns_config"]["taken_at"], 100);
    let state = store.load_state("w").unwrap();
    assert_eq!(state.last_probe, Some(310));
    assert_eq!(state.last_snapshot, Some(300));
    assert_eq!(state.last_complete_snapshot, None);
    assert_eq!(state.last_snapshot_complete, None);
    // 取得履歴はそのまま残る
    assert_eq!(history_count(&store), 3);
}

#[test]
fn v2_migration_skips_malformed_snapshots() {
    let rows = [
        (100, "not json".to_string()),
        (110, json!({ "taken_at": 110 }).to_string()),
        (120, json!({ "collectors": [ok(json!(1))] }).to_string()),
        (
            130,
            json!({ "collectors": { "routes": "ok", "dns_config": { "ok": true } } }).to_string(),
        ),
        (
            90,
            snapshot(90, ok(json!({ "n": 1 })), failed()).to_string(),
        ),
    ];
    let db = v2_db("v2-malformed", &rows);
    let store = db.open();
    assert_eq!(Store::version(&store.conn).unwrap(), MIGRATIONS.len());
    // 形の合わない行は基準にせず、正しい行からは引き継ぐ
    let baseline = store.last_known_good("w", &names()).unwrap().unwrap();
    assert_eq!(baseline["collectors"]["routes"]["data"]["n"], 1);
    assert_eq!(baseline["collectors"]["routes"]["taken_at"], 90);
    assert!(baseline["collectors"].get("dns_config").is_none());
    assert_eq!(history_count(&store), 5);
}

#[test]
fn v2_database_without_snapshots_is_migrated() {
    let db = v2_db("v2-empty", &[]);
    let store = db.open();
    assert_eq!(Store::version(&store.conn).unwrap(), MIGRATIONS.len());
    assert!(store.last_known_good("w", &names()).unwrap().is_none());
}

#[test]
fn v3_database_is_migrated_to_process_identities() {
    let db = TempDb::new("v3");
    let conn = Connection::open(db.path()).unwrap();
    conn.execute_batch(&format!(
        "{SCHEMA_V1} {HIST_BY_AGGREGATION} {KNOWN_GOOD} PRAGMA user_version = 3;
         INSERT INTO watch_state (watch, last_probe, streak, active) VALUES ('w', 310, 2, 1);"
    ))
    .unwrap();
    drop(conn);
    let mut store = db.open();
    assert_eq!(Store::version(&store.conn).unwrap(), MIGRATIONS.len());
    // 既存の状態はそのまま残り、学習期間の起点は未設定になる
    let state = store.load_state("w").unwrap();
    assert_eq!(state.last_probe, Some(310));
    assert_eq!(state.trigger.streak, 2);
    assert_eq!(store.learning_started("w").unwrap(), None);
    assert!(store.identity_statuses("w").unwrap().is_empty());
    store
        .observe_identities("w", 1, &[("a".to_string(), IdentityStatus::Known)])
        .unwrap();
    assert_eq!(store.identity_statuses("w").unwrap().len(), 1);
}

#[test]
fn observing_updates_counters_but_keeps_the_status() {
    let mut store = Store::in_memory().unwrap();
    let seen = |status| [("a".to_string(), status)];
    store
        .observe_identities("w", 10, &seen(IdentityStatus::Pending))
        .unwrap();
    store
        .observe_identities("w", 20, &seen(IdentityStatus::Known))
        .unwrap();
    assert_eq!(
        store.identity_statuses("w").unwrap()["a"],
        IdentityStatus::Pending
    );
    let (first, last, count): (i64, i64, i64) = store
        .conn
        .query_row(
            "SELECT first_seen, last_seen, seen_count FROM process_identities",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!((first, last, count), (10, 20, 2));
}

#[test]
fn only_pending_identities_become_reported() {
    let mut store = Store::in_memory().unwrap();
    store
        .observe_identities(
            "w",
            10,
            &[
                ("p".to_string(), IdentityStatus::Pending),
                ("k".to_string(), IdentityStatus::Known),
            ],
        )
        .unwrap();
    store
        .mark_reported("w", &["p".to_string(), "k".to_string()])
        .unwrap();
    let statuses = store.identity_statuses("w").unwrap();
    assert_eq!(statuses["p"], IdentityStatus::Reported);
    assert_eq!(statuses["k"], IdentityStatus::Known);
    // watch ごとに分かれる
    assert!(store.identity_statuses("other").unwrap().is_empty());
}

#[test]
fn learning_start_is_set_once_and_independent_of_check_state() {
    let store = Store::in_memory().unwrap();
    assert_eq!(store.learning_started("w").unwrap(), None);
    store.start_learning("w", 100).unwrap();
    store.start_learning("w", 200).unwrap();
    assert_eq!(store.learning_started("w").unwrap(), Some(100));
    store
        .save_state(
            "w",
            &WatchState {
                last_probe: Some(300),
                ..WatchState::default()
            },
        )
        .unwrap();
    assert_eq!(store.learning_started("w").unwrap(), Some(100));
    store.start_learning("w", 400).unwrap();
    assert_eq!(store.load_state("w").unwrap().last_probe, Some(300));
}

#[test]
fn state_round_trips_and_defaults_when_missing() {
    let store = Store::in_memory().unwrap();
    assert_eq!(store.load_state("w").unwrap(), WatchState::default());
    let state = WatchState {
        last_probe: Some(1),
        last_snapshot: Some(2),
        last_complete_snapshot: Some(2),
        last_snapshot_complete: Some(true),
        trigger: TriggerState {
            streak: 3,
            since: Some(4),
            last_fired: Some(5),
            active: true,
        },
    };
    store.save_state("w", &state).unwrap();
    store.set_last_snapshot("w", 2).unwrap();
    assert_eq!(store.load_state("w").unwrap(), state);
}

#[test]
fn last_snapshot_alone_creates_default_state() {
    let store = Store::in_memory().unwrap();
    store.set_last_snapshot("w", 2).unwrap();
    let expected = WatchState {
        last_snapshot: Some(2),
        last_complete_snapshot: Some(2),
        last_snapshot_complete: Some(true),
        ..WatchState::default()
    };
    assert_eq!(store.load_state("w").unwrap(), expected);
}

#[test]
fn last_snapshot_never_moves_backwards() {
    let store = Store::in_memory().unwrap();
    // snapshot が 100 に収集を始め、その間に check が 110 で保存し、最後に snapshot が完了する
    store.set_last_snapshot("w", 110).unwrap();
    store.set_last_snapshot("w", 100).unwrap();
    assert_eq!(store.load_state("w").unwrap().last_snapshot, Some(110));
    store.set_last_snapshot("w", 120).unwrap();
    assert_eq!(store.load_state("w").unwrap().last_snapshot, Some(120));
}

/// 別プロセスの代わりに同じファイルを複数の接続で開くための DB。drop で片付ける
struct TempDb {
    dir: std::path::PathBuf,
}

impl TempDb {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("kuda-store-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self { dir }
    }

    fn path(&self) -> std::path::PathBuf {
        self.dir.join("kuda.db")
    }

    fn open(&self) -> Store {
        Store::open(&self.path()).unwrap()
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn snapshot_does_not_roll_back_check_state() {
    // 接続より先に宣言し、接続を閉じてから片付ける
    let db = TempDb::new("snapshot-race");
    let snapshot = db.open();
    let check = db.open();

    // snapshot が収集している間に check が状態を進めて保存し、その後 snapshot が
    // 完了する。commands::snapshot は収集前に読んだ状態を書き戻さず、
    // set_last_snapshot だけを呼ぶ
    let mut checked = check.load_state("w").unwrap();
    checked.last_probe = Some(10);
    checked.trigger = TriggerState {
        streak: 3,
        since: Some(4),
        last_fired: Some(5),
        active: true,
    };
    check.save_state("w", &checked).unwrap();
    snapshot.set_last_snapshot("w", 20).unwrap();

    let state = check.load_state("w").unwrap();
    assert_eq!(state.last_probe, Some(10));
    assert_eq!(state.last_snapshot, Some(20));
    assert_eq!(state.trigger, checked.trigger);
}

#[test]
fn check_does_not_roll_back_last_snapshot() {
    let db = TempDb::new("check-race");
    let snapshot = db.open();
    let check = db.open();

    // check が状態を読んだ後に snapshot が完了し、その後で check が保存する
    let mut state = check.load_state("w").unwrap();
    snapshot.set_last_snapshot("w", 20).unwrap();
    state.last_probe = Some(30);
    check.save_state("w", &state).unwrap();

    let state = snapshot.load_state("w").unwrap();
    assert_eq!(state.last_probe, Some(30));
    assert_eq!(state.last_snapshot, Some(20));
}

#[test]
fn new_database_is_at_the_latest_version() {
    let store = Store::in_memory().unwrap();
    assert_eq!(Store::version(&store.conn).unwrap(), MIGRATIONS.len());
}

#[test]
fn rejects_a_database_from_a_newer_kuda() {
    let db = TempDb::new("newer");
    let path = db.path();
    Connection::open(&path)
        .unwrap()
        .pragma_update(None, "user_version", MIGRATIONS.len() as i64 + 1)
        .unwrap();
    let error = Store::open(&path).err().unwrap().to_string();
    assert!(error.contains(&path.display().to_string()), "{error}");
    assert!(error.contains("Update kuda"), "{error}");
    // 拒否した DB は書き換えない
    let version = Store::version(&Connection::open(&path).unwrap()).unwrap();
    assert_eq!(version, MIGRATIONS.len() + 1);
}

#[test]
fn reopening_keeps_data() {
    let db = TempDb::new("reopen");
    db.open().record_run("w", &run(100, true)).unwrap();
    assert_eq!(db.open().sample_count("w").unwrap(), 1);
}
