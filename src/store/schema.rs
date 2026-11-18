//! スキーマと移行。

/// `MIGRATIONS[i]` は版 i の DB を版 i + 1 へ上げる。新規 DB は版 0 から順に適用する。
/// 版を足すときは末尾に追加し、既存の要素は書き換えない
pub(super) const MIGRATIONS: [&str; 4] = [
    SCHEMA_V1,
    HIST_BY_AGGREGATION,
    KNOWN_GOOD,
    PROCESS_IDENTITIES,
];

/// 版 1 の分布に付ける `aggregate_by`。記録時の集計方式が分からない
pub(super) const HIST_V1: &str = "v1";
/// 版 1 の分布のうち、現在の集計方式に合わず引き取れなかったもの。全体の統計にだけ使う
pub(super) const HIST_UNKNOWN: &str = "unknown";

/// 版 2: bucket の意味は集計方式で変わるので、分布を集計方式ごとに分ける
pub(super) const HIST_BY_AGGREGATION: &str = "
    CREATE TABLE baseline_hist_v2 (
        watch TEXT NOT NULL,
        aggregate_by TEXT NOT NULL,
        series TEXT NOT NULL,
        bucket INTEGER NOT NULL,
        bin INTEGER NOT NULL,
        count INTEGER NOT NULL,
        PRIMARY KEY (watch, aggregate_by, series, bucket, bin)
    ) WITHOUT ROWID;
    INSERT INTO baseline_hist_v2 (watch, aggregate_by, series, bucket, bin, count)
        SELECT watch, 'v1', series, bucket, bin, count FROM baseline_hist;
    DROP TABLE baseline_hist;
    ALTER TABLE baseline_hist_v2 RENAME TO baseline_hist;
";

/// 版 3: 取得履歴（snapshots）と比較基準を分ける。比較基準は collector ごとに
/// 最後に成功したデータを持ち、失敗した取得で置き換えない。
/// 既存の履歴からは collector ごとに最後の成功を拾って基準にする。全 collector が
/// 成功した最後の取得時刻は分からないので空にし、次の取得を再試行の間隔で行う
pub(super) const KNOWN_GOOD: &str = "
    CREATE TABLE known_good (
        watch TEXT NOT NULL,
        collector TEXT NOT NULL,
        ts INTEGER NOT NULL,
        data TEXT NOT NULL,
        PRIMARY KEY (watch, collector)
    ) WITHOUT ROWID;
    -- 壊れた行で DB を開けなくならないよう、形の合わない行は読まずに飛ばす。
    -- SQLite は AND を左から評価するとは限らないので、CASE で順序を決める
    INSERT INTO known_good (watch, collector, ts, data)
        SELECT s.watch, c.key, MAX(s.ts), c.value -> '$.data'
        FROM snapshots AS s,
             json_each(
                 CASE WHEN NOT json_valid(s.data) THEN '{}'
                      WHEN json_type(s.data, '$.collectors') = 'object' THEN s.data
                      ELSE '{}' END,
                 '$.collectors'
             ) AS c
        WHERE CASE WHEN c.type = 'object'
                   THEN json_type(c.value, '$.ok') = 'true'
                        AND json_type(c.value, '$.data') IS NOT NULL
                   ELSE 0 END
        GROUP BY s.watch, c.key;
    ALTER TABLE watch_state ADD COLUMN last_complete_snapshot INTEGER;
    ALTER TABLE watch_state ADD COLUMN last_snapshot_complete INTEGER;
";

/// 版 4: プロセスの既知の集合。status は 'known' | 'pending' | 'reported'。
/// 学習期間の起点は、check が所有する他の列と書き込みが混ざらないよう watch_state の別の列に持つ
pub(super) const PROCESS_IDENTITIES: &str = "
    CREATE TABLE process_identities (
        watch TEXT NOT NULL,
        identity TEXT NOT NULL,
        status TEXT NOT NULL,
        first_seen INTEGER NOT NULL,
        last_seen INTEGER NOT NULL,
        seen_count INTEGER NOT NULL,
        PRIMARY KEY (watch, identity)
    ) WITHOUT ROWID;
    ALTER TABLE watch_state ADD COLUMN learning_started INTEGER;
";

pub(super) const SCHEMA_V1: &str = "
    CREATE TABLE probe_results (
        watch TEXT NOT NULL,
        ts INTEGER NOT NULL,
        target TEXT NOT NULL,
        ok INTEGER NOT NULL,
        rtt_ms REAL,
        value REAL,
        error TEXT
    );
    CREATE INDEX probe_results_watch_ts ON probe_results (watch, ts);

    CREATE TABLE metrics (
        watch TEXT NOT NULL,
        ts INTEGER NOT NULL,
        name TEXT NOT NULL,
        value REAL NOT NULL
    );
    CREATE INDEX metrics_watch_ts ON metrics (watch, ts);

    -- 時間帯別の分布。metrics_retention を超えて蓄積する
    CREATE TABLE baseline_hist (
        watch TEXT NOT NULL,
        series TEXT NOT NULL,
        bucket INTEGER NOT NULL,
        bin INTEGER NOT NULL,
        count INTEGER NOT NULL,
        PRIMARY KEY (watch, series, bucket, bin)
    ) WITHOUT ROWID;

    CREATE TABLE snapshots (
        watch TEXT NOT NULL,
        ts INTEGER NOT NULL,
        data TEXT NOT NULL
    );
    CREATE INDEX snapshots_watch_ts ON snapshots (watch, ts);

    CREATE TABLE watch_state (
        watch TEXT PRIMARY KEY,
        last_probe INTEGER,
        last_snapshot INTEGER,
        streak INTEGER NOT NULL,
        since INTEGER,
        last_fired INTEGER,
        active INTEGER NOT NULL
    ) WITHOUT ROWID;
";
