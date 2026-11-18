//! watch ごとの判定状態（watch_state）。
//!
//! 1 行を、書く側ごとの 2 つの型に分けて読み書きする。check が書く `ProbeState` と、
//! `record_snapshot` だけが書く `SnapshotState`。check と snapshot は並行して動くので、
//! 片方が読んだ値を丸ごと書き戻すと相手の更新を巻き戻す。書けない型にしておけば、
//! その取り違えを型で防げる。

use super::Store;
use crate::trigger::TriggerState;
use anyhow::Result;
use rusqlite::{OptionalExtension, params};

/// check が所有する probe と trigger の状態
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProbeState {
    pub last_probe: Option<i64>,
    pub trigger: TriggerState,
}

/// スナップショット取得の履歴。`record_snapshot` だけが更新するので、保存する関数は無い
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SnapshotState {
    /// 最後にスナップショットを取得した時刻。collector の成否を問わない
    pub last_snapshot: Option<i64>,
    /// 全 collector が成功した最後の取得の時刻
    pub last_complete_snapshot: Option<i64>,
    /// `last_snapshot` の取得で全 collector が成功したか。版 2 から上げた直後は分からないので None。
    /// 成功と失敗の取得が同じ秒に重なると時刻では見分けられないので、時刻とは別に持つ
    pub last_snapshot_complete: Option<bool>,
}

impl Store {
    pub fn load_probe_state(&self, watch: &str) -> Result<ProbeState> {
        let state = self
            .conn
            .query_row(
                "SELECT last_probe, streak, since, last_fired, active
                 FROM watch_state WHERE watch = ?1",
                params![watch],
                |row| {
                    Ok(ProbeState {
                        last_probe: row.get(0)?,
                        trigger: TriggerState {
                            streak: row.get(1)?,
                            since: row.get(2)?,
                            last_fired: row.get(3)?,
                            active: row.get(4)?,
                        },
                    })
                },
            )
            .optional()?;
        Ok(state.unwrap_or_default())
    }

    pub fn load_snapshot_state(&self, watch: &str) -> Result<SnapshotState> {
        let state = self
            .conn
            .query_row(
                "SELECT last_snapshot, last_complete_snapshot, last_snapshot_complete
                 FROM watch_state WHERE watch = ?1",
                params![watch],
                |row| {
                    Ok(SnapshotState {
                        last_snapshot: row.get(0)?,
                        last_complete_snapshot: row.get(1)?,
                        last_snapshot_complete: row.get(2)?,
                    })
                },
            )
            .optional()?;
        Ok(state.unwrap_or_default())
    }

    /// check が所有する列だけを保存する。スナップショットの列は `record_snapshot` が
    /// 更新するので触らない（snapshot と並行しても巻き戻さない）
    pub fn save_probe_state(&self, watch: &str, state: &ProbeState) -> Result<()> {
        self.conn.execute(
            "INSERT INTO watch_state (watch, last_probe, streak, since, last_fired, active)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT (watch) DO UPDATE SET
                 last_probe = excluded.last_probe,
                 streak = excluded.streak,
                 since = excluded.since,
                 last_fired = excluded.last_fired,
                 active = excluded.active",
            params![
                watch,
                state.last_probe,
                state.trigger.streak,
                state.trigger.since,
                state.trigger.last_fired,
                state.trigger.active
            ],
        )?;
        Ok(())
    }
}
