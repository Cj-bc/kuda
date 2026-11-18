//! スナップショットの取得履歴と、collector ごとの比較基準（last_known_good）。

use super::Store;
use anyhow::Result;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde_json::{Value, json};

impl Store {
    /// 正常時に取得したスナップショットを記録する。取得履歴には失敗した collector も
    /// そのまま残し、新しい `keep` 件だけを残す。比較基準は成功した collector の分だけを
    /// 置き換え、失敗した collector は前回までの成功データを使い続ける。
    /// 全 collector が成功したときだけ、取得時刻を `last_complete_snapshot` にも記録する
    pub fn record_snapshot(&self, watch: &str, ts: i64, snapshot: &Value, keep: u32) -> Result<()> {
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO snapshots (watch, ts, data) VALUES (?1, ?2, ?3)",
            params![watch, ts, snapshot.to_string()],
        )?;
        tx.execute(
            "DELETE FROM snapshots WHERE watch = ?1 AND rowid NOT IN (
                 SELECT rowid FROM snapshots WHERE watch = ?1
                 ORDER BY ts DESC, rowid DESC LIMIT ?2
             )",
            params![watch, keep],
        )?;
        let mut complete = true;
        for (name, result) in snapshot["collectors"].as_object().into_iter().flatten() {
            if result["ok"] != Value::Bool(true) {
                complete = false;
                continue;
            }
            // check と snapshot が並行したとき、収集開始の早い側が後から完了しても戻さない
            tx.execute(
                "INSERT INTO known_good (watch, collector, ts, data) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (watch, collector) DO UPDATE SET ts = excluded.ts, data = excluded.data
                 WHERE excluded.ts >= known_good.ts",
                params![watch, name, ts, result["data"].to_string()],
            )?;
        }
        Self::update_last_snapshot(&tx, watch, ts, complete)?;
        tx.commit()?;
        Ok(())
    }

    /// `collectors` それぞれの最後の成功データをまとめた、比較基準のスナップショット。
    /// collector ごとに取得時刻が異なるので、時刻は各 collector の `taken_at` に持つ。
    /// どれも成功したことがなければ None
    pub fn last_known_good(&self, watch: &str, collectors: &[String]) -> Result<Option<Value>> {
        let mut statement = self
            .conn
            .prepare("SELECT ts, data FROM known_good WHERE watch = ?1 AND collector = ?2")?;
        let mut merged = serde_json::Map::new();
        for name in collectors {
            let row: Option<(i64, String)> = statement
                .query_row(params![watch, name], |row| Ok((row.get(0)?, row.get(1)?)))
                .optional()?;
            if let Some((ts, data)) = row {
                let data: Value = serde_json::from_str(&data)?;
                merged.insert(
                    name.clone(),
                    json!({ "ok": true, "taken_at": ts, "data": data }),
                );
            }
        }
        Ok((!merged.is_empty()).then(|| json!({ "collectors": merged })))
    }

    /// last_snapshot・last_snapshot_complete と、`complete` なら last_complete_snapshot だけを
    /// 更新する。check と snapshot のどちらからも呼ばれるので、他の列は読み込んだ時点の値で
    /// 上書きしない。後から完了した側の収集開始が早いこともあるので、時刻は戻さない。
    /// 同じ秒の取得が重なったら、どちらかが失敗していれば失敗とする
    fn update_last_snapshot(conn: &Connection, watch: &str, ts: i64, complete: bool) -> Result<()> {
        // SET の右辺の列名は、どれも更新前の値を指す
        conn.execute(
            "INSERT INTO watch_state
                 (watch, last_snapshot, last_complete_snapshot, last_snapshot_complete, streak, active)
             VALUES (?1, ?2, ?3, ?4, 0, 0)
             ON CONFLICT (watch) DO UPDATE SET
                 last_snapshot =
                     max(coalesce(last_snapshot, excluded.last_snapshot), excluded.last_snapshot),
                 last_complete_snapshot = max(
                     coalesce(last_complete_snapshot, excluded.last_complete_snapshot),
                     coalesce(excluded.last_complete_snapshot, last_complete_snapshot)
                 ),
                 last_snapshot_complete = CASE
                     WHEN last_snapshot IS NULL OR excluded.last_snapshot > last_snapshot
                         THEN excluded.last_snapshot_complete
                     WHEN excluded.last_snapshot = last_snapshot
                         THEN last_snapshot_complete AND excluded.last_snapshot_complete
                     ELSE last_snapshot_complete
                 END",
            params![watch, ts, complete.then_some(ts), complete],
        )?;
        Ok(())
    }

    /// 全 collector が成功した取得として時刻だけを記録する
    #[cfg(test)]
    pub fn set_last_snapshot(&self, watch: &str, ts: i64) -> Result<()> {
        Self::update_last_snapshot(&self.conn, watch, ts, true)
    }
}
