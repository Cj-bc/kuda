//! プロセスの既知の集合（process_identities）と学習期間の起点。

use super::Store;
use anyhow::{Result, bail};
use rusqlite::{OptionalExtension, params};
use std::collections::HashMap;

/// プロセスの識別キーの扱い
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityStatus {
    /// 既知。数えない
    Known,
    /// 未知。まだ報告していない
    Pending,
    /// 事件に載せて報告済み。`kuda baseline accept` まで既知にならず、数えない
    Reported,
}

impl IdentityStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Known => "known",
            Self::Pending => "pending",
            Self::Reported => "reported",
        }
    }

    fn parse(text: &str) -> Result<Self> {
        match text {
            "known" => Ok(Self::Known),
            "pending" => Ok(Self::Pending),
            "reported" => Ok(Self::Reported),
            other => bail!("unknown identity status: {other}"),
        }
    }
}

impl Store {
    /// 学習期間の起点（最初に分類した時刻）。まだ無ければ None
    pub fn learning_started(&self, watch: &str) -> Result<Option<i64>> {
        let started = self
            .conn
            .query_row(
                "SELECT learning_started FROM watch_state WHERE watch = ?1",
                params![watch],
                |row| row.get(0),
            )
            .optional()?;
        Ok(started.flatten())
    }

    /// 学習期間の起点を記録する。既にあれば変えない。
    /// `save_probe_state` と同じ行を触るが、列が別なので互いを巻き戻さない
    pub fn start_learning(&self, watch: &str, ts: i64) -> Result<()> {
        self.conn.execute(
            "INSERT INTO watch_state (watch, streak, active, learning_started)
             VALUES (?1, 0, 0, ?2)
             ON CONFLICT (watch) DO UPDATE SET
                 learning_started = coalesce(learning_started, excluded.learning_started)",
            params![watch, ts],
        )?;
        Ok(())
    }

    /// watch の識別キーと status を全件返す
    pub fn identity_statuses(&self, watch: &str) -> Result<HashMap<String, IdentityStatus>> {
        let mut statement = self
            .conn
            .prepare("SELECT identity, status FROM process_identities WHERE watch = ?1")?;
        let rows = statement.query_map(params![watch], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut statuses = HashMap::new();
        for row in rows {
            let (identity, status) = row?;
            statuses.insert(identity, IdentityStatus::parse(&status)?);
        }
        Ok(statuses)
    }

    /// 今回見た識別キーを記録する。新しいものは `status` で登録し、
    /// 既にあるものは `last_seen` と `seen_count` だけを更新して status は変えない
    pub fn observe_identities(
        &mut self,
        watch: &str,
        ts: i64,
        seen: &[(String, IdentityStatus)],
    ) -> Result<()> {
        let tx = self.conn.transaction()?;
        for (identity, status) in seen {
            tx.execute(
                "INSERT INTO process_identities
                     (watch, identity, status, first_seen, last_seen, seen_count)
                 VALUES (?1, ?2, ?3, ?4, ?4, 1)
                 ON CONFLICT (watch, identity) DO UPDATE SET
                     last_seen = excluded.last_seen,
                     seen_count = seen_count + 1",
                params![watch, identity, status.as_str(), ts],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// 指定した識別キーのうち pending のものを reported にする。
    /// 報告を始めた後に accept された known を巻き戻さないよう、pending だけを対象にする
    pub fn mark_reported(&mut self, watch: &str, identities: &[String]) -> Result<()> {
        let tx = self.conn.transaction()?;
        for identity in identities {
            tx.execute(
                "UPDATE process_identities SET status = 'reported'
                 WHERE watch = ?1 AND identity = ?2 AND status = 'pending'",
                params![watch, identity],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
}
