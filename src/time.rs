//! 人が読む時刻の表記。

use chrono::{Local, TimeZone};

/// Unix 秒をローカル時刻で表す。表せない値はそのまま数で返す
pub fn format_time(ts: i64) -> String {
    Local.timestamp_opt(ts, 0).single().map_or_else(
        || ts.to_string(),
        |time| time.format("%Y-%m-%d %H:%M:%S %:z").to_string(),
    )
}
