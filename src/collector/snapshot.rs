//! スナップショットと、collector ごとの比較基準の型。
//!
//! DB（`snapshots.data`、`known_good.data`）と事件ディレクトリの JSON は、型を導入する前の
//! 形のまま読み書きする。版 3 への移行 SQL と LLM 向けプロンプトがその形に依存している。
//! キーの出力順も旧来（`json!` が作るキー昇順）に合わせ、フィールドを昇順に宣言する。

use serde::de::Error as _;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use std::collections::BTreeMap;

/// 全 collector を 1 回実行した結果
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Snapshot {
    pub collectors: BTreeMap<String, CollectorResult>,
    pub taken_at: i64,
}

impl Snapshot {
    /// 失敗した collector の名前
    pub fn failed(&self) -> Vec<&str> {
        self.collectors
            .iter()
            .filter(|(_, result)| !result.is_ok())
            .map(|(name, _)| name.as_str())
            .collect()
    }

    /// 全 collector が成功したか
    pub fn is_complete(&self) -> bool {
        self.collectors.values().all(CollectorResult::is_ok)
    }
}

/// collector 1 つの結果。成功時の中身は collector ごとに形が違うので `Value` のまま持つ
#[derive(Debug, Clone, PartialEq)]
pub enum CollectorResult {
    Ok(Value),
    Failed(String),
}

impl CollectorResult {
    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Ok(_))
    }
}

impl Serialize for CollectorResult {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Ok(data) => {
                let mut state = serializer.serialize_struct("CollectorResult", 2)?;
                state.serialize_field("data", data)?;
                state.serialize_field("ok", &true)?;
                state.end()
            }
            Self::Failed(error) => {
                let mut state = serializer.serialize_struct("CollectorResult", 2)?;
                state.serialize_field("error", error)?;
                state.serialize_field("ok", &false)?;
                state.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for CollectorResult {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // 旧実装は `ok` が true 以外なら失敗として扱っていた。欠けた項目は読めた範囲で補う
        #[derive(Deserialize)]
        struct Wire {
            ok: bool,
            #[serde(default)]
            data: Value,
            #[serde(default)]
            error: String,
        }
        let wire = Wire::deserialize(deserializer)?;
        Ok(if wire.ok {
            Self::Ok(wire.data)
        } else {
            Self::Failed(wire.error)
        })
    }
}

/// collector ごとの最後の成功データ（`Store::last_known_good`）。
/// collector によって最後に成功した時刻が違うので、時刻は各エントリに持つ
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KnownGood {
    pub collectors: BTreeMap<String, KnownGoodEntry>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct KnownGoodEntry {
    pub taken_at: i64,
    pub data: Value,
}

impl Serialize for KnownGoodEntry {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // 成功したものしか持たないが、Snapshot の形と揃えて `ok` も書く
        let mut state = serializer.serialize_struct("KnownGoodEntry", 3)?;
        state.serialize_field("data", &self.data)?;
        state.serialize_field("ok", &true)?;
        state.serialize_field("taken_at", &self.taken_at)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for KnownGoodEntry {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            ok: bool,
            taken_at: i64,
            #[serde(default)]
            data: Value,
        }
        let wire = Wire::deserialize(deserializer)?;
        if !wire.ok {
            return Err(D::Error::custom("a known-good entry must have ok = true"));
        }
        Ok(Self {
            taken_at: wire.taken_at,
            data: wire.data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// 旧実装が書いていた JSON 文字列そのまま
    const OLD_SNAPSHOT: &str = r#"{"collectors":{"dns_config":{"error":"command not found","ok":false},"routes":{"data":{"n":1},"ok":true}},"taken_at":100}"#;
    const OLD_KNOWN_GOOD: &str =
        r#"{"collectors":{"routes":{"data":[{"destination":"default"}],"ok":true,"taken_at":50}}}"#;

    fn snapshot() -> Snapshot {
        Snapshot {
            taken_at: 100,
            collectors: BTreeMap::from([
                ("routes".to_string(), CollectorResult::Ok(json!({ "n": 1 }))),
                (
                    "dns_config".to_string(),
                    CollectorResult::Failed("command not found".to_string()),
                ),
            ]),
        }
    }

    #[test]
    fn snapshot_round_trips_the_old_json_shape() {
        assert_eq!(serde_json::to_string(&snapshot()).unwrap(), OLD_SNAPSHOT);
        assert_eq!(
            serde_json::from_str::<Snapshot>(OLD_SNAPSHOT).unwrap(),
            snapshot()
        );
    }

    #[test]
    fn a_null_payload_stays_a_success() {
        let text = r#"{"collectors":{"a":{"data":null,"ok":true}},"taken_at":1}"#;
        let parsed: Snapshot = serde_json::from_str(text).unwrap();
        assert_eq!(parsed.collectors["a"], CollectorResult::Ok(Value::Null));
        assert_eq!(serde_json::to_string(&parsed).unwrap(), text);
    }

    #[test]
    fn a_result_that_is_not_ok_reads_as_failed() {
        let parsed: Snapshot =
            serde_json::from_str(r#"{"collectors":{"a":{"ok":false}},"taken_at":1}"#).unwrap();
        assert_eq!(parsed.failed(), ["a"]);
    }

    #[test]
    fn reports_failed_collectors_and_completeness() {
        let snapshot = snapshot();
        assert_eq!(snapshot.failed(), ["dns_config"]);
        assert!(!snapshot.is_complete());

        let complete = Snapshot {
            taken_at: 1,
            collectors: BTreeMap::from([("a".to_string(), CollectorResult::Ok(json!(1)))]),
        };
        assert!(complete.failed().is_empty());
        assert!(complete.is_complete());
    }

    #[test]
    fn known_good_round_trips_the_old_json_shape() {
        let known_good = KnownGood {
            collectors: BTreeMap::from([(
                "routes".to_string(),
                KnownGoodEntry {
                    taken_at: 50,
                    data: json!([{ "destination": "default" }]),
                },
            )]),
        };
        assert_eq!(serde_json::to_string(&known_good).unwrap(), OLD_KNOWN_GOOD);
        assert_eq!(
            serde_json::from_str::<KnownGood>(OLD_KNOWN_GOOD).unwrap(),
            known_good
        );
    }

    #[test]
    fn a_known_good_entry_that_failed_is_rejected() {
        let text = r#"{"collectors":{"a":{"ok":false,"taken_at":1}}}"#;
        assert!(serde_json::from_str::<KnownGood>(text).is_err());
    }
}
