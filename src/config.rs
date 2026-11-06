//! config.toml の読み込みと検証。

use crate::trigger::Expr;
use anyhow::{Context, Result, bail, ensure};
use log::LevelFilter;
use serde::{Deserialize, Deserializer};
use std::collections::HashSet;
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub general: General,
    #[serde(default)]
    pub backends: Backends,
    #[serde(default, rename = "watch")]
    pub watches: Vec<Watch>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct General {
    #[serde(deserialize_with = "log_level")]
    pub log_level: LevelFilter,
    pub log_retention_days: u32,
    pub incident_retention_days: u32,
}

impl Default for General {
    fn default() -> Self {
        Self {
            log_level: LevelFilter::Info,
            log_retention_days: 14,
            incident_retention_days: 30,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Backends {
    pub claude_code: Option<ClaudeCodeBackend>,
    pub codex: Option<CodexBackend>,
    pub local: Option<LocalBackend>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaudeCodeBackend {
    pub command: String,
    #[serde(default = "default_max_turns")]
    pub max_turns: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodexBackend {
    pub command: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalBackend {
    pub endpoint: String,
    pub model: String,
    #[serde(default)]
    #[allow(dead_code)] // 値は読まない。analyze_only 以外の指定を拒否するために持つ
    pub mode: LocalMode,
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalMode {
    /// ツール実行なしで事件ファイルだけを分析する
    #[default]
    AnalyzeOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    ClaudeCode,
    Codex,
    Local,
}

impl BackendKind {
    pub const ALL: [Self; 3] = [Self::ClaudeCode, Self::Codex, Self::Local];

    pub fn name(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude_code",
            Self::Codex => "codex",
            Self::Local => "local",
        }
    }

    pub fn parse(name: &str) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|kind| kind.name() == name)
            .with_context(|| format!("unknown backend: {name}"))
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Watch {
    pub name: String,
    /// 前回の probe から何秒経っていれば実行するか
    #[serde(default = "default_interval", deserialize_with = "duration")]
    pub interval: Duration,
    pub probe: Probe,
    #[serde(default)]
    pub baseline: Baseline,
    pub trigger: Option<Trigger>,
    pub diagnose: Option<Diagnose>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeKind {
    Tcp,
    Icmp,
    Dns,
    Http,
    Command,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Probe {
    pub kind: ProbeKind,
    #[serde(default)]
    pub targets: Vec<String>,
    #[serde(default = "default_probe_timeout", deserialize_with = "duration")]
    pub timeout: Duration,
    /// kind = "dns": 問い合わせ先。省略時は OS のリゾルバを使う
    pub server: Option<String>,
    /// kind = "http": 期待するステータス。省略時は 2xx/3xx を成功とする
    pub expect_status: Option<u16>,
    /// kind = "command": 実行するコマンドと引数
    #[serde(default)]
    pub command: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregateBy {
    WeekdayHour,
    Hour,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub enum CollectorSpec {
    Adapters,
    Routes,
    DnsConfig,
    Traceroute(String),
}

impl CollectorSpec {
    pub fn name(&self) -> String {
        match self {
            Self::Adapters => "adapters".to_string(),
            Self::Routes => "routes".to_string(),
            Self::DnsConfig => "dns_config".to_string(),
            Self::Traceroute(target) => format!("traceroute:{target}"),
        }
    }
}

impl TryFrom<String> for CollectorSpec {
    type Error = String;

    fn try_from(value: String) -> std::result::Result<Self, String> {
        match value.as_str() {
            "adapters" => Ok(Self::Adapters),
            "routes" => Ok(Self::Routes),
            "dns_config" => Ok(Self::DnsConfig),
            other => match other.strip_prefix("traceroute:") {
                Some(target) if !target.is_empty() => Ok(Self::Traceroute(target.to_string())),
                _ => Err(format!("unknown collector: {other}")),
            },
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Baseline {
    #[serde(deserialize_with = "duration")]
    pub metrics_retention: Duration,
    pub aggregate_by: AggregateBy,
    /// これ未満の時間帯は全体の統計で代用する
    pub min_samples: u64,
    pub snapshot_collectors: Vec<CollectorSpec>,
    #[serde(deserialize_with = "duration")]
    pub snapshot_interval: Duration,
    pub keep_good_snapshots: u32,
}

impl Default for Baseline {
    fn default() -> Self {
        Self {
            metrics_retention: Duration::from_secs(7 * 86400),
            aggregate_by: AggregateBy::WeekdayHour,
            min_samples: 30,
            snapshot_collectors: Vec::new(),
            snapshot_interval: Duration::from_secs(6 * 3600),
            keep_good_snapshots: 5,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trigger {
    pub when: Expr,
    #[serde(default = "default_consecutive")]
    pub consecutive: u32,
    #[serde(default = "default_cooldown", deserialize_with = "duration")]
    pub cooldown: Duration,
    #[serde(default)]
    pub recover_notify: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Diagnose {
    pub backend: BackendKind,
    pub fallback: Option<BackendKind>,
    pub prompt_file: String,
    #[serde(default)]
    pub allowed_commands: AllowedCommands,
    #[serde(default = "default_max_duration", deserialize_with = "duration")]
    pub max_duration: Duration,
}

/// LLM に許可するコマンド。他の OS 向けのコマンドまで許可しないよう OS ごとに持つ
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AllowedCommands {
    pub windows: Vec<String>,
    pub linux: Vec<String>,
}

impl AllowedCommands {
    /// 実行中の OS の分だけを返す
    pub fn current(&self) -> &[String] {
        self.for_os(cfg!(windows))
    }

    fn for_os(&self, windows: bool) -> &[String] {
        if windows { &self.windows } else { &self.linux }
    }
}

fn default_max_turns() -> u32 {
    20
}

fn default_interval() -> Duration {
    Duration::from_secs(300)
}

fn default_probe_timeout() -> Duration {
    Duration::from_secs(3)
}

fn default_consecutive() -> u32 {
    3
}

fn default_cooldown() -> Duration {
    Duration::from_secs(1800)
}

fn default_max_duration() -> Duration {
    Duration::from_secs(300)
}

fn log_level<'de, D: Deserializer<'de>>(deserializer: D) -> Result<LevelFilter, D::Error> {
    let text = String::deserialize(deserializer)?;
    text.parse().map_err(serde::de::Error::custom)
}

fn duration<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Duration, D::Error> {
    let text = String::deserialize(deserializer)?;
    parse_duration(&text).map_err(serde::de::Error::custom)
}

/// "500ms" "3s" "5m" "6h" "7d" 形式の期間を解釈する
pub fn parse_duration(text: &str) -> std::result::Result<Duration, String> {
    let error = || format!("invalid duration: {text:?} (expected e.g. 500ms, 3s, 5m, 6h, 7d)");
    let split = text.find(|c: char| !c.is_ascii_digit()).ok_or_else(error)?;
    let (number, unit) = text.split_at(split);
    let number: u64 = number.parse().map_err(|_| error())?;
    let millis = match unit {
        "ms" => Some(1),
        "s" => Some(1000),
        "m" => Some(60_000),
        "h" => Some(3_600_000),
        "d" => Some(86_400_000),
        _ => None,
    };
    millis
        .and_then(|unit| number.checked_mul(unit))
        .map(Duration::from_millis)
        .ok_or_else(error)
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("invalid config: {}", path.display()))
    }

    fn parse(text: &str) -> Result<Self> {
        let config: Self = toml::from_str(text)?;
        config.validate()?;
        Ok(config)
    }

    pub fn watch(&self, name: &str) -> Result<&Watch> {
        self.watches
            .iter()
            .find(|watch| watch.name == name)
            .with_context(|| format!("no such watch: {name}"))
    }

    fn backend_defined(&self, kind: BackendKind) -> bool {
        match kind {
            BackendKind::ClaudeCode => self.backends.claude_code.is_some(),
            BackendKind::Codex => self.backends.codex.is_some(),
            BackendKind::Local => self.backends.local.is_some(),
        }
    }

    fn validate(&self) -> Result<()> {
        let mut names = HashSet::new();
        for watch in &self.watches {
            // ディレクトリ名と systemd のユニット名にそのまま使うので文字種を絞る
            ensure!(
                !watch.name.is_empty()
                    && watch
                        .name
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
                "watch name must be [A-Za-z0-9_-]+: {:?}",
                watch.name
            );
            ensure!(
                names.insert(&watch.name),
                "duplicate watch name: {}",
                watch.name
            );
            self.validate_watch(watch)
                .with_context(|| format!("watch {:?}", watch.name))?;
        }
        Ok(())
    }

    fn validate_watch(&self, watch: &Watch) -> Result<()> {
        watch.probe.validate()?;
        if let Some(trigger) = &watch.trigger {
            ensure!(trigger.consecutive >= 1, "consecutive must be at least 1");
        }
        if let Some(diagnose) = &watch.diagnose {
            for kind in std::iter::once(diagnose.backend).chain(diagnose.fallback) {
                ensure!(
                    self.backend_defined(kind),
                    "backend {} is not configured in [backends]",
                    kind.name()
                );
            }
        }
        Ok(())
    }
}

impl Probe {
    fn validate(&self) -> Result<()> {
        if self.kind == ProbeKind::Command {
            ensure!(!self.command.is_empty(), "command probe needs `command`");
            ensure!(self.targets.is_empty(), "command probe takes no `targets`");
            return Ok(());
        }
        ensure!(!self.targets.is_empty(), "probe needs `targets`");
        for target in &self.targets {
            match self.kind {
                ProbeKind::Tcp => {
                    let has_port = target
                        .rsplit_once(':')
                        .is_some_and(|(_, port)| port.parse::<u16>().is_ok());
                    if !has_port && target != "gateway" {
                        bail!("tcp target needs a port: {target}");
                    }
                }
                ProbeKind::Http => {
                    if !target.starts_with("http://") && !target.starts_with("https://") {
                        bail!("http target must be a URL: {target}");
                    }
                }
                ProbeKind::Icmp | ProbeKind::Dns | ProbeKind::Command => {}
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL_WATCH: &str = r#"
        [[watch]]
        name = "w"
        [watch.probe]
        kind = "tcp"
        targets = ["192.0.2.1:443"]
    "#;

    #[test]
    fn example_config_is_valid() {
        let config = Config::parse(include_str!("../config.example.toml")).unwrap();
        let watch = config.watch("network-reachability").unwrap();
        assert_eq!(watch.interval, Duration::from_secs(300));
        assert_eq!(watch.probe.kind, ProbeKind::Tcp);
        assert_eq!(watch.baseline.aggregate_by, AggregateBy::WeekdayHour);
        assert_eq!(
            watch.baseline.snapshot_collectors.last(),
            Some(&CollectorSpec::Traceroute("1.1.1.1".to_string()))
        );
        let diagnose = watch.diagnose.as_ref().unwrap();
        assert_eq!(diagnose.backend, BackendKind::ClaudeCode);
        assert_eq!(diagnose.fallback, Some(BackendKind::Local));
        let allowed = &diagnose.allowed_commands;
        assert!(allowed.windows.contains(&"tracert".to_string()));
        assert!(!allowed.windows.contains(&"traceroute".to_string()));
        assert!(allowed.linux.contains(&"traceroute".to_string()));
        assert!(!allowed.linux.contains(&"tracert".to_string()));
    }

    #[test]
    fn optional_sections_get_defaults() {
        let config = Config::parse(MINIMAL_WATCH).unwrap();
        let watch = config.watch("w").unwrap();
        assert_eq!(watch.interval, Duration::from_secs(300));
        assert_eq!(watch.probe.timeout, Duration::from_secs(3));
        assert_eq!(watch.baseline.min_samples, 30);
        assert!(watch.trigger.is_none());
        assert_eq!(config.general.log_retention_days, 14);
    }

    #[test]
    fn parses_durations() {
        assert_eq!(parse_duration("500ms"), Ok(Duration::from_millis(500)));
        assert_eq!(parse_duration("3s"), Ok(Duration::from_secs(3)));
        assert_eq!(parse_duration("5m"), Ok(Duration::from_secs(300)));
        assert_eq!(parse_duration("6h"), Ok(Duration::from_secs(21600)));
        assert_eq!(parse_duration("7d"), Ok(Duration::from_secs(604800)));
        for bad in ["", "5", "m", "5x", "-5m", "1.5h"] {
            assert!(parse_duration(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn rejects_typos_in_keys() {
        let text = MINIMAL_WATCH.replace("targets", "target");
        assert!(Config::parse(&text).is_err());
    }

    #[test]
    fn rejects_unsafe_and_duplicate_watch_names() {
        assert!(Config::parse(&MINIMAL_WATCH.replace("\"w\"", "\"../evil\"")).is_err());
        assert!(Config::parse(&format!("{MINIMAL_WATCH}{MINIMAL_WATCH}")).is_err());
    }

    #[test]
    fn tcp_targets_need_a_port_except_gateway() {
        let with_target = |t: &str| MINIMAL_WATCH.replace("192.0.2.1:443", t);
        assert!(Config::parse(&with_target("gateway")).is_ok());
        assert!(Config::parse(&with_target("gateway:80")).is_ok());
        assert!(Config::parse(&with_target("[::1]:443")).is_ok());
        assert!(Config::parse(&with_target("192.0.2.1")).is_err());
    }

    #[test]
    fn diagnose_backend_must_be_configured() {
        let text = format!(
            "{MINIMAL_WATCH}\n[watch.diagnose]\nbackend = \"codex\"\nprompt_file = \"p.md\"\n"
        );
        assert!(Config::parse(&text).is_err());
        let text = format!("[backends.codex]\ncommand = \"codex\"\n{text}");
        assert!(Config::parse(&text).is_ok());
    }

    fn with_allowed_commands(table: &str) -> String {
        format!(
            "[backends.codex]\ncommand = \"codex\"\n{MINIMAL_WATCH}\n\
             [watch.diagnose]\nbackend = \"codex\"\nprompt_file = \"p.md\"\n{table}"
        )
    }

    #[test]
    fn allowed_commands_are_selected_per_os() {
        let text = with_allowed_commands(
            "[watch.diagnose.allowed_commands]\nwindows = [\"tracert\"]\nlinux = [\"traceroute\"]\n",
        );
        let config = Config::parse(&text).unwrap();
        let diagnose = config.watch("w").unwrap().diagnose.as_ref().unwrap();
        assert_eq!(diagnose.allowed_commands.for_os(true), ["tracert"]);
        assert_eq!(diagnose.allowed_commands.for_os(false), ["traceroute"]);
    }

    #[test]
    fn omitted_os_allows_no_commands() {
        let text = with_allowed_commands("[watch.diagnose.allowed_commands]\nlinux = [\"ping\"]\n");
        let config = Config::parse(&text).unwrap();
        let diagnose = config.watch("w").unwrap().diagnose.as_ref().unwrap();
        assert!(diagnose.allowed_commands.for_os(true).is_empty());
    }

    #[test]
    fn rejects_unknown_os_and_flat_allowed_commands() {
        let unknown = "[watch.diagnose.allowed_commands]\nwindow = [\"ping\"]\n";
        assert!(Config::parse(&with_allowed_commands(unknown)).is_err());
        let flat = "allowed_commands = [\"ping\"]\n";
        assert!(Config::parse(&with_allowed_commands(flat)).is_err());
    }

    #[test]
    fn rejects_unknown_collector() {
        let text = format!("{MINIMAL_WATCH}\n[watch.baseline]\nsnapshot_collectors = [\"nope\"]\n");
        assert!(Config::parse(&text).is_err());
    }
}
