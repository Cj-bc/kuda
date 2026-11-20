//! config.toml の読み込みと検証。

use crate::metrics;
use crate::os::Os;
use crate::paths::is_safe_name;
use crate::trigger::Expr;
use anyhow::{Context, Result, bail, ensure};
use log::LevelFilter;
use serde::{Deserialize, Deserializer};
use std::collections::HashSet;
use std::path::Path;
use std::time::Duration;

/// 検証済みの設定。TOML の形そのままの型は `Raw*` で、ここへは検証を通ったものだけが来る
#[derive(Debug)]
pub struct Config {
    pub general: General,
    pub backends: Backends,
    pub watches: Vec<Watch>,
}

/// config.toml の形そのまま。不正な組み合わせの検出と振り分けは `Config::from_raw` が受け持つ
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default)]
    general: General,
    #[serde(default)]
    backends: Backends,
    #[serde(default, rename = "watch")]
    watches: Vec<RawWatch>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct General {
    #[serde(deserialize_with = "log_level")]
    pub log_level: LevelFilter,
    pub log_retention_days: u32,
    pub incident_retention_days: u32,
    /// 自動で始めた調査の開始と終了をデスクトップ通知で知らせる
    pub notify: bool,
}

impl Default for General {
    fn default() -> Self {
        Self {
            log_level: LevelFilter::Info,
            log_retention_days: 14,
            incident_retention_days: 30,
            notify: true,
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

#[derive(Debug)]
pub struct Watch {
    pub name: String,
    /// 前回の probe から何秒経っていれば実行するか
    pub interval: Duration,
    pub probe: ProbeSpec,
    pub stats: StatsConfig,
    pub snapshots: SnapshotConfig,
    pub trigger: Option<Trigger>,
    pub diagnose: Option<Diagnose>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawWatch {
    name: String,
    #[serde(default = "default_interval", deserialize_with = "duration")]
    interval: Duration,
    probe: RawProbe,
    #[serde(default)]
    baseline: RawBaseline,
    trigger: Option<Trigger>,
    diagnose: Option<Diagnose>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeKind {
    Tcp,
    Icmp,
    Dns,
    Http,
    Command,
    Process,
}

/// probe の種類ごとに、その種類で意味のある設定だけを持つ
#[derive(Debug)]
pub enum ProbeSpec {
    Tcp {
        targets: Vec<String>,
        timeout: Duration,
    },
    Icmp {
        targets: Vec<String>,
        timeout: Duration,
    },
    Dns {
        targets: Vec<String>,
        /// 問い合わせ先。省略時は OS のリゾルバを使う
        server: Option<String>,
        timeout: Duration,
    },
    Http {
        targets: Vec<String>,
        /// 期待するステータス。省略時は 2xx/3xx を成功とする
        expect_status: Option<u16>,
        timeout: Duration,
    },
    /// 実行するコマンドと引数。program が結果の target 名になる
    Command {
        program: String,
        args: Vec<String>,
        timeout: Duration,
    },
    /// プロセスの列挙に timeout は要らない
    Process(ProcessSpec),
}

impl ProbeSpec {
    pub fn kind(&self) -> ProbeKind {
        match self {
            Self::Tcp { .. } => ProbeKind::Tcp,
            Self::Icmp { .. } => ProbeKind::Icmp,
            Self::Dns { .. } => ProbeKind::Dns,
            Self::Http { .. } => ProbeKind::Http,
            Self::Command { .. } => ProbeKind::Command,
            Self::Process(_) => ProbeKind::Process,
        }
    }
}

#[derive(Debug)]
pub struct ProcessSpec {
    /// いるはずのプロセス。正規化後のパスに対する glob で、
    /// 1 つも動いていないパターンを `missing` に数える
    pub expected: Vec<String>,
    /// 監視しないパス（glob）。数えもせず、学習もしない
    pub ignore: Vec<String>,
    /// 最初の probe から、見たものをすべて既知として登録する期間
    pub learn_for: Duration,
}

/// `[watch.probe]` の形そのまま。種類に関わらず全部のキーを受け、`RawProbe::into_spec` が
/// 種類に合うものだけを `ProbeSpec` へ移す
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProbe {
    kind: ProbeKind,
    #[serde(default)]
    targets: Vec<String>,
    #[serde(default = "default_probe_timeout", deserialize_with = "duration")]
    timeout: Duration,
    server: Option<String>,
    expect_status: Option<u16>,
    #[serde(default)]
    command: Vec<String>,
    #[serde(default)]
    expected: Vec<String>,
    #[serde(default)]
    ignore: Vec<String>,
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
    Processes,
    ListeningPorts,
    Traceroute(String),
}

impl CollectorSpec {
    pub fn name(&self) -> String {
        match self {
            Self::Adapters => "adapters".to_string(),
            Self::Routes => "routes".to_string(),
            Self::DnsConfig => "dns_config".to_string(),
            Self::Processes => "processes".to_string(),
            Self::ListeningPorts => "listening_ports".to_string(),
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
            "processes" => Ok(Self::Processes),
            "listening_ports" => Ok(Self::ListeningPorts),
            other => match other.strip_prefix("traceroute:") {
                Some(target) if !target.is_empty() => Ok(Self::Traceroute(target.to_string())),
                _ => Err(format!("unknown collector: {other}")),
            },
        }
    }
}

/// 時間帯ごとの平常値の統計
#[derive(Debug)]
pub struct StatsConfig {
    pub metrics_retention: Duration,
    pub aggregate_by: AggregateBy,
    /// これ未満の時間帯は全体の統計で代用する
    pub min_samples: u64,
}

impl Default for StatsConfig {
    fn default() -> Self {
        Self {
            metrics_retention: Duration::from_secs(7 * 86400),
            aggregate_by: AggregateBy::WeekdayHour,
            min_samples: 30,
        }
    }
}

/// 異常時に見比べる、平常時の状態の snapshot
#[derive(Debug)]
pub struct SnapshotConfig {
    pub collectors: Vec<CollectorSpec>,
    pub interval: Duration,
    pub keep_good: u32,
}

impl Default for SnapshotConfig {
    fn default() -> Self {
        Self {
            collectors: Vec::new(),
            interval: Duration::from_secs(6 * 3600),
            keep_good: 5,
        }
    }
}

/// `[watch.baseline]` の形そのまま。TOML ではこの 1 つの表に、統計・snapshot・
/// プロセスの既知集合の設定が並ぶ。使う側は別々なので `RawWatch::into_watch` が分ける
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct RawBaseline {
    #[serde(deserialize_with = "duration")]
    metrics_retention: Duration,
    aggregate_by: AggregateBy,
    min_samples: u64,
    snapshot_collectors: Vec<CollectorSpec>,
    #[serde(deserialize_with = "duration")]
    snapshot_interval: Duration,
    keep_good_snapshots: u32,
    /// kind = "process" でだけ使い、その場合は必須
    #[serde(deserialize_with = "optional_duration")]
    learn_for: Option<Duration>,
}

impl Default for RawBaseline {
    fn default() -> Self {
        let stats = StatsConfig::default();
        let snapshots = SnapshotConfig::default();
        Self {
            metrics_retention: stats.metrics_retention,
            aggregate_by: stats.aggregate_by,
            min_samples: stats.min_samples,
            snapshot_collectors: snapshots.collectors,
            snapshot_interval: snapshots.interval,
            keep_good_snapshots: snapshots.keep_good,
            learn_for: None,
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
        self.for_os(Os::current())
    }

    fn for_os(&self, os: Os) -> &[String] {
        match os {
            Os::Windows => &self.windows,
            Os::Linux => &self.linux,
        }
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

fn optional_duration<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Duration>, D::Error> {
    let text = String::deserialize(deserializer)?;
    parse_duration(&text)
        .map(Some)
        .map_err(serde::de::Error::custom)
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
        Self::from_raw(toml::from_str(text)?)
    }

    pub fn watch(&self, name: &str) -> Result<&Watch> {
        self.watches
            .iter()
            .find(|watch| watch.name == name)
            .with_context(|| format!("no such watch: {name}"))
    }

    fn from_raw(raw: RawConfig) -> Result<Self> {
        let mut names = HashSet::new();
        let mut watches = Vec::new();
        for raw_watch in raw.watches {
            // ディレクトリ名と systemd のユニット名にそのまま使うので文字種を絞る
            ensure!(
                is_safe_name(&raw_watch.name),
                "watch name must be [A-Za-z0-9_-]+: {:?}",
                raw_watch.name
            );
            ensure!(
                names.insert(raw_watch.name.clone()),
                "duplicate watch name: {}",
                raw_watch.name
            );
            let name = raw_watch.name.clone();
            let watch = raw_watch
                .into_watch(&raw.backends)
                .with_context(|| format!("watch {name:?}"))?;
            watches.push(watch);
        }
        Ok(Self {
            general: raw.general,
            backends: raw.backends,
            watches,
        })
    }
}

impl Backends {
    fn is_defined(&self, kind: BackendKind) -> bool {
        match kind {
            BackendKind::ClaudeCode => self.claude_code.is_some(),
            BackendKind::Codex => self.codex.is_some(),
            BackendKind::Local => self.local.is_some(),
        }
    }
}

impl RawWatch {
    fn into_watch(self, backends: &Backends) -> Result<Watch> {
        let RawBaseline {
            metrics_retention,
            aggregate_by,
            min_samples,
            snapshot_collectors,
            snapshot_interval,
            keep_good_snapshots,
            learn_for,
        } = self.baseline;
        let probe = self.probe.into_spec(learn_for)?;
        if let Some(trigger) = &self.trigger {
            ensure!(trigger.consecutive >= 1, "consecutive must be at least 1");
            // 式の変数は probe の種類で決まるので、パースではなくここで照合する
            let available = metrics::variables_for(probe.kind());
            for name in trigger.when.variables() {
                ensure!(
                    available.contains(&name),
                    "unknown variable: {name} (available: {})",
                    available.join(", ")
                );
            }
        }
        if let Some(diagnose) = &self.diagnose {
            for kind in std::iter::once(diagnose.backend).chain(diagnose.fallback) {
                ensure!(
                    backends.is_defined(kind),
                    "backend {} is not configured in [backends]",
                    kind.name()
                );
            }
        }
        Ok(Watch {
            name: self.name,
            interval: self.interval,
            probe,
            stats: StatsConfig {
                metrics_retention,
                aggregate_by,
                min_samples,
            },
            snapshots: SnapshotConfig {
                collectors: snapshot_collectors,
                interval: snapshot_interval,
                keep_good: keep_good_snapshots,
            },
            trigger: self.trigger,
            diagnose: self.diagnose,
        })
    }
}

impl RawProbe {
    /// `learn_for` は `[watch.baseline]` のキーだが process の設定なので、呼び出し側から受ける
    fn into_spec(self, learn_for: Option<Duration>) -> Result<ProbeSpec> {
        let Self {
            kind,
            targets,
            timeout,
            server,
            expect_status,
            command,
            expected,
            ignore,
        } = self;
        if kind != ProbeKind::Process {
            ensure!(
                expected.is_empty() && ignore.is_empty(),
                "`expected` and `ignore` are only for kind = \"process\""
            );
            ensure!(
                learn_for.is_none(),
                "`learn_for` is only for kind = \"process\""
            );
        }
        // 種類違いのキーを黙って捨てると、効いていると思い込んだまま監視が続く
        ensure!(
            kind == ProbeKind::Dns || server.is_none(),
            "`server` is only for kind = \"dns\""
        );
        ensure!(
            kind == ProbeKind::Http || expect_status.is_none(),
            "`expect_status` is only for kind = \"http\""
        );
        let need_targets = || -> Result<()> {
            ensure!(!targets.is_empty(), "probe needs `targets`");
            Ok(())
        };
        match kind {
            ProbeKind::Process => {
                ensure!(targets.is_empty(), "process probe takes no `targets`");
                ensure!(command.is_empty(), "process probe takes no `command`");
                let learn_for =
                    learn_for.context("process probe needs `learn_for` in [watch.baseline]")?;
                Ok(ProbeSpec::Process(ProcessSpec {
                    expected,
                    ignore,
                    learn_for,
                }))
            }
            ProbeKind::Command => {
                ensure!(targets.is_empty(), "command probe takes no `targets`");
                let (program, args) = command
                    .split_first()
                    .context("command probe needs `command`")?;
                Ok(ProbeSpec::Command {
                    program: program.clone(),
                    args: args.to_vec(),
                    timeout,
                })
            }
            ProbeKind::Tcp => {
                need_targets()?;
                for target in &targets {
                    let has_port = target
                        .rsplit_once(':')
                        .is_some_and(|(_, port)| port.parse::<u16>().is_ok());
                    if !has_port && target != "gateway" {
                        bail!("tcp target needs a port: {target}");
                    }
                }
                Ok(ProbeSpec::Tcp { targets, timeout })
            }
            ProbeKind::Http => {
                need_targets()?;
                for target in &targets {
                    if !target.starts_with("http://") && !target.starts_with("https://") {
                        bail!("http target must be a URL: {target}");
                    }
                }
                Ok(ProbeSpec::Http {
                    targets,
                    expect_status,
                    timeout,
                })
            }
            ProbeKind::Icmp => {
                need_targets()?;
                Ok(ProbeSpec::Icmp { targets, timeout })
            }
            ProbeKind::Dns => {
                need_targets()?;
                Ok(ProbeSpec::Dns {
                    targets,
                    server,
                    timeout,
                })
            }
        }
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
        assert_eq!(watch.probe.kind(), ProbeKind::Tcp);
        assert_eq!(watch.stats.aggregate_by, AggregateBy::WeekdayHour);
        assert_eq!(
            watch.snapshots.collectors.last(),
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
        assert!(matches!(
            watch.probe,
            ProbeSpec::Tcp { timeout, .. } if timeout == Duration::from_secs(3)
        ));
        assert_eq!(watch.stats.min_samples, 30);
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
    fn rejects_keys_of_another_kind() {
        let with_key = |kind: &str, key: &str| {
            let probe = MINIMAL_WATCH.replace("kind = \"tcp\"", &format!("kind = \"{kind}\""));
            let probe = probe.replace("192.0.2.1:443", "https://example.com");
            format!("{probe}{key}\n")
        };
        let server = "server = \"192.0.2.53\"";
        let status = "expect_status = 200";
        assert!(Config::parse(&with_key("dns", server)).is_ok());
        assert!(Config::parse(&with_key("http", status)).is_ok());
        for (kind, key) in [("http", server), ("dns", status), ("icmp", server)] {
            let error = format!("{:#}", Config::parse(&with_key(kind, key)).unwrap_err());
            assert!(error.contains("is only for kind"), "{kind}: {error}");
        }
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
        assert_eq!(diagnose.allowed_commands.for_os(Os::Windows), ["tracert"]);
        assert_eq!(diagnose.allowed_commands.for_os(Os::Linux), ["traceroute"]);
    }

    #[test]
    fn omitted_os_allows_no_commands() {
        let text = with_allowed_commands("[watch.diagnose.allowed_commands]\nlinux = [\"ping\"]\n");
        let config = Config::parse(&text).unwrap();
        let diagnose = config.watch("w").unwrap().diagnose.as_ref().unwrap();
        assert!(diagnose.allowed_commands.for_os(Os::Windows).is_empty());
    }

    #[test]
    fn rejects_unknown_os_and_flat_allowed_commands() {
        let unknown = "[watch.diagnose.allowed_commands]\nwindow = [\"ping\"]\n";
        assert!(Config::parse(&with_allowed_commands(unknown)).is_err());
        let flat = "allowed_commands = [\"ping\"]\n";
        assert!(Config::parse(&with_allowed_commands(flat)).is_err());
    }

    #[test]
    fn rejects_unknown_variable_in_trigger_and_lists_available() {
        let with_when =
            |when: &str| format!("{MINIMAL_WATCH}\n[watch.trigger]\nwhen = \"{when}\"\n");
        assert!(Config::parse(&with_when("loss >= 0.5")).is_ok());
        for bad in ["nope > 1", "loss > 1 || baseline.nope > 1"] {
            let error = format!("{:#}", Config::parse(&with_when(bad)).unwrap_err());
            assert!(error.contains("unknown variable"), "{error}");
            assert!(error.contains("rtt_p50"), "{error}");
        }
    }

    const PROCESS_WATCH: &str = r#"
        [[watch]]
        name = "p"
        [watch.probe]
        kind = "process"
        expected = ['c:\windows\*']
        ignore = ['c:\tmp\*']
        [watch.baseline]
        learn_for = "7d"
        [watch.trigger]
        when = "masquerade >= 1 || unknown >= 3"
    "#;

    #[test]
    fn process_watch_is_valid() {
        let config = Config::parse(PROCESS_WATCH).unwrap();
        let watch = config.watch("p").unwrap();
        assert_eq!(watch.probe.kind(), ProbeKind::Process);
        let ProbeSpec::Process(spec) = &watch.probe else {
            panic!("process probe expected: {:?}", watch.probe);
        };
        assert_eq!(spec.expected.len(), 1);
        assert_eq!(spec.ignore.len(), 1);
        assert_eq!(spec.learn_for, Duration::from_secs(604800));
    }

    #[test]
    fn command_probe_is_split_into_program_and_args() {
        let text = r#"
            [[watch]]
            name = "c"
            [watch.probe]
            kind = "command"
            command = ["check", "--fast"]
        "#;
        let config = Config::parse(text).unwrap();
        let ProbeSpec::Command { program, args, .. } = &config.watch("c").unwrap().probe else {
            panic!("command probe expected");
        };
        assert_eq!(program, "check");
        assert_eq!(args, &["--fast"]);
        assert!(Config::parse(&text.replace(r#"["check", "--fast"]"#, "[]")).is_err());
    }

    #[test]
    fn process_watch_rejects_wrong_combinations() {
        let with = |extra: &str| {
            PROCESS_WATCH.replace(
                "kind = \"process\"",
                &format!("kind = \"process\"\n{extra}"),
            )
        };
        assert!(Config::parse(&with("targets = [\"a:1\"]")).is_err());
        assert!(Config::parse(&with("command = [\"x\"]")).is_err());
        assert!(Config::parse(&PROCESS_WATCH.replace("learn_for = \"7d\"", "")).is_err());
        let bad = PROCESS_WATCH.replace("masquerade >= 1", "baseline.rtt_p95 > 1");
        let error = format!("{:#}", Config::parse(&bad).unwrap_err());
        assert!(error.contains("unknown variable"), "{error}");
        assert!(error.contains("unknown_user_writable"), "{error}");
    }

    #[test]
    fn process_only_keys_are_rejected_for_other_kinds() {
        for extra in ["expected = [\"a\"]", "ignore = [\"a\"]"] {
            let text = MINIMAL_WATCH.replace("kind = \"tcp\"", &format!("kind = \"tcp\"\n{extra}"));
            assert!(Config::parse(&text).is_err(), "{extra}");
        }
        let text = format!("{MINIMAL_WATCH}\n[watch.baseline]\nlearn_for = \"7d\"\n");
        assert!(Config::parse(&text).is_err());
    }

    #[test]
    fn rejects_unknown_collector() {
        let text = format!("{MINIMAL_WATCH}\n[watch.baseline]\nsnapshot_collectors = [\"nope\"]\n");
        assert!(Config::parse(&text).is_err());
    }

    #[test]
    fn accepts_process_collectors() {
        let text = format!(
            "{MINIMAL_WATCH}\n[watch.baseline]\nsnapshot_collectors = [\"processes\", \"listening_ports\"]\n"
        );
        let config = Config::parse(&text).unwrap();
        assert_eq!(
            config.watch("w").unwrap().snapshots.collectors,
            [CollectorSpec::Processes, CollectorSpec::ListeningPorts]
        );
    }
}
