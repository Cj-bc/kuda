//! LLM による調査。バックエンドの選択、フォールバック、レポートの保存。
//!
//! 使い魔は管の外へ無制限に出さない: 1 回の調査で試すのは主バックエンドと
//! fallback を 1 度ずつだけで、それぞれ `max_duration` で打ち切る。

mod claude_code;
mod codex;
mod local;

use crate::config::{BackendKind, Config, Diagnose};
use crate::incident::{Incident, format_time};
use crate::paths::{Paths, create_private_dir};
use anyhow::{Context, Result, bail};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub struct Request<'a> {
    pub prompt: &'a str,
    pub incident_dir: &'a Path,
    pub allowed_commands: &'a [String],
    pub timeout: Duration,
}

pub trait Backend {
    /// 使える状態か確かめる。理由を添えて失敗を返す
    fn available(&self) -> Result<String, String>;
    /// 調査を実行し、レポート本文を返す
    fn run(&self, request: &Request) -> Result<String>;
}

pub fn backend(config: &Config, kind: BackendKind) -> Result<Box<dyn Backend>> {
    let missing = || format!("backend {} is not configured", kind.name());
    Ok(match kind {
        BackendKind::ClaudeCode => {
            let settings = config.backends.claude_code.clone();
            Box::new(claude_code::ClaudeCode(settings.with_context(missing)?))
        }
        BackendKind::Codex => {
            let settings = config.backends.codex.clone();
            Box::new(codex::Codex(settings.with_context(missing)?))
        }
        BackendKind::Local => {
            let settings = config.backends.local.clone();
            Box::new(local::Local(settings.with_context(missing)?))
        }
    })
}

pub fn expand_prompt(template: &str, incident: &Incident) -> String {
    template
        .replace("{{incident_dir}}", &incident.dir.display().to_string())
        .replace("{{watch}}", &incident.watch)
        .replace("{{os}}", std::env::consts::OS)
        .replace("{{since}}", &format_time(incident.since))
}

struct Attempt {
    kind: BackendKind,
    elapsed: Duration,
    error: Option<String>,
}

fn attempt_order(diagnose: &Diagnose, override_kind: Option<BackendKind>) -> Vec<BackendKind> {
    match override_kind {
        Some(kind) => vec![kind],
        None => std::iter::once(diagnose.backend)
            .chain(diagnose.fallback)
            .collect(),
    }
}

fn run_backend(config: &Config, kind: BackendKind, request: &Request) -> Result<String> {
    let backend = backend(config, kind)?;
    if let Err(reason) = backend.available() {
        bail!("not available: {reason}");
    }
    backend.run(request)
}

fn render_report(incident: &Incident, attempts: &[Attempt], body: &str) -> String {
    let mut text = format!("# 調査レポート: {}\n\n", incident.watch);
    let _ = writeln!(text, "- 事件: {}", incident.dir.display());
    let _ = writeln!(text, "- 発生開始: {}", format_time(incident.since));
    for attempt in attempts {
        let elapsed = attempt.elapsed.as_secs_f64();
        let outcome = match &attempt.error {
            None => "成功".to_string(),
            Some(error) => format!("失敗: {error}"),
        };
        let name = attempt.kind.name();
        let _ = writeln!(text, "- バックエンド {name}: {outcome}（{elapsed:.1} 秒）");
    }
    let _ = writeln!(text, "\n{body}");
    text
}

/// 調査を実行してレポートを保存し、そのパスを返す。全バックエンドが失敗しても
/// 失敗の記録をレポートとして残したうえでエラーを返す
pub fn investigate(
    config: &Config,
    paths: &Paths,
    diagnose: &Diagnose,
    incident: &Incident,
    override_kind: Option<BackendKind>,
) -> Result<PathBuf> {
    let prompt_path = paths.config_dir.join(&diagnose.prompt_file);
    let template = std::fs::read_to_string(&prompt_path)
        .with_context(|| format!("failed to read {}", prompt_path.display()))?;
    let prompt = expand_prompt(&template, incident);
    let request = Request {
        prompt: &prompt,
        incident_dir: &incident.dir,
        allowed_commands: &diagnose.allowed_commands,
        timeout: diagnose.max_duration,
    };

    let mut attempts = Vec::new();
    let mut body = None;
    for kind in attempt_order(diagnose, override_kind) {
        log::info!("investigating {} with {}", incident.id, kind.name());
        let started = Instant::now();
        let result = run_backend(config, kind, &request);
        let elapsed = started.elapsed();
        match result {
            Ok(text) => {
                attempts.push(Attempt {
                    kind,
                    elapsed,
                    error: None,
                });
                body = Some(text);
                break;
            }
            Err(error) => {
                log::warn!("backend {} failed: {error:#}", kind.name());
                attempts.push(Attempt {
                    kind,
                    elapsed,
                    error: Some(format!("{error:#}")),
                });
            }
        }
    }

    let dir = paths.reports_dir.join(&incident.watch);
    create_private_dir(&dir)?;
    let path = dir.join(format!("{}.md", incident.id));
    let succeeded = body.is_some();
    let body = body.unwrap_or_else(|| "すべてのバックエンドが失敗しました。".to_string());
    std::fs::write(&path, render_report(incident, &attempts, &body))
        .with_context(|| format!("failed to write {}", path.display()))?;
    if !succeeded {
        bail!("all backends failed; see {}", path.display());
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn incident() -> Incident {
        Incident {
            watch: "w".to_string(),
            id: "20261106-120000".to_string(),
            created: 1000,
            since: 900,
            dir: PathBuf::from("incidents-dir"),
        }
    }

    #[test]
    fn expands_placeholders() {
        let prompt = expand_prompt("{{incident_dir}} {{watch}} {{os}} {{unknown}}", &incident());
        assert_eq!(
            prompt,
            format!("incidents-dir w {} {{{{unknown}}}}", std::env::consts::OS)
        );
    }

    fn diagnose(fallback: Option<BackendKind>) -> Diagnose {
        Diagnose {
            backend: BackendKind::ClaudeCode,
            fallback,
            prompt_file: "p.md".to_string(),
            allowed_commands: Vec::new(),
            max_duration: Duration::from_secs(1),
        }
    }

    #[test]
    fn override_replaces_backend_and_fallback() {
        let diagnose = diagnose(Some(BackendKind::Local));
        assert_eq!(
            attempt_order(&diagnose, None),
            [BackendKind::ClaudeCode, BackendKind::Local]
        );
        assert_eq!(
            attempt_order(&diagnose, Some(BackendKind::Codex)),
            [BackendKind::Codex]
        );
    }

    #[test]
    fn report_records_backend_outcomes_and_duration() {
        let attempts = [
            Attempt {
                kind: BackendKind::ClaudeCode,
                elapsed: Duration::from_millis(1500),
                error: Some("not available".to_string()),
            },
            Attempt {
                kind: BackendKind::Local,
                elapsed: Duration::from_secs(2),
                error: None,
            },
        ];
        let report = render_report(&incident(), &attempts, "## 症状\nbody");
        assert!(report.contains("claude_code: 失敗: not available（1.5 秒）"));
        assert!(report.contains("local: 成功（2.0 秒）"));
        assert!(report.contains("## 症状"));
    }
}
