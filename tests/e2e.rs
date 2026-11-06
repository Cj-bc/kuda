//! 実バイナリを KUDA_HOME の下で動かす通しの確認。LLM は偽のコマンドに置き換える。

use std::net::{Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

struct Home {
    dir: PathBuf,
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

const RESULT_JSON: &str =
    r#"[{"type":"result","subtype":"success","is_error":false,"result":"fake-report-body"}]"#;

fn write_fake_claude(dir: &Path, json: &str) -> PathBuf {
    if cfg!(windows) {
        let path = dir.join("fake-claude.cmd");
        std::fs::write(&path, format!("@echo off\r\necho {json}\r\n")).unwrap();
        path
    } else {
        let path = dir.join("fake-claude");
        std::fs::write(&path, format!("#!/bin/sh\ncat >/dev/null\necho '{json}'\n")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        path
    }
}

impl Home {
    fn new(name: &str, watch_body: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("kuda-e2e-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("prompts")).unwrap();
        std::fs::write(
            dir.join("prompts").join("p.md"),
            "investigate {{incident_dir}}",
        )
        .unwrap();
        let claude = write_fake_claude(&dir, RESULT_JSON);
        let config = format!(
            "[backends.claude_code]\ncommand = '{}'\n\n{watch_body}",
            claude.display()
        );
        std::fs::write(dir.join("config.toml"), config).unwrap();
        Self { dir }
    }

    fn kuda(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_kuda"))
            .args(args)
            .env("KUDA_HOME", &self.dir)
            .output()
            .unwrap()
    }

    fn files_under(&self, subdir: &str) -> Vec<PathBuf> {
        let mut found = Vec::new();
        let mut pending = vec![self.dir.join(subdir)];
        while let Some(dir) = pending.pop() {
            for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    pending.push(path);
                } else {
                    found.push(path);
                }
            }
        }
        found
    }

    fn wait_for_report(&self) -> Option<PathBuf> {
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            let report = self
                .files_under("reports")
                .into_iter()
                .find(|path| !path.to_string_lossy().contains("recovered"));
            if let Some(report) = report {
                // 書き込みの途中を読まないよう、本文が揃うまで待つ
                if std::fs::read_to_string(&report).is_ok_and(|text| !text.is_empty()) {
                    return Some(report);
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        None
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        stdout(output),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn closed_port() -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    listener.local_addr().unwrap().port()
}

fn failing_watch(port: u16, consecutive: u32) -> String {
    format!(
        r#"
[[watch]]
name = "test-unreachable"
interval = "5m"
  [watch.probe]
  kind = "tcp"
  targets = ["127.0.0.1:{port}"]
  timeout = "2s"
  [watch.trigger]
  when = "loss >= 0.5"
  consecutive = {consecutive}
  cooldown = "10m"
  recover_notify = true
  [watch.diagnose]
  backend = "claude_code"
  prompt_file = "prompts/p.md"
  allowed_commands = ["ping"]
"#
    )
}

#[test]
fn trigger_fires_on_the_second_run_and_produces_a_report() {
    let home = Home::new("fire", &failing_watch(closed_port(), 2));

    assert_success(&home.kuda(&["check"]));
    assert!(home.files_under("incidents").is_empty());

    assert_success(&home.kuda(&["check", "--force"]));
    let incident_files = home.files_under("incidents");
    for name in ["summary.md", "diff.md", "current.json", "metrics.csv"] {
        assert!(
            incident_files.iter().any(|path| path.ends_with(name)),
            "{name} missing from {incident_files:?}"
        );
    }

    let report = home.wait_for_report().expect("no report was written");
    let text = std::fs::read_to_string(&report).unwrap();
    assert!(text.contains("fake-report-body"), "{text}");
    assert!(text.contains("claude_code: 成功"), "{text}");
    assert!(report.starts_with(home.dir.join("reports").join("test-unreachable")));
}

#[test]
fn cooldown_prevents_a_second_incident() {
    let home = Home::new("cooldown", &failing_watch(closed_port(), 1));
    assert_success(&home.kuda(&["check", "--force"]));
    home.wait_for_report().expect("no report was written");
    assert_success(&home.kuda(&["check", "--force"]));
    let summaries = home
        .files_under("incidents")
        .into_iter()
        .filter(|path| path.ends_with("summary.md"))
        .count();
    assert_eq!(summaries, 1);
}

#[test]
fn interval_skips_a_watch_unless_forced() {
    let home = Home::new("interval", &failing_watch(closed_port(), 5));
    assert_success(&home.kuda(&["check"]));
    assert_success(&home.kuda(&["check"]));
    let status = stdout(&home.kuda(&["status"]));
    assert!(status.contains("samples: 1"), "{status}");
    assert!(status.contains("streak 1/5"), "{status}");

    // 同じ秒に実行すると ts が重なるので秒をまたがせる
    std::thread::sleep(Duration::from_millis(1100));
    assert_success(&home.kuda(&["check", "--force"]));
    let status = stdout(&home.kuda(&["status"]));
    assert!(status.contains("samples: 2"), "{status}");
    assert!(status.contains("FAILED"), "{status}");
}

#[test]
fn recovery_is_reported_after_the_target_returns() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let home = Home::new("recover", &failing_watch(port, 1));
    assert_success(&home.kuda(&["check", "--force"]));
    home.wait_for_report().expect("no report was written");

    let _listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
    assert_success(&home.kuda(&["check", "--force"]));
    let recovered = home
        .files_under("reports")
        .into_iter()
        .find(|path| path.to_string_lossy().contains("recovered"));
    assert!(recovered.is_some());
    let status = stdout(&home.kuda(&["status"]));
    assert!(status.contains("streak 0/1, idle"), "{status}");
}

#[test]
fn dry_run_builds_an_incident_without_calling_the_llm() {
    let home = Home::new("dry", &failing_watch(closed_port(), 2));
    let output = home.kuda(&["diagnose", "--watch", "test-unreachable", "--dry-run"]);
    assert_success(&output);
    assert!(stdout(&output).contains("incident:"));
    assert!(!home.files_under("incidents").is_empty());
    assert!(home.files_under("reports").is_empty());
}

#[test]
fn failed_backend_falls_back_and_records_both() {
    let port = closed_port();
    let watch = failing_watch(port, 1).replace(
        "backend = \"claude_code\"",
        "backend = \"codex\"\n  fallback = \"claude_code\"",
    );
    let home = Home::new("fallback", &watch);
    let config = home.dir.join("config.toml");
    let text = std::fs::read_to_string(&config).unwrap();
    std::fs::write(
        &config,
        format!("[backends.codex]\ncommand = 'kuda-no-such-codex'\n{text}"),
    )
    .unwrap();

    let output = home.kuda(&["diagnose", "--watch", "test-unreachable"]);
    assert_success(&output);
    let report = home.wait_for_report().expect("no report was written");
    let text = std::fs::read_to_string(report).unwrap();
    assert!(text.contains("codex: 失敗"), "{text}");
    assert!(text.contains("claude_code: 成功"), "{text}");
}

#[test]
fn check_config_reports_missing_references() {
    let home = Home::new("config", &failing_watch(closed_port(), 2));
    assert_success(&home.kuda(&["check-config"]));

    std::fs::remove_file(home.dir.join("prompts").join("p.md")).unwrap();
    let output = home.kuda(&["check-config"]);
    assert!(!output.status.success());
    assert!(stdout(&output).contains("prompt file not found"));
}

#[test]
fn invalid_config_fails_with_a_message() {
    let home = Home::new("invalid", &failing_watch(closed_port(), 2));
    std::fs::write(home.dir.join("config.toml"), "[[watch]]\nnme = 1\n").unwrap();
    let output = home.kuda(&["check"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid config"), "{stderr}");
}
