//! 調査の進み具合をデスクトップ通知で知らせる。
//!
//! 通知は補助的なものなので、出せなくても調査は止めずにログに残すだけにする。
//! Windows は PowerShell 5.1 から WinRT のトーストを、Linux は `notify-send` を使う。

use crate::exec;
use anyhow::{Result, bail};
use std::path::Path;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(15);

pub enum Event<'a> {
    Started {
        watch: &'a str,
    },
    Finished {
        watch: &'a str,
        report: &'a Path,
    },
    /// 失敗の記録をレポートに残せていれば `report` に入る
    Failed {
        watch: &'a str,
        report: Option<&'a Path>,
    },
}

impl Event<'_> {
    fn title(&self) -> String {
        match self {
            Self::Started { watch } => format!("Kuda: {watch} で異常を検知"),
            Self::Finished { watch, .. } => format!("Kuda: {watch} の調査が完了"),
            Self::Failed { watch, .. } => format!("Kuda: {watch} の調査に失敗"),
        }
    }

    fn body(&self) -> String {
        match self {
            Self::Started { .. } => "LLM による調査を始めました".to_string(),
            Self::Finished { report, .. } => format!("レポート: {}", report.display()),
            Self::Failed {
                report: Some(report),
                ..
            } => format!("失敗の記録: {}", report.display()),
            Self::Failed { report: None, .. } => "詳細はログを確認してください".to_string(),
        }
    }

    /// 通知を押したときに開くファイル
    #[cfg(any(windows, test))]
    fn target(&self) -> Option<&Path> {
        match self {
            Self::Started { .. } => None,
            Self::Finished { report, .. } => Some(report),
            Self::Failed { report, .. } => *report,
        }
    }
}

pub fn send(event: &Event) {
    match show(event) {
        Ok(()) => log::debug!("notified: {}", event.title()),
        Err(error) => log::warn!("failed to notify: {error:#}"),
    }
}

fn check(output: exec::Output) -> Result<()> {
    if output.timed_out {
        bail!("timed out");
    }
    if !output.success() {
        bail!("exited with {:?}: {}", output.code, output.stderr.trim());
    }
    Ok(())
}

/// PowerShell 7 には WinRT の型が無いので、Windows 付属の 5.1 を使う
#[cfg(windows)]
const TOAST_SCRIPT: &str = "\
$ErrorActionPreference = 'Stop'; \
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null; \
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] > $null; \
$xml = New-Object Windows.Data.Xml.Dom.XmlDocument; \
$xml.LoadXml($env:KUDA_TOAST_XML); \
$toast = New-Object Windows.UI.Notifications.ToastNotification $xml; \
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($env:KUDA_TOAST_APP_ID).Show($toast)";

/// 未登録のアプリはトーストを出せないので、PowerShell の AppUserModelID を借りる
#[cfg(windows)]
const POWERSHELL_APP_ID: &str =
    r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe";

#[cfg(windows)]
fn show(event: &Event) -> Result<()> {
    let mut command = exec::command("powershell.exe");
    command
        .args(["-NoProfile", "-NonInteractive", "-Command", TOAST_SCRIPT])
        .env("KUDA_TOAST_XML", toast_xml(event))
        .env("KUDA_TOAST_APP_ID", POWERSHELL_APP_ID);
    check(exec::run(command, None, TIMEOUT)?)
}

#[cfg(unix)]
fn show(event: &Event) -> Result<()> {
    let Some(program) = exec::find_program("notify-send") else {
        bail!("notify-send is not installed");
    };
    let urgency = match event {
        Event::Failed { .. } => "critical",
        _ => "normal",
    };
    let mut command = exec::command(program);
    command
        .args(["--app-name=kuda", &format!("--urgency={urgency}")])
        .arg(event.title())
        .arg(event.body());
    check(exec::run(command, None, TIMEOUT)?)
}

#[cfg(any(windows, test))]
fn toast_xml(event: &Event) -> String {
    let launch = event
        .target()
        .map(|path| {
            let uri = escape_xml(&file_uri(path));
            format!(r#" activationType="protocol" launch="{uri}""#)
        })
        .unwrap_or_default();
    format!(
        r#"<toast{launch}><visual><binding template="ToastGeneric"><text>{}</text><text>{}</text></binding></visual></toast>"#,
        escape_xml(&event.title()),
        escape_xml(&event.body()),
    )
}

#[cfg(any(windows, test))]
fn escape_xml(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// 絶対パスを file URI にする。区切りを `/` に揃え、記号と非 ASCII は % で表す
#[cfg(any(windows, test))]
fn file_uri(path: &Path) -> String {
    let text = path.display().to_string().replace('\\', "/");
    let mut uri = String::from("file://");
    if !text.starts_with('/') {
        uri.push('/');
    }
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' | b':' => {
                uri.push(byte as char)
            }
            _ => uri.push_str(&format!("%{byte:02X}")),
        }
    }
    uri
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_uri_handles_windows_and_unix_paths() {
        assert_eq!(
            file_uri(Path::new(r"C:\Users\a b\reports\w\1.md")),
            "file:///C:/Users/a%20b/reports/w/1.md"
        );
        assert_eq!(
            file_uri(Path::new("/home/a/調査.md")),
            "file:///home/a/%E8%AA%BF%E6%9F%BB.md"
        );
    }

    #[test]
    fn toast_opens_the_report_and_escapes_text() {
        let report = Path::new("/r/w&1.md");
        let xml = toast_xml(&Event::Finished {
            watch: "<w>",
            report,
        });
        assert!(xml.contains(r#"launch="file:///r/w%261.md""#));
        assert!(xml.contains("Kuda: &lt;w&gt; の調査が完了"));
        assert!(xml.contains("レポート: /r/w&amp;1.md"));
    }

    #[test]
    fn started_toast_has_no_launch_target() {
        let xml = toast_xml(&Event::Started { watch: "w" });
        assert!(!xml.contains("launch="));
    }
}
