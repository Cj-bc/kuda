use super::{Backend, Request};
use crate::config::ClaudeCodeBackend;
use crate::process;
use anyhow::{Context, Result, bail};
use serde_json::Value;

pub struct ClaudeCode(pub ClaudeCodeBackend);

/// allowed_commands を許可ルールへ変換する。Windows では Claude Code のシェルが
/// Git Bash になるので、PowerShell コマンドレットは powershell 経由の形にする
fn allow_rule(command: &str, windows: bool) -> String {
    let is_cmdlet = command.contains('-') && command.starts_with(char::is_uppercase);
    if windows && is_cmdlet {
        format!("Bash(powershell -NoProfile -Command {command}:*)")
    } else {
        format!("Bash({command}:*)")
    }
}

/// ツールの境界をここで固定する。
/// - 使えるのは Read と Bash だけで、MCP サーバーも読み込まない
/// - Read は作業ディレクトリ（事件ディレクトリ）の中に限る
/// - ユーザー設定の allow ルールとフックを持ち込まない
/// - 許可されていない操作は確認せず拒否する
///
/// `--bare` は OAuth のログインを読まなくなるので使わない
fn args(max_turns: u32, allowed_commands: &[String], windows: bool) -> Vec<String> {
    let mut args: Vec<String> = [
        "-p",
        "--output-format",
        "json",
        "--strict-mcp-config",
        "--setting-sources",
        "project",
        "--permission-mode",
        "dontAsk",
        "--max-turns",
    ]
    .map(str::to_string)
    .to_vec();
    args.push(max_turns.to_string());
    args.extend(["--tools".to_string(), "Read".to_string()]);
    if !allowed_commands.is_empty() {
        args.push("Bash".to_string());
    }
    args.extend(["--allowedTools".to_string(), "Read(./**)".to_string()]);
    args.extend(allowed_commands.iter().map(|c| allow_rule(c, windows)));
    args
}

/// `--output-format json` の出力から本文を取り出す。
/// バージョンによって単一の結果オブジェクトかイベントの配列かが異なる
fn parse_output(stdout: &str) -> Result<String> {
    let parsed: Value = serde_json::from_str(stdout.trim()).context("output is not JSON")?;
    let result = match &parsed {
        Value::Array(events) => events.iter().rev().find(|e| e["type"] == "result"),
        other => Some(other),
    }
    .context("output has no result event")?;

    let text = result["result"].as_str().unwrap_or_default();
    if result["is_error"] == Value::Bool(true) {
        let subtype = result["subtype"].as_str().unwrap_or("unknown");
        bail!("claude reported an error ({subtype}): {text}");
    }
    if text.is_empty() {
        bail!("claude returned an empty result");
    }
    Ok(text.to_string())
}

impl Backend for ClaudeCode {
    fn available(&self) -> Result<String, String> {
        process::find_program(&self.0.command)
            .map(|path| path.display().to_string())
            .ok_or_else(|| format!("command not found: {}", self.0.command))
    }

    fn run(&self, request: &Request) -> Result<String> {
        let program = process::find_program(&self.0.command)
            .with_context(|| format!("command not found: {}", self.0.command))?;
        let mut command = process::command(program);
        command
            .args(args(
                self.0.max_turns,
                request.allowed_commands,
                cfg!(windows),
            ))
            .current_dir(request.incident_dir);
        // プロンプトは複数行なので、.cmd ラッパーでも壊れないよう標準入力で渡す
        let output = process::run(command, Some(request.prompt), request.timeout)?;
        if output.timed_out {
            bail!("timed out after {:?}", request.timeout);
        }
        if !output.success() {
            // 認証エラーなどは stdout の JSON に入っていることが多い
            let detail = parse_output(&output.stdout)
                .err()
                .map_or_else(|| output.stderr.clone(), |e| e.to_string());
            bail!("exit code {:?}: {}", output.code, detail.trim());
        }
        parse_output(&output.stdout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn converts_allowed_commands_to_rules() {
        assert_eq!(allow_rule("tracert", true), "Bash(tracert:*)");
        assert_eq!(
            allow_rule("Test-NetConnection", true),
            "Bash(powershell -NoProfile -Command Test-NetConnection:*)"
        );
        assert_eq!(
            allow_rule("Test-NetConnection", false),
            "Bash(Test-NetConnection:*)"
        );
    }

    #[test]
    fn locks_down_tools_and_settings() {
        let args = args(20, &strings(&["ping"]), false);
        let joined = args.join(" ");
        assert!(joined.contains("--tools Read Bash --allowedTools Read(./**) Bash(ping:*)"));
        assert!(joined.contains("--max-turns 20"));
        assert!(joined.contains("--permission-mode dontAsk"));
        assert!(joined.contains("--strict-mcp-config"));
        assert!(joined.contains("--setting-sources project"));
    }

    #[test]
    fn no_allowed_commands_means_no_bash() {
        let args = args(20, &[], false);
        assert!(!args.iter().any(|arg| arg.starts_with("Bash")));
    }

    #[test]
    fn reads_result_from_event_array() {
        let stdout = r###"[{"type":"system","subtype":"init"},
            {"type":"user","is_error":true},
            {"type":"result","subtype":"success","is_error":false,"result":"## 症状"}]"###;
        assert_eq!(parse_output(stdout).unwrap(), "## 症状");
    }

    #[test]
    fn reads_result_from_single_object() {
        let stdout = r#"{"type":"result","subtype":"success","is_error":false,"result":"ok"}"#;
        assert_eq!(parse_output(stdout).unwrap(), "ok");
    }

    #[test]
    fn surfaces_errors_from_the_result() {
        let stdout = r#"{"type":"result","subtype":"error_max_turns","is_error":true,"result":""}"#;
        let error = parse_output(stdout).unwrap_err().to_string();
        assert!(error.contains("error_max_turns"));
    }

    #[test]
    fn rejects_malformed_output() {
        assert!(parse_output("not json").is_err());
        assert!(parse_output(r#"[{"type":"system"}]"#).is_err());
        assert!(parse_output(r#"{"type":"result","is_error":false,"result":""}"#).is_err());
    }
}
