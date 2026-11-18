use super::{Backend, Request};
use crate::config::ClaudeCodeBackend;
use crate::exec;
use crate::os::Os;
use anyhow::{Context, Result, bail};
use serde_json::Value;

pub struct ClaudeCode(pub ClaudeCodeBackend);

/// allowed_commands を許可ルールへ変換する。Windows では Claude Code のシェルが
/// Git Bash になるので、PowerShell コマンドレットは powershell 経由の形にする
fn allow_rule(command: &str, os: Os) -> String {
    let is_cmdlet = command.contains('-') && command.starts_with(char::is_uppercase);
    if os == Os::Windows && is_cmdlet {
        format!("Bash(powershell -NoProfile -Command {command}:*)")
    } else {
        format!("Bash({command}:*)")
    }
}

/// ツールの境界をここで固定する。
/// - 使えるのは Read と Bash だけで、MCP サーバーも読み込まない
/// - Read は作業ディレクトリ（事件ディレクトリ）の中に限る
/// - 設定は user / project / local のどれも読まない。事件ディレクトリは第三者から
///   受け取ることもあり、そこの `.claude/settings.json` のフックや allow ルールを
///   読むと、ここで渡すルールの外でコマンドが動きうる。CLAUDE.md も読まれなくなるが、
///   事件ディレクトリの中身は指示ではなく調べる材料なので、それでよい
/// - 許可されていない操作は確認せず拒否する
///
/// `--setting-sources ""` が何も読まない意味になることは CLI に明記されていないので、
/// 設定ファイルを無視する `--restricted` も付ける。これを知らない古い CLI は
/// 未知のオプションとして起動に失敗するので、設定を読んだまま動くことはない。
/// `--restricted` はほかに、ファイル系ツールを作業ディレクトリに閉じ込め、`--tools` に
/// 無いコード実行ツールを外すが、どちらも上の方針（`Read(./**)` と Read・Bash だけ）と一致する。
/// `--bare` は OAuth のログインを読まなくなるので使わない
fn args(max_turns: u32, allowed_commands: &[String], os: Os) -> Vec<String> {
    let mut args: Vec<String> = [
        "-p",
        "--output-format",
        "json",
        "--strict-mcp-config",
        "--restricted",
        "--setting-sources",
        "",
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
    args.extend(allowed_commands.iter().map(|c| allow_rule(c, os)));
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

/// 失敗したときの理由を組み立てる。認証エラーなどは stdout の JSON に入っていることが
/// 多く、未知のオプションで起動できなかったときなどは stdout が空で stderr にだけ出る
fn failure_detail(stdout: &str, stderr: &str) -> String {
    let from_stdout = serde_json::from_str::<Value>(stdout.trim())
        .ok()
        .and_then(|_| parse_output(stdout).err())
        .map(|e| e.to_string());
    let stderr = stderr.trim();
    let parts: Vec<String> = from_stdout
        .into_iter()
        .chain((!stderr.is_empty()).then(|| stderr.to_string()))
        .collect();
    if parts.is_empty() {
        // どちらにも手がかりが無ければ、stdout を読めなかった理由だけでも返す
        return parse_output(stdout)
            .err()
            .map_or_else(String::new, |e| e.to_string());
    }
    parts.join("; ")
}

impl Backend for ClaudeCode {
    fn available(&self) -> Result<String, String> {
        exec::find_program(&self.0.command)
            .map(|path| path.display().to_string())
            .ok_or_else(|| format!("command not found: {}", self.0.command))
    }

    fn run(&self, request: &Request) -> Result<String> {
        let program = exec::find_program(&self.0.command)
            .with_context(|| format!("command not found: {}", self.0.command))?;
        let mut command = exec::command(program);
        command
            .args(args(
                self.0.max_turns,
                request.allowed_commands,
                Os::current(),
            ))
            .current_dir(request.incident_dir);
        // プロンプトは複数行なので、.cmd ラッパーでも壊れないよう標準入力で渡す
        let output = exec::run(command, Some(request.prompt), request.timeout)?;
        if output.timed_out {
            bail!("timed out after {:?}", request.timeout);
        }
        if !output.success() {
            let detail = failure_detail(&output.stdout, &output.stderr);
            bail!("exit code {:?}: {detail}", output.code);
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
        assert_eq!(allow_rule("tracert", Os::Windows), "Bash(tracert:*)");
        assert_eq!(
            allow_rule("Test-NetConnection", Os::Windows),
            "Bash(powershell -NoProfile -Command Test-NetConnection:*)"
        );
        assert_eq!(
            allow_rule("Test-NetConnection", Os::Linux),
            "Bash(Test-NetConnection:*)"
        );
    }

    #[test]
    fn locks_down_tools() {
        let args = args(20, &strings(&["ping"]), Os::Linux);
        let joined = args.join(" ");
        assert!(joined.contains("--tools Read Bash --allowedTools Read(./**) Bash(ping:*)"));
        assert!(joined.contains("--max-turns 20"));
        assert!(joined.contains("--permission-mode dontAsk"));
        assert!(joined.contains("--strict-mcp-config"));
    }

    #[test]
    fn loads_no_setting_sources() {
        let args = args(20, &[], Os::Linux);
        let at = args.iter().position(|arg| arg == "--setting-sources");
        assert_eq!(args.get(at.unwrap() + 1).map(String::as_str), Some(""));
        assert!(args.iter().any(|arg| arg == "--restricted"));
    }

    #[test]
    fn no_allowed_commands_means_no_bash() {
        let args = args(20, &[], Os::Linux);
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
    fn failure_shows_stderr_when_stdout_is_empty() {
        let detail = failure_detail("", "error: unknown option '--restricted'\n");
        assert_eq!(detail, "error: unknown option '--restricted'");
    }

    #[test]
    fn failure_prefers_the_error_in_stdout() {
        let stdout = r#"{"type":"result","subtype":"error_during_execution","is_error":true,"result":"not logged in"}"#;
        let detail = failure_detail(stdout, "");
        assert!(detail.contains("error_during_execution"), "{detail}");
        assert!(detail.contains("not logged in"), "{detail}");
    }

    #[test]
    fn failure_without_any_clue_explains_the_stdout() {
        assert_eq!(failure_detail("garbage", ""), "output is not JSON");
    }

    #[test]
    fn rejects_malformed_output() {
        assert!(parse_output("not json").is_err());
        assert!(parse_output(r#"[{"type":"system"}]"#).is_err());
        assert!(parse_output(r#"{"type":"result","is_error":false,"result":""}"#).is_err());
    }
}
