//! traceroute / tracert による経路の取得。

use crate::process;
use anyhow::{Result, bail};
use serde_json::{Value, json};
use std::net::IpAddr;
use std::time::Duration;

const MAX_HOPS: &str = "15";
/// check 全体がスケジューラの制限（2 分）に収まるよう、経路が途中で切れていても打ち切る
const TIMEOUT: Duration = Duration::from_secs(40);

pub fn collect(target: &str) -> Result<Value> {
    let (program, args): (&str, Vec<&str>) = if cfg!(windows) {
        ("tracert", vec!["-d", "-h", MAX_HOPS, "-w", "500", target])
    } else {
        (
            "traceroute",
            vec!["-n", "-m", MAX_HOPS, "-w", "1", "-q", "1", target],
        )
    };
    let Some(path) = process::find_program(program) else {
        bail!("{program} is not installed");
    };
    let mut command = process::command(path);
    command.args(args);
    let output = process::run(command, None, TIMEOUT)?;
    let hops = parse_hops(&output.stdout);
    if hops.is_empty() {
        bail!(
            "{program} produced no hops (exit {:?}): {}",
            output.code,
            output.stderr.trim()
        );
    }
    // raw は RTT で毎回変わるので、差分の対象にはしない（incident の diff が除外する）
    Ok(json!({
        "target": target,
        "hops": hops,
        "truncated": output.timed_out,
        "raw": output.stdout,
    }))
}

/// 各ホップの IP を順に返す。応答の無いホップは None。
/// 文言はロケールで変わるので、行頭のホップ番号と IP 形式のトークンだけを見る
fn parse_hops(text: &str) -> Vec<Option<String>> {
    text.lines()
        .filter(|line| {
            line.split_whitespace()
                .next()
                .is_some_and(|first| first.parse::<u32>().is_ok())
        })
        .map(|line| {
            line.split_whitespace()
                .skip(1)
                .map(|token| token.trim_matches(['[', ']', '(', ')']))
                .find(|token| token.parse::<IpAddr>().is_ok())
                .map(str::to_string)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tracert_output() {
        let text = "\r\nTracing route to 1.1.1.1 over a maximum of 15 hops\r\n\r\n  \
            1    <1 ms    <1 ms    <1 ms  192.168.1.1\r\n  \
            2     *        *        *     Request timed out.\r\n  \
            3    12 ms    11 ms    12 ms  1.1.1.1\r\n\r\nTrace complete.\r\n";
        assert_eq!(
            parse_hops(text),
            [
                Some("192.168.1.1".to_string()),
                None,
                Some("1.1.1.1".to_string())
            ]
        );
    }

    #[test]
    fn parses_traceroute_output() {
        let text = "traceroute to 1.1.1.1 (1.1.1.1), 15 hops max, 60 byte packets\n \
            1  192.168.1.1  0.512 ms\n 2  *\n 3  2001:db8::1  9.1 ms\n";
        assert_eq!(
            parse_hops(text),
            [
                Some("192.168.1.1".to_string()),
                None,
                Some("2001:db8::1".to_string())
            ]
        );
    }

    #[test]
    fn locale_specific_text_is_ignored() {
        let text = "1.1.1.1 へのルートをトレースしています\n  1     *     *     *     要求がタイムアウトしました。\n";
        assert_eq!(parse_hops(text), [None]);
    }
}
