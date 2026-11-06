use super::Sample;
use crate::process;
use std::time::{Duration, Instant};

/// 終了コード 0 を成功とする。標準出力の最終行が数値なら `value` 指標になる
pub fn check(argv: &[String], timeout: Duration) -> Result<Sample, String> {
    let mut command = process::command(&argv[0]);
    command.args(&argv[1..]);
    let started = Instant::now();
    let output = process::run(command, None, timeout).map_err(|e| format!("{e:#}"))?;
    let rtt_ms = started.elapsed().as_secs_f64() * 1000.0;

    if output.timed_out {
        return Err(format!("timed out after {timeout:?}"));
    }
    if !output.success() {
        return Err(format!(
            "exit code {:?}: {}",
            output.code,
            output.stderr.trim()
        ));
    }
    Ok(Sample {
        rtt_ms: Some(rtt_ms),
        value: parse_value(&output.stdout),
    })
}

fn parse_value(stdout: &str) -> Option<f64> {
    stdout
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())?
        .trim()
        .parse()
        .ok()
        .filter(|value: &f64| value.is_finite())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TIMEOUT: Duration = Duration::from_secs(30);

    fn shell(script: &str) -> Vec<String> {
        let argv: &[&str] = if cfg!(windows) {
            &["powershell", "-NoProfile", "-Command", script]
        } else {
            &["sh", "-c", script]
        };
        argv.iter().map(|arg| arg.to_string()).collect()
    }

    #[test]
    fn reads_numeric_stdout_as_value() {
        let sample = check(&shell("echo 42.5"), TIMEOUT).unwrap();
        assert_eq!(sample.value, Some(42.5));
    }

    #[test]
    fn non_zero_exit_is_a_failure() {
        assert!(check(&shell("exit 2"), TIMEOUT).is_err());
    }

    #[test]
    fn parses_only_a_numeric_last_line() {
        assert_eq!(parse_value("log line\n12\n\n"), Some(12.0));
        assert_eq!(parse_value("12\nnot a number\n"), None);
        assert_eq!(parse_value("NaN\n"), None);
        assert_eq!(parse_value(""), None);
    }
}
