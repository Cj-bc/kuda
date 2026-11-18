use super::Sample;
use crate::exec;
use std::time::{Duration, Instant};

/// 終了コード 0 を成功とする。標準出力の最終行が数値なら `value` 指標になる
pub fn check(program: &str, args: &[String], timeout: Duration) -> Result<Sample, String> {
    let mut command = exec::command(program);
    command.args(args);
    let started = Instant::now();
    let output = exec::run(command, None, timeout).map_err(|e| format!("{e:#}"))?;
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

    fn run(script: &str) -> Result<Sample, String> {
        let (program, args): (&str, &[&str]) = if cfg!(windows) {
            ("powershell", &["-NoProfile", "-Command", script])
        } else {
            ("sh", &["-c", script])
        };
        let args: Vec<String> = args.iter().map(|arg| arg.to_string()).collect();
        check(program, &args, TIMEOUT)
    }

    #[test]
    fn reads_numeric_stdout_as_value() {
        let sample = run("echo 42.5").unwrap();
        assert_eq!(sample.value, Some(42.5));
    }

    #[test]
    fn non_zero_exit_is_a_failure() {
        assert!(run("exit 2").is_err());
    }

    #[test]
    fn parses_only_a_numeric_last_line() {
        assert_eq!(parse_value("log line\n12\n\n"), Some(12.0));
        assert_eq!(parse_value("12\nnot a number\n"), None);
        assert_eq!(parse_value("NaN\n"), None);
        assert_eq!(parse_value(""), None);
    }
}
