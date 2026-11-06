//! 調査プロセスを親から切り離して起動する。
//!
//! スケジューラはタスクの終了時に残ったプロセスも止めるので、そのまま子として
//! 起動すると調査が途中で消える。

use anyhow::{Context, Result};
use std::path::Path;
use std::process::{Command, Stdio};

fn diagnose_command(program: &Path, watch: &str, incident_dir: &Path) -> Vec<String> {
    vec![
        program.display().to_string(),
        "diagnose".to_string(),
        "--watch".to_string(),
        watch.to_string(),
        "--incident".to_string(),
        incident_dir.display().to_string(),
    ]
}

pub fn spawn_diagnose(watch: &str, incident_dir: &Path) -> Result<()> {
    let program = std::env::current_exe().context("failed to locate the kuda binary")?;
    spawn(watch, &diagnose_command(&program, watch, incident_dir))
}

fn base_command(argv: &[String]) -> Command {
    let mut command = Command::new(&argv[0]);
    command
        .args(&argv[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

#[cfg(windows)]
fn spawn(_watch: &str, argv: &[String]) -> Result<()> {
    use std::os::windows::process::CommandExt;

    const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const ERROR_ACCESS_DENIED: i32 = 5;

    let flags = DETACHED_PROCESS | CREATE_NO_WINDOW;
    let result = base_command(argv)
        .creation_flags(flags | CREATE_BREAKAWAY_FROM_JOB)
        .spawn();
    match result {
        Ok(_) => Ok(()),
        // ジョブが離脱を許可していないと失敗する。切り離せなくても調査は試みる
        Err(error) if error.raw_os_error() == Some(ERROR_ACCESS_DENIED) => {
            log::warn!("job does not allow breakaway; diagnose may end with the task");
            base_command(argv)
                .creation_flags(flags)
                .spawn()
                .map(drop)
                .context("failed to start diagnose")
        }
        Err(error) => Err(error).context("failed to start diagnose"),
    }
}

#[cfg(unix)]
fn spawn(watch: &str, argv: &[String]) -> Result<()> {
    use crate::process;
    use std::os::unix::process::CommandExt;
    use std::time::Duration;

    // ユーザーの systemd が動いていれば別ユニットにする。cgroup ごと止められずに済み、
    // 同名ユニットが動いていれば起動に失敗するので多重起動防止にもなる
    if std::env::var_os("XDG_RUNTIME_DIR").is_some()
        && let Some(systemd_run) = process::find_program("systemd-run")
    {
        let mut command = process::command(systemd_run);
        command.args(systemd_run_args(watch, |key| std::env::var(key).ok()));
        command.args(argv);
        match process::run(command, None, Duration::from_secs(10)) {
            Ok(output) if output.success() => return Ok(()),
            Ok(output) if output.stderr.contains("already") => {
                log::info!("diagnose for {watch} is already running");
                return Ok(());
            }
            Ok(output) => log::warn!("systemd-run failed: {}", output.stderr.trim()),
            Err(error) => log::warn!("systemd-run failed: {error:#}"),
        }
    }

    // cron など systemd の外から起動された場合は、セッションから切り離すだけにする
    base_command(argv)
        .process_group(0)
        .spawn()
        .map(drop)
        .context("failed to start diagnose")
}

/// 別ユニットはサービスマネージャの環境で動くので、解決に使う変数を引き継ぐ
#[cfg(any(unix, test))]
fn systemd_run_args(watch: &str, env: impl Fn(&str) -> Option<String>) -> Vec<String> {
    let mut args = vec![
        "--user".to_string(),
        "--collect".to_string(),
        "--quiet".to_string(),
        format!("--unit=kuda-diagnose-{watch}"),
    ];
    for key in [
        "PATH",
        "KUDA_HOME",
        "XDG_CONFIG_HOME",
        "XDG_STATE_HOME",
        "XDG_DATA_HOME",
    ] {
        if let Some(value) = env(key) {
            args.push(format!("--setenv={key}={value}"));
        }
    }
    args
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_diagnose_arguments() {
        let argv = diagnose_command(Path::new("kuda"), "w", Path::new("incident"));
        assert_eq!(
            argv,
            ["kuda", "diagnose", "--watch", "w", "--incident", "incident"]
        );
    }

    #[test]
    fn systemd_unit_is_named_after_the_watch_and_keeps_env() {
        let args = systemd_run_args("w", |key| (key == "PATH").then(|| "/bin".to_string()));
        assert!(args.contains(&"--unit=kuda-diagnose-w".to_string()));
        assert!(args.contains(&"--setenv=PATH=/bin".to_string()));
        assert!(!args.iter().any(|arg| arg.contains("KUDA_HOME")));
    }
}
