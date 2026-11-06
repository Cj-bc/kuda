//! 外部コマンドの起動。タイムアウトと、コンソール窓を出さないことをここで揃える。

use anyhow::{Context, Result};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Debug)]
pub struct Output {
    /// タイムアウトで打ち切ったときは None
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
}

impl Output {
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }
}

/// 子プロセス用の `Command` を作る。Windows では窓が一瞬出ないようフラグを付ける
pub fn command(program: impl AsRef<std::ffi::OsStr>) -> Command {
    #[allow(unused_mut)]
    let mut command = Command::new(program);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    command
}

fn capture(mut stream: impl Read + Send + 'static) -> (Arc<Mutex<Vec<u8>>>, JoinHandle<()>) {
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let shared = Arc::clone(&buffer);
    let reader = std::thread::spawn(move || {
        let mut chunk = [0; 8192];
        while let Ok(n) = stream.read(&mut chunk) {
            if n == 0 {
                break;
            }
            if let Ok(mut buffer) = shared.lock() {
                buffer.extend_from_slice(&chunk[..n]);
            }
        }
    });
    (buffer, reader)
}

fn lossy(buffer: &Mutex<Vec<u8>>) -> String {
    buffer
        .lock()
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_default()
}

/// 実行して出力を集める。時間切れなら kill し、そこまでの出力を返す
pub fn run(mut command: Command, stdin: Option<&str>, timeout: Duration) -> Result<Output> {
    command
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .with_context(|| format!("failed to start {:?}", command.get_program()))?;

    if let (Some(mut pipe), Some(text)) = (child.stdin.take(), stdin) {
        let text = text.to_string();
        // 大きな入力でパイプが詰まっても待ち続けないよう別スレッドで書く
        std::thread::spawn(move || {
            let _ = pipe.write_all(text.as_bytes());
        });
    }
    let (stdout, stdout_reader) = capture(child.stdout.take().context("stdout is not piped")?);
    let (stderr, stderr_reader) = capture(child.stderr.take().context("stderr is not piped")?);

    let deadline = Instant::now() + timeout;
    let (code, timed_out) = loop {
        if let Some(status) = child.try_wait()? {
            break (status.code(), false);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break (None, true);
        }
        std::thread::sleep(Duration::from_millis(20));
    };

    // 孫プロセスがパイプを握っていると EOF が来ないので、join で待ち切らない
    let grace = Instant::now() + Duration::from_secs(1);
    while Instant::now() < grace && !(stdout_reader.is_finished() && stderr_reader.is_finished()) {
        std::thread::sleep(Duration::from_millis(10));
    }

    Ok(Output {
        code,
        stdout: lossy(&stdout),
        stderr: lossy(&stderr),
        timed_out,
    })
}

/// PATH からプログラムを探す。パスが書かれていればその存在だけを確かめる
pub fn find_program(name: &str) -> Option<PathBuf> {
    let extensions: Vec<String> = if cfg!(windows) {
        let pathext = std::env::var("PATHEXT").unwrap_or_else(|_| ".EXE;.CMD;.BAT".to_string());
        std::iter::once(String::new())
            .chain(pathext.split(';').map(str::to_string))
            .collect()
    } else {
        vec![String::new()]
    };
    let candidates = |dir: &Path| -> Option<PathBuf> {
        extensions
            .iter()
            .map(|ext| dir.join(format!("{name}{ext}")))
            .find(|path| path.is_file())
    };

    if Path::new(name).components().count() > 1 {
        return candidates(Path::new(""));
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).find_map(|dir| candidates(&dir))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// テスト用に、シェル経由でスクリプトを走らせる Command を作る
    fn shell(script: &str) -> Command {
        if cfg!(windows) {
            let mut cmd = command("powershell");
            cmd.args(["-NoProfile", "-Command", script]);
            cmd
        } else {
            let mut cmd = command("sh");
            cmd.args(["-c", script]);
            cmd
        }
    }

    #[test]
    fn captures_stdout_and_exit_code() {
        let script = "echo hello; exit 3";
        let output = run(shell(script), None, Duration::from_secs(30)).unwrap();
        assert_eq!(output.code, Some(3));
        assert!(output.stdout.contains("hello"));
        assert!(!output.timed_out);
    }

    #[test]
    fn kills_on_timeout_and_keeps_partial_output() {
        let script = if cfg!(windows) {
            "[Console]::Out.WriteLine('partial'); [Console]::Out.Flush(); Start-Sleep 30"
        } else {
            "echo partial; sleep 30"
        };
        let started = Instant::now();
        let output = run(shell(script), None, Duration::from_secs(3)).unwrap();
        assert!(output.timed_out);
        assert_eq!(output.code, None);
        assert!(output.stdout.contains("partial"));
        assert!(started.elapsed() < Duration::from_secs(15));
    }

    #[test]
    fn passes_stdin() {
        let script = if cfg!(windows) {
            "[Console]::In.ReadToEnd()"
        } else {
            "cat"
        };
        let output = run(shell(script), Some("from-stdin"), Duration::from_secs(30)).unwrap();
        assert!(output.stdout.contains("from-stdin"));
    }

    #[test]
    fn missing_program_is_an_error() {
        let result = run(
            command("kuda-no-such-program"),
            None,
            Duration::from_secs(1),
        );
        assert!(result.is_err());
        assert!(find_program("kuda-no-such-program").is_none());
    }

    #[test]
    fn finds_a_program_on_path() {
        let name = if cfg!(windows) { "cmd" } else { "sh" };
        assert!(find_program(name).is_some());
    }
}
