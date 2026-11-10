//! 外部コマンドの起動。タイムアウトと、コンソール窓を出さないことをここで揃える。

use anyhow::{Context, Result};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
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

/// 子プロセスとその子孫をまとめて止めるための入れ物。
/// Windows はジョブオブジェクト、Unix はプロセスグループで子孫を束ねる
#[cfg(windows)]
struct Tree {
    /// ジョブを作れなかったときは None で、直接の子だけを止める
    job: Option<windows::Win32::Foundation::HANDLE>,
}

#[cfg(windows)]
impl Tree {
    fn prepare(_command: &mut Command) -> Self {
        Tree { job: None }
    }

    /// ジョブに入れた後に起動された孫もジョブに属する。
    /// spawn から登録までの間に子が孫を起動すると取りこぼすが、その隙間はごく短い
    fn attach(&mut self, child: &Child) {
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::Foundation::{CloseHandle, HANDLE};
        use windows::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        };

        let result = unsafe {
            CreateJobObjectW(None, windows::core::PCWSTR::null()).and_then(|job| {
                // kuda が落ちてハンドルが閉じられたときも子孫ごと止まるようにする
                let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
                info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                let attached = SetInformationJobObject(
                    job,
                    JobObjectExtendedLimitInformation,
                    (&raw const info).cast(),
                    size_of_val(&info) as u32,
                )
                .and_then(|()| AssignProcessToJobObject(job, HANDLE(child.as_raw_handle())));
                match attached {
                    Ok(()) => Ok(job),
                    Err(error) => {
                        let _ = CloseHandle(job);
                        Err(error)
                    }
                }
            })
        };
        match result {
            Ok(job) => self.job = Some(job),
            Err(error) => log::warn!("failed to put the child in a job object: {error}"),
        }
    }

    fn kill(&mut self, child: &mut Child) {
        if let Some(job) = self.job {
            let _ = unsafe { windows::Win32::System::JobObjects::TerminateJobObject(job, 1) };
        }
        let _ = child.kill();
    }
}

/// ハンドルを閉じるとジョブに残った子孫も止まる。終了後に居残る孫も片付けることになる
#[cfg(windows)]
impl Drop for Tree {
    fn drop(&mut self) {
        if let Some(job) = self.job.take() {
            let _ = unsafe { windows::Win32::Foundation::CloseHandle(job) };
        }
    }
}

#[cfg(unix)]
struct Tree;

#[cfg(unix)]
impl Tree {
    /// 子を新しいプロセスグループの長にする。孫は特に何もしなければ同じグループに入る
    fn prepare(command: &mut Command) -> Self {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
        Tree
    }

    fn attach(&mut self, _child: &Child) {}

    /// 子をまだ回収していないので、グループ ID（= 子の PID）が他に再利用されることはない
    fn kill(&mut self, child: &mut Child) {
        if let Ok(pgid) = libc::pid_t::try_from(child.id()) {
            unsafe {
                libc::killpg(pgid, libc::SIGKILL);
            }
        }
        let _ = child.kill();
    }
}

/// 実行して出力を集める。時間切れなら子孫ごと kill し、そこまでの出力を返す
pub fn run(mut command: Command, stdin: Option<&str>, timeout: Duration) -> Result<Output> {
    command
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut tree = Tree::prepare(&mut command);
    let mut child = command
        .spawn()
        .with_context(|| format!("failed to start {:?}", command.get_program()))?;
    tree.attach(&child);

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
            tree.kill(&mut child);
            let _ = child.wait();
            break (None, true);
        }
        std::thread::sleep(Duration::from_millis(20));
    };

    // 子孫を止めたのでパイプは閉じるはずだが、ジョブやグループから抜けた孫が
    // パイプを握っていると EOF が来ないので、join で待ち切らない
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

    /// 孫プロセスを起動し、孫が「起動した」印を書いたあと、しばらく眠って「期限後」の印を書くコマンド
    #[cfg(windows)]
    fn spawns_grandchild(started: &Path, late: &Path) -> Command {
        use std::os::windows::process::CommandExt;
        // 外側の cmd が子、内側の cmd が孫。ping で約 4 秒眠る
        let mut cmd = command("cmd");
        cmd.raw_arg(format!(
            "/d /c cmd /d /c \"echo x>\"{}\" & ping -n 5 127.0.0.1 >nul & echo x>\"{}\"\"",
            started.display(),
            late.display()
        ));
        cmd
    }

    #[cfg(unix)]
    fn spawns_grandchild(started: &Path, late: &Path) -> Command {
        // サブシェルが孫。外側の sh は wait で待つだけ
        let script = format!(
            "(touch '{}'; sleep 4; touch '{}') & wait",
            started.display(),
            late.display()
        );
        shell(&script)
    }

    #[test]
    fn kills_grandchildren_on_timeout() {
        let dir = std::env::temp_dir().join(format!("kuda-process-tree-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let started = dir.join("started");
        let late = dir.join("late");
        let _ = std::fs::remove_file(&started);
        let _ = std::fs::remove_file(&late);

        let begun = Instant::now();
        let output = run(
            spawns_grandchild(&started, &late),
            None,
            Duration::from_secs(2),
        )
        .unwrap();
        assert!(output.timed_out);
        // 孫がパイプを握ったままでも、読み取りの待ちで詰まらずに戻る
        assert!(begun.elapsed() < Duration::from_millis(3500));
        assert!(started.exists(), "grandchild did not start before the deadline");

        // 孫が生きていれば印を書くはずの時刻を十分に過ぎるまで待つ
        std::thread::sleep(Duration::from_secs(7).saturating_sub(begun.elapsed()));
        let wrote_late = late.exists();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(!wrote_late, "grandchild kept running after the timeout");
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
