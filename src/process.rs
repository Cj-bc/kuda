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
    fn attach(&mut self, child: &mut Child) {
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
            // すぐ終わった子は登録が拒否される。子自身は止める必要がないので警告はしないが、
            // ジョブに入る前に子が起動した子孫は止められない（spawn 直後の隙間と同じ既知の制限）
            Err(error) if matches!(child.try_wait(), Ok(Some(_))) => {
                log::debug!("child exited before joining a job object: {error}");
            }
            Err(error) => log::warn!("failed to put the child in a job object: {error}"),
        }
    }

    fn exited(&mut self, child: &mut Child) -> std::io::Result<bool> {
        Ok(child.try_wait()?.is_some())
    }

    /// 終了を確かめられなくなったときに、子孫を残さず手を引く
    fn abandon(&mut self, child: &mut Child, _error: &std::io::Error) {
        self.kill(child);
        let _ = child.wait();
    }

    /// 子が終了済みでも呼んでよい。その終了コードは上書きされない
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

/// 実行中の子のプロセスグループ ID。0 は空き。
/// 別グループにした子には端末の Ctrl-C などが届かないので、kuda が受けたシグナルで
/// ここに載っているグループを止める。シグナルハンドラから読むので固定長のアトミックにする
#[cfg(unix)]
static GROUPS: [std::sync::atomic::AtomicI32; 64] =
    [const { std::sync::atomic::AtomicI32::new(0) }; 64];

/// 載っているグループをすべて止めてから、既定の動作（終了）でシグナルを受け直す。
/// async-signal-safe な処理だけを使う
#[cfg(unix)]
extern "C" fn on_terminating_signal(signal: libc::c_int) {
    use std::sync::atomic::Ordering;
    for slot in &GROUPS {
        let pgid = slot.load(Ordering::SeqCst);
        if pgid > 0 {
            unsafe {
                libc::killpg(pgid, libc::SIGKILL);
            }
        }
    }
    unsafe {
        libc::signal(signal, libc::SIG_DFL);
        libc::raise(signal);
    }
}

/// SIGINT / SIGTERM / SIGHUP / SIGQUIT のハンドラを一度だけ入れる。
/// 既定以外（nohup による無視など）になっているシグナルはそのままにする。
/// SIGQUIT も既定の動作で受け直すので、コアダンプはこれまでどおり残る
#[cfg(unix)]
fn install_signal_handlers() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
            unsafe {
                let mut current: libc::sigaction = std::mem::zeroed();
                if libc::sigaction(signal, std::ptr::null(), &mut current) != 0
                    || current.sa_sigaction != libc::SIG_DFL
                {
                    continue;
                }
                let mut action: libc::sigaction = std::mem::zeroed();
                action.sa_sigaction =
                    on_terminating_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
                libc::sigemptyset(&mut action.sa_mask);
                libc::sigaction(signal, &action, std::ptr::null_mut());
            }
        }
    });
}

#[cfg(unix)]
struct Tree {
    /// GROUPS の中で使っている枠。埋まっていたときは None で、シグナル時に止められない
    slot: Option<usize>,
}

#[cfg(unix)]
impl Tree {
    /// 子を新しいプロセスグループの長にする。孫は特に何もしなければ同じグループに入る
    fn prepare(command: &mut Command) -> Self {
        use std::os::unix::process::CommandExt;
        install_signal_handlers();
        // Ctrl-Z (SIGTSTP) では kuda だけが止まって子のグループは走り続け、再開すると
        // 壁時計の期限を過ぎているのですぐ時間切れとして止める
        command.process_group(0);
        Tree { slot: None }
    }

    /// シグナルで止める対象に載せる。spawn からここまでの間に届いたシグナルでは止められない
    fn attach(&mut self, child: &mut Child) {
        use std::sync::atomic::Ordering;
        let Ok(pgid) = libc::pid_t::try_from(child.id()) else {
            return;
        };
        self.slot = GROUPS.iter().position(|slot| {
            slot.compare_exchange(0, pgid, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        });
        if self.slot.is_none() {
            log::debug!("too many running commands to stop them on signals");
        }
    }

    /// 子が終わったかを、回収（reap）せずに調べる。回収するまで子の PID は再利用されないので、
    /// 終了後でもグループ ID（= 子の PID）を安全に killpg できる
    fn exited(&mut self, child: &mut Child) -> std::io::Result<bool> {
        let pid: libc::id_t = child.id();
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                pid,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            return match error.kind() {
                std::io::ErrorKind::Interrupted => Ok(false),
                _ => Err(error),
            };
        }
        // WNOHANG でまだ終わっていなければ si_pid は 0 のまま
        Ok(unsafe { info.si_pid() } != 0)
    }

    /// 子を回収する前に呼ぶ。シグナル用の枠も、回収後に別のグループを止めないようここで外す
    fn kill(&mut self, child: &mut Child) {
        if let Ok(pgid) = libc::pid_t::try_from(child.id()) {
            unsafe {
                libc::killpg(pgid, libc::SIGKILL);
            }
        }
        self.release();
        let _ = child.kill();
    }

    /// 終了を確かめられなくなったときに、子孫を残さず手を引く。
    /// ECHILD なら子はもう回収されていて PID（= グループ ID）が再利用されうるので、killpg しない
    fn abandon(&mut self, child: &mut Child, error: &std::io::Error) {
        if error.raw_os_error() == Some(libc::ECHILD) {
            self.release();
        } else {
            self.kill(child);
            let _ = child.wait();
        }
    }

    fn release(&mut self) {
        if let Some(slot) = self.slot.take() {
            GROUPS[slot].store(0, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

#[cfg(unix)]
impl Drop for Tree {
    fn drop(&mut self) {
        self.release();
    }
}

/// 実行して出力を集める。時間切れなら子孫ごと kill し、そこまでの出力を返す。
/// 子が正常に終わった場合も、子が残していった子孫（バックグラウンドの孫など）は止める
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
    tree.attach(&mut child);

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
    let timed_out = loop {
        match tree.exited(&mut child) {
            Ok(true) => break false,
            Ok(false) => {}
            Err(error) => {
                tree.abandon(&mut child, &error);
                return Err(error).context("failed to wait for the command");
            }
        }
        if Instant::now() >= deadline {
            break true;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    tree.kill(&mut child);
    let status = child.wait();
    let code = if timed_out { None } else { status?.code() };

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

    /// 孫プロセスを起動し、孫が「起動した」印を書いたあと、約 4 秒眠って「期限後」の印を書くコマンド。
    /// detach なら子は孫を待たずに 1 秒ほどで正常終了し、そうでなければ孫の終わりを待つ
    #[cfg(windows)]
    fn spawns_grandchild(started: &Path, late: &Path, detach: bool) -> Command {
        use std::os::windows::process::CommandExt;
        // 外側の cmd が子、内側の cmd が孫。ping で眠る
        let grandchild = format!(
            "cmd /d /c \"echo x>\"{}\" & ping -n 5 127.0.0.1 >nul & echo x>\"{}\"\"",
            started.display(),
            late.display()
        );
        let mut cmd = command("cmd");
        if detach {
            cmd.raw_arg(format!(
                "/d /c start \"\" /b {grandchild} & ping -n 2 127.0.0.1 >nul"
            ));
        } else {
            cmd.raw_arg(format!("/d /c {grandchild}"));
        }
        cmd
    }

    #[cfg(unix)]
    fn spawns_grandchild(started: &Path, late: &Path, detach: bool) -> Command {
        // サブシェルが孫
        let script = format!(
            "(touch '{}'; sleep 4; touch '{}') & {}",
            started.display(),
            late.display(),
            if detach { "sleep 1" } else { "wait" }
        );
        shell(&script)
    }

    /// 孫の印を置く、テストごとの空のディレクトリ
    fn marker_dir(test: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kuda-{test}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// 孫が生きていれば「期限後」の印を書くはずの時刻を十分に過ぎるまで待ってから、印の有無を返す
    fn grandchild_finished(dir: &Path, begun: Instant) -> bool {
        std::thread::sleep(Duration::from_secs(7).saturating_sub(begun.elapsed()));
        let wrote_late = dir.join("late").exists();
        let _ = std::fs::remove_dir_all(dir);
        wrote_late
    }

    #[test]
    fn kills_grandchildren_on_timeout() {
        let dir = marker_dir("timeout-tree");
        let begun = Instant::now();
        let command = spawns_grandchild(&dir.join("started"), &dir.join("late"), false);
        let output = run(command, None, Duration::from_secs(2)).unwrap();
        assert!(output.timed_out);
        // 孫がパイプを握ったままでも、読み取りの待ちで詰まらずに戻る
        assert!(begun.elapsed() < Duration::from_millis(3500));
        assert!(
            dir.join("started").exists(),
            "grandchild did not start before the deadline"
        );
        assert!(
            !grandchild_finished(&dir, begun),
            "grandchild kept running after the timeout"
        );
    }

    #[test]
    fn kills_leftover_grandchildren_after_a_normal_exit() {
        let dir = marker_dir("leftover-tree");
        let begun = Instant::now();
        let command = spawns_grandchild(&dir.join("started"), &dir.join("late"), true);
        let output = run(command, None, Duration::from_secs(30)).unwrap();
        assert!(!output.timed_out);
        assert_eq!(output.code, Some(0));
        assert!(begun.elapsed() < Duration::from_millis(3500));
        assert!(
            dir.join("started").exists(),
            "grandchild did not start before the child exited"
        );
        assert!(
            !grandchild_finished(&dir, begun),
            "grandchild kept running after the child exited"
        );
    }

    /// テストバイナリ自身をこの環境変数付きで起動すると、孫を起動するコマンドを run で走らせる側になる
    #[cfg(unix)]
    const SIGNAL_HELPER_DIR: &str = "KUDA_TEST_SIGNAL_HELPER_DIR";

    #[cfg(unix)]
    #[test]
    fn stops_commands_when_signalled() {
        use std::os::unix::process::ExitStatusExt;

        if let Some(dir) = std::env::var_os(SIGNAL_HELPER_DIR) {
            let dir = PathBuf::from(dir);
            let command = spawns_grandchild(&dir.join("started"), &dir.join("late"), false);
            let _ = run(command, None, Duration::from_secs(30));
            return;
        }

        let dir = marker_dir("signal-tree");
        let mut helper = Command::new(std::env::current_exe().unwrap());
        // SIGTERM を無視する設定で起動された環境でも、ヘルパーではハンドラが入るようにする
        unsafe {
            std::os::unix::process::CommandExt::pre_exec(&mut helper, || {
                libc::signal(libc::SIGTERM, libc::SIG_DFL);
                Ok(())
            });
        }
        let mut helper = helper
            .args([
                "--exact",
                "process::tests::stops_commands_when_signalled",
                "--nocapture",
            ])
            .env(SIGNAL_HELPER_DIR, &dir)
            .stdout(Stdio::null())
            .spawn()
            .unwrap();

        let waiting = Instant::now() + Duration::from_secs(10);
        while !dir.join("started").exists() && Instant::now() < waiting {
            std::thread::sleep(Duration::from_millis(20));
        }
        let begun = Instant::now();
        assert!(dir.join("started").exists(), "grandchild did not start");

        let pid = libc::pid_t::try_from(helper.id()).unwrap();
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
        let status = helper.wait().unwrap();
        // ハンドラが既定の動作で受け直すので、シグナルによる終了になる
        assert_eq!(status.signal(), Some(libc::SIGTERM));
        assert!(
            !grandchild_finished(&dir, begun),
            "grandchild kept running after kuda was signalled"
        );
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
