//! kind = "process": 動いているプロセスの列挙。判定や学習はここでは行わない。

use anyhow::Result;

#[derive(Debug, Clone, PartialEq)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub name: String,
    /// 正規化前の実行ファイルのパス。保護プロセスなどで取れないときは None
    pub path: Option<String>,
    pub user: Option<String>,
    /// Unix 秒
    pub started: Option<i64>,
    /// Linux のカーネルスレッド（stat の flags に PF_KTHREAD）。Windows では常に false
    pub kernel_thread: bool,
}

/// 全プロセスを列挙する。個々のプロセスの詳細が取れなくても列挙は続ける
pub fn enumerate() -> Result<Vec<ProcessInfo>> {
    imp::enumerate()
}

/// 別々の列挙で見た起動時刻が、同じプロセスのものか。
/// Linux の起動時刻は、起動からの経過と、読むたびに計算される起動時刻（btime）から作るので、
/// 列挙をまたぐと 1 秒ずれうる。同じ 1 秒のうちに同じ PID が再利用されることは考えない
pub fn same_start(recorded: i64, seen: Option<i64>) -> bool {
    seen.is_some_and(|seen| (seen - recorded).abs() <= 1)
}

#[cfg(windows)]
mod imp {
    use super::ProcessInfo;
    use anyhow::{Context, Result};
    use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE};
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
        QueryFullProcessImageNameW,
    };
    use windows::core::PWSTR;

    /// FILETIME（1601-01-01 からの 100ns 単位）と Unix エポックの差
    const FILETIME_UNIX_OFFSET_SECS: i64 = 11_644_473_600;

    /// 閉じ忘れを防ぐ
    struct Handle(HANDLE);

    impl Drop for Handle {
        fn drop(&mut self) {
            // 閉じられなくても出来ることがない
            let _ = unsafe { CloseHandle(self.0) };
        }
    }

    pub fn enumerate() -> Result<Vec<ProcessInfo>> {
        let snapshot = Handle(
            unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
                .context("CreateToolhelp32Snapshot failed")?,
        );
        let mut entry = PROCESSENTRY32W {
            dwSize: size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        unsafe { Process32FirstW(snapshot.0, &mut entry) }.context("Process32FirstW failed")?;

        let mut processes = Vec::new();
        loop {
            processes.push(describe(&entry));
            if unsafe { Process32NextW(snapshot.0, &mut entry) }.is_err() {
                break; // ERROR_NO_MORE_FILES で終わる
            }
        }
        Ok(processes)
    }

    fn describe(entry: &PROCESSENTRY32W) -> ProcessInfo {
        let len = entry
            .szExeFile
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(entry.szExeFile.len());
        let pid = entry.th32ProcessID;
        // 開けないプロセス（保護プロセスなど）は path / started を諦める
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
            .ok()
            .map(Handle);
        ProcessInfo {
            pid,
            // PID 0（System Idle）は親を持たない
            ppid: (pid != 0).then_some(entry.th32ParentProcessID),
            name: String::from_utf16_lossy(&entry.szExeFile[..len]),
            path: handle.as_ref().and_then(|h| image_path(h.0)),
            user: None,
            started: handle.as_ref().and_then(|h| start_time(h.0)),
            kernel_thread: false,
        }
    }

    fn image_path(process: HANDLE) -> Option<String> {
        // 拡張パスは 32767 文字まで。MAX_PATH では足りないことがある
        let mut buf = vec![0u16; 32768];
        let mut len = buf.len() as u32;
        unsafe {
            QueryFullProcessImageNameW(
                process,
                PROCESS_NAME_WIN32,
                PWSTR(buf.as_mut_ptr()),
                &mut len,
            )
        }
        .ok()?;
        Some(String::from_utf16_lossy(&buf[..len as usize]))
    }

    fn start_time(process: HANDLE) -> Option<i64> {
        let mut created = FILETIME::default();
        let mut unused = [FILETIME::default(); 3];
        let [exited, kernel, user] = &mut unused;
        unsafe { GetProcessTimes(process, &mut created, exited, kernel, user) }.ok()?;
        let ticks = (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime);
        Some((ticks / 10_000_000) as i64 - FILETIME_UNIX_OFFSET_SECS)
    }
}

/// Linux のパス（任意のバイト列）を文字列にする。パスは識別キーになるので、別のパスが
/// 同じ文字列にならないようにする。置き換え文字で崩すと、UTF-8 でないファイル名どうしが
/// 1 つの識別キーにまとまり、新しい実行ファイルが既知のものとして扱われうる。
/// そこで、UTF-8 として読めないバイトは `\xNN` に、`\` は `\\` にする
#[cfg(any(unix, test))]
fn path_text(bytes: &[u8]) -> String {
    let mut text = String::new();
    for chunk in bytes.utf8_chunks() {
        text.push_str(&chunk.valid().replace('\\', "\\\\"));
        for byte in chunk.invalid() {
            text.push_str(&format!("\\x{byte:02x}"));
        }
    }
    text
}

#[cfg(unix)]
mod imp {
    use super::{ProcessInfo, path_text};
    use anyhow::{Context, Result};
    use std::fs;
    use std::os::unix::ffi::OsStrExt;

    pub fn enumerate() -> Result<Vec<ProcessInfo>> {
        let boot_time = boot_time().context("cannot read btime from /proc/stat")?;
        let ticks_per_sec = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as u64;
        let users = read_users();

        let mut processes = Vec::new();
        for entry in fs::read_dir("/proc").context("cannot read /proc")? {
            let Ok(entry) = entry else { continue };
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<u32>().ok())
            else {
                continue;
            };
            // 列挙の途中で終わったプロセスは読めない。黙って飛ばす
            if let Some(info) = describe(pid, boot_time, ticks_per_sec, &users) {
                processes.push(info);
            }
        }
        Ok(processes)
    }

    fn describe(
        pid: u32,
        boot_time: i64,
        ticks_per_sec: u64,
        users: &[(u32, String)],
    ) -> Option<ProcessInfo> {
        let stat = parse_stat_bytes(&fs::read(format!("/proc/{pid}/stat")).ok()?)?;
        // 他ユーザーのプロセスやカーネルスレッドでは読めない
        let path = fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .map(|p| path_text(p.as_os_str().as_bytes()));
        let user = fs::read_to_string(format!("/proc/{pid}/status"))
            .ok()
            .and_then(|status| parse_uid(&status))
            .map(|uid| match users.iter().find(|(id, _)| *id == uid) {
                Some((_, name)) => name.clone(),
                None => uid.to_string(),
            });
        Some(ProcessInfo {
            pid,
            ppid: Some(stat.ppid),
            name: stat.name,
            path,
            user,
            started: Some(boot_time + (stat.start_ticks / ticks_per_sec) as i64),
            kernel_thread: stat.kernel_thread,
        })
    }

    struct Stat {
        name: String,
        ppid: u32,
        start_ticks: u64,
        kernel_thread: bool,
    }

    /// include/linux/sched.h の PF_KTHREAD。PID の名前空間の中でも正しく判定できる
    /// （名前空間の中では kthreadd が PID 2 とは限らず、PID 2 が普通のサービスでありうる）
    const PF_KTHREAD: u64 = 0x0020_0000;

    /// comm は UTF-8 とは限らない（プロセスが自由に付けられる）。UTF-8 として読むと
    /// プロセスごと列挙から落ちるので、名前だけを置き換え文字で崩して読む。
    /// 区切りの `(` `)` と数字は ASCII なので、崩しても位置は変わらない
    fn parse_stat_bytes(stat: &[u8]) -> Option<Stat> {
        parse_stat(&String::from_utf8_lossy(stat))
    }

    /// `pid (comm) state ppid ...`。comm は空白や括弧を含みうるので、最後の `)` で区切る
    fn parse_stat(stat: &str) -> Option<Stat> {
        let open = stat.find('(')?;
        let close = stat.rfind(')')?;
        let rest: Vec<&str> = stat.get(close + 1..)?.split_whitespace().collect();
        // rest[0] = state, rest[1] = ppid, rest[6] = flags（stat の 9 番目）、
        // rest[19] = starttime（stat の 22 番目）
        let flags: u64 = rest.get(6)?.parse().ok()?;
        Some(Stat {
            name: stat.get(open + 1..close)?.to_string(),
            ppid: rest.get(1)?.parse().ok()?,
            start_ticks: rest.get(19)?.parse().ok()?,
            kernel_thread: flags & PF_KTHREAD != 0,
        })
    }

    fn parse_uid(status: &str) -> Option<u32> {
        let line = status.lines().find_map(|l| l.strip_prefix("Uid:"))?;
        line.split_whitespace().next()?.parse().ok()
    }

    fn boot_time() -> Option<i64> {
        fs::read_to_string("/proc/stat")
            .ok()?
            .lines()
            .find_map(|l| l.strip_prefix("btime "))?
            .trim()
            .parse()
            .ok()
    }

    /// /etc/passwd から uid と名前の対応を読む。読めなければ uid を数字のまま出す
    fn read_users() -> Vec<(u32, String)> {
        let Ok(passwd) = fs::read_to_string("/etc/passwd") else {
            return Vec::new();
        };
        passwd
            .lines()
            .filter_map(|line| {
                let mut fields = line.split(':');
                let name = fields.next()?;
                let uid = fields.nth(1)?.parse().ok()?;
                Some((uid, name.to_string()))
            })
            .collect()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn stat_with_spaces_and_parens_in_the_name() {
            let line =
                "42 (a) b (c) S 7 42 42 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 12345 1000 10 0";
            let stat = parse_stat(line).unwrap();
            assert_eq!(stat.name, "a) b (c");
            assert_eq!(stat.ppid, 7);
            assert_eq!(stat.start_ticks, 12345);
            assert!(!stat.kernel_thread);
        }

        #[test]
        fn kernel_threads_are_told_by_their_flags() {
            // kworker の実例。flags 0x4208060 に PF_KTHREAD（0x200000）が立っている
            let line = "88 (kworker/0:1H) I 2 0 0 0 -1 69238880 0 0 0 0 0 0 0 0 0 -20 1 0 77 0 0";
            assert!(parse_stat(line).unwrap().kernel_thread);
        }

        #[test]
        fn a_name_that_is_not_utf8_keeps_the_process() {
            let line = b"42 (x\xff\xfey) S 7 42 42 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 12345 1000 10 0";
            let stat = parse_stat_bytes(line).unwrap();
            assert_eq!(stat.name, "x\u{fffd}\u{fffd}y");
            assert_eq!(stat.ppid, 7);
            assert_eq!(stat.start_ticks, 12345);
        }

        #[test]
        fn uid_is_the_real_uid() {
            assert_eq!(
                parse_uid("Name:\tx\nUid:\t1000\t1001\t1000\t1000\n"),
                Some(1000)
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec;

    #[test]
    fn lists_itself_with_path_and_start_time() {
        let processes = enumerate().unwrap();
        let me = processes
            .iter()
            .find(|p| p.pid == std::process::id())
            .expect("own pid is listed");
        let exe = std::env::current_exe().unwrap();
        let path = me.path.as_deref().expect("own path is readable");
        // Windows は大文字小文字や 8.3 短縮名が異なりうるので、ファイル名で比べる
        assert_eq!(
            std::path::Path::new(path)
                .file_name()
                .unwrap()
                .to_ascii_lowercase(),
            exe.file_name().unwrap().to_ascii_lowercase()
        );

        let now = chrono::Utc::now().timestamp();
        let started = me.started.expect("own start time is readable");
        assert!(started <= now + 1 && started > now - 24 * 3600, "{started}");
        assert!(me.ppid.is_some_and(|ppid| ppid != 0));
    }

    #[test]
    fn child_reports_this_process_as_its_parent() {
        #[cfg(windows)]
        let mut command = exec::command("ping");
        #[cfg(windows)]
        command.args(["-n", "10", "127.0.0.1"]);
        #[cfg(unix)]
        let mut command = exec::command("sleep");
        #[cfg(unix)]
        command.arg("10");

        let mut child = command.spawn().unwrap();
        let processes = enumerate().unwrap();
        let _ = child.kill();
        let _ = child.wait();

        let found = processes.iter().find(|p| p.pid == child.id()).unwrap();
        assert_eq!(found.ppid, Some(std::process::id()));
    }

    /// 別のパスは別の文字列になる。UTF-8 のパスで `\` を含まないものは、そのまま
    #[test]
    fn paths_stay_distinct_when_they_are_not_utf8() {
        assert_eq!(path_text(b"/usr/bin/tool"), "/usr/bin/tool");
        assert_eq!(path_text(b"/tmp/a\xff"), r"/tmp/a\xff");
        assert_ne!(path_text(b"/tmp/a\xff"), path_text(b"/tmp/a\xfe"));
        // 文字どおり `\xff` という名前のファイルとも区別する
        assert_eq!(path_text(br"/tmp/a\xff"), r"/tmp/a\\xff");
    }
}
