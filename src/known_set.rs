//! プロセスの識別と分類のうち、ストアに触れない純関数。
//!
//! 環境変数や実行中の OS は関数の中で読まない。呼び出し側が [`Os`] と [`Roots`] を渡す。
//! こうしておくと、Windows のパス規則のテストを Linux 上でも走らせられる。
//! ストアを使う分類（`classify`）は別のタスクで足す。

// 呼ぶのは分類と check 側。T4 で使うまで未使用になる
#![allow(dead_code)]

use crate::probe::ProcessInfo;
use std::collections::{HashMap, HashSet};

/// パス規則を切り替えるための OS。実行中の OS とは限らない（テストのため）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    Windows,
    Linux,
}

impl Os {
    pub fn current() -> Os {
        if cfg!(windows) {
            Os::Windows
        } else {
            Os::Linux
        }
    }

    fn separator(self) -> char {
        match self {
            Os::Windows => '\\',
            Os::Linux => '/',
        }
    }
}

/// 正規化の結果
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// 識別キー。パスが取れたら正規化したパス、取れなければ `name:<小文字名>`
    pub key: String,
    /// Linux で実行ファイルが削除済み（` (deleted)`）だった。事件の証拠に載せる
    pub deleted: bool,
}

/// パスの正規化のうち、バージョン要素の置き換えを除いた部分。フラグ判定にはこちらを使う
/// （`C:\Users\1.2.3\...` のような置き換えで場所の判定が変わらないように）
fn normalize_basic(os: Os, path: &str) -> (String, bool) {
    match os {
        Os::Windows => {
            let path = path.strip_prefix(r"\\?\").unwrap_or(path);
            (path.replace('/', "\\").to_ascii_lowercase(), false)
        }
        Os::Linux => match path.strip_suffix(" (deleted)") {
            Some(rest) => (rest.to_string(), true),
            None => (path.to_string(), false),
        },
    }
}

/// パスを識別キーに正規化する（§2.2 の 1〜3）
pub fn normalize_path(os: Os, path: &str) -> Identity {
    let (path, deleted) = normalize_basic(os, path);
    let sep = os.separator();
    let key = path
        .split(sep)
        .map(|element| {
            if is_version_element(element) {
                "*"
            } else {
                element
            }
        })
        .collect::<Vec<_>>()
        .join(&sep.to_string());
    Identity { key, deleted }
}

/// `(v|app-)?数字(.数字)+` の後に、任意で `[-+_.]` と英数字・`.` の列が続く形か。
/// 更新のたびに変わるディレクトリ名やファイル名を 1 つの識別キーにまとめるために使う。
/// `python3` や `x64` のように `.` を含まない数字は、バージョンとみなさない
fn is_version_element(element: &str) -> bool {
    let lower = element.to_ascii_lowercase();
    let rest = lower
        .strip_prefix("app-")
        .or_else(|| lower.strip_prefix('v'))
        .unwrap_or(&lower);
    let bytes = rest.as_bytes();

    let digits = |from: usize| {
        bytes[from..]
            .iter()
            .take_while(|b| b.is_ascii_digit())
            .count()
    };
    let first = digits(0);
    if first == 0 {
        return false;
    }
    let mut pos = first;
    let mut groups = 0;
    // `.` の後に数字が続く限りだけ食う。`1.2.3.exe` の `.exe` は後ろの列として扱う
    while pos < bytes.len() && bytes[pos] == b'.' {
        let n = digits(pos + 1);
        if n == 0 {
            break;
        }
        pos += 1 + n;
        groups += 1;
    }
    if groups == 0 {
        return false;
    }
    match bytes.get(pos) {
        None => true,
        Some(b'-' | b'+' | b'_' | b'.') => bytes[pos + 1..]
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'.'),
        Some(_) => false,
    }
}

/// Linux のカーネルスレッドか。`/proc/<pid>/exe` が読めず、自身が kthreadd（PID 2）か
/// その子であるものを対象外にする。Windows では常に false
pub fn is_kernel_thread(os: Os, info: &ProcessInfo) -> bool {
    os == Os::Linux && info.path.is_none() && (info.pid == 2 || info.ppid == Some(2))
}

/// プロセスの識別キーを求める。対象外（カーネルスレッド）は None
pub fn identify(os: Os, info: &ProcessInfo) -> Option<Identity> {
    if is_kernel_thread(os, info) {
        return None;
    }
    Some(match &info.path {
        Some(path) => normalize_path(os, path),
        None => Identity {
            key: format!("name:{}", info.name.to_lowercase()),
            deleted: false,
        },
    })
}

/// フラグ判定に使う、解決済みの場所。環境変数はここへ渡す前に呼び出し側が読む
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Roots {
    os: Os,
    /// 正規化済み。末尾の区切りは無い
    user_writable: Vec<String>,
    /// 正規化済み（Windows の `%SystemRoot%`）
    system_root: String,
}

impl Roots {
    /// 渡す値は正規化前でよい。空や根（`/`）は、全部が書き込み可能になってしまうので捨てる
    pub fn new(os: Os, user_writable: &[&str], system_root: Option<&str>) -> Roots {
        let trim = |p: &str| {
            let (p, _) = normalize_basic(os, p);
            p.trim_end_matches(os.separator()).to_string()
        };
        Roots {
            os,
            user_writable: user_writable
                .iter()
                .map(|p| trim(p))
                .filter(|p| !p.is_empty())
                .collect(),
            system_root: trim(system_root.unwrap_or(r"C:\Windows")),
        }
    }

    /// 実行中の環境から組み立てる。環境変数を読むのはここだけ
    pub fn from_env() -> Roots {
        let os = Os::current();
        let var = |name: &str| std::env::var(name).unwrap_or_default();
        match os {
            Os::Windows => {
                let (profile, temp, tmp, root) = (
                    var("USERPROFILE"),
                    var("TEMP"),
                    var("TMP"),
                    var("SystemRoot"),
                );
                let root = (!root.is_empty()).then_some(root.as_str());
                Roots::new(os, &[&profile, &temp, &tmp, r"C:\Users\Public"], root)
            }
            Os::Linux => {
                let home = var("HOME");
                Roots::new(os, &[&home, "/tmp", "/var/tmp", "/dev/shm"], None)
            }
        }
    }
}

/// `path` が `dir` と同じか、その配下にあるか。どちらも正規化済み
fn is_under(sep: char, path: &str, dir: &str) -> bool {
    path.strip_prefix(dir)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with(sep))
}

/// user_writable: 利用者が書き込める場所（ユーザーフォルダや一時領域）の配下にある実行ファイル
pub fn is_user_writable(roots: &Roots, path: &str) -> bool {
    let (path, _) = normalize_basic(roots.os, path);
    roots
        .user_writable
        .iter()
        .any(|dir| is_under(roots.os.separator(), &path, dir))
}

/// Windows のシステムプロセスの名前
const SYSTEM_PROCESS_NAMES: &[&str] = &[
    "svchost.exe",
    "lsass.exe",
    "csrss.exe",
    "winlogon.exe",
    "wininit.exe",
    "services.exe",
    "smss.exe",
    "taskhostw.exe",
    "dllhost.exe",
    "conhost.exe",
    "rundll32.exe",
    "spoolsv.exe",
];

/// masquerade: Windows のシステムプロセスの名前なのに、置き場所が違う。
/// パスが取れないもの（`path` が None）は判定しない。Linux では常に false
pub fn is_masquerade(roots: &Roots, name: &str, path: Option<&str>) -> bool {
    if roots.os != Os::Windows {
        return false;
    }
    let Some(path) = path else {
        return false;
    };
    let name = name.to_ascii_lowercase();
    let (path, _) = normalize_basic(roots.os, path);
    // 名前の表に無ければ対象外。explorer.exe だけは %SystemRoot% 直下が正しい置き場所
    let allowed: Vec<String> = if name == "explorer.exe" {
        vec![roots.system_root.clone()]
    } else if SYSTEM_PROCESS_NAMES.contains(&name.as_str()) {
        vec![
            format!(r"{}\system32", roots.system_root),
            format!(r"{}\syswow64", roots.system_root),
        ]
    } else {
        return false;
    };
    // 親ディレクトリの完全一致で見る。`system32\evil\svchost.exe` も不正にする
    let parent = path.rsplit_once('\\').map_or("", |(dir, _)| dir);
    !allowed.iter().any(|dir| dir == parent)
}

/// 根のプロセスとその子孫を除いたプロセス一覧を返す。
///
/// `roots` は (PID, 起動時刻)。kuda 自身と実行中の調査プロセスを渡す。
/// 判断はすべて「除外しすぎない」側に倒す。除外は見えなくする操作なので、
/// 誤って除くより、kuda 自身が未知として見えるほうがまだ安全だから。
/// - 根は、一覧に同じ PID がいて起動時刻が一致するときだけ生きているとみなす（PID 再利用対策）
/// - 親子は、親の起動時刻 ≤ 子の起動時刻のときだけたどる。
///   どちらかの起動時刻が None のときは確かめられないので、たどらない
pub fn without_descendants<'a>(
    processes: &'a [ProcessInfo],
    roots: &[(u32, i64)],
) -> Vec<&'a ProcessInfo> {
    let by_pid: HashMap<u32, &ProcessInfo> = processes.iter().rev().map(|p| (p.pid, p)).collect();
    let mut children: HashMap<u32, Vec<&ProcessInfo>> = HashMap::new();
    for p in processes {
        if let Some(ppid) = p.ppid {
            children.entry(ppid).or_default().push(p);
        }
    }

    let mut excluded: HashSet<u32> = HashSet::new();
    let mut queue: Vec<&ProcessInfo> = roots
        .iter()
        .filter_map(|&(pid, started)| {
            by_pid
                .get(&pid)
                .copied()
                .filter(|p| p.started == Some(started))
        })
        .collect();
    while let Some(parent) = queue.pop() {
        if !excluded.insert(parent.pid) {
            continue;
        }
        for &child in children.get(&parent.pid).into_iter().flatten() {
            match (parent.started, child.started) {
                (Some(ps), Some(cs)) if ps <= cs => queue.push(child),
                _ => {}
            }
        }
    }
    processes
        .iter()
        .filter(|p| !excluded.contains(&p.pid))
        .collect()
}

/// `*`（区切りも跨ぐ）だけを扱う glob。大文字小文字は区別しない
/// （パターンもパスも小文字にそろえる。Linux のパスも同じ扱いにして規則を 1 つにする）
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.to_lowercase().chars().collect();
    let text: Vec<char> = text.to_lowercase().chars().collect();
    let (mut p, mut t) = (0, 0);
    // 直近の `*` の位置と、そのとき `*` に食わせていた text の終端
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        if p < pattern.len() && pattern[p] == '*' {
            star = Some((p, t));
            p += 1;
        } else if p < pattern.len() && pattern[p] == text[t] {
            p += 1;
            t += 1;
        } else if let Some((sp, st)) = star {
            p = sp + 1;
            t = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|&c| c == '*')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn norm(os: Os, path: &str) -> String {
        normalize_path(os, path).key
    }

    fn info(pid: u32, ppid: Option<u32>, started: Option<i64>) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid,
            name: format!("p{pid}"),
            path: Some(format!("/bin/p{pid}")),
            user: None,
            started,
        }
    }

    #[test]
    fn version_elements_are_replaced() {
        for element in [
            "1.2.3",
            "app-1.0.9",
            "v18.20.0",
            "2.1.0-beta.1",
            "130.0.6723.92",
            "APP-1.0.9",
            "V1.2",
        ] {
            assert!(is_version_element(element), "{element}");
        }
        assert_eq!(
            norm(
                Os::Windows,
                r"C:\Users\x\AppData\Local\app\app-1.0.9\app.exe"
            ),
            r"c:\users\x\appdata\local\app\*\app.exe"
        );
        assert_eq!(
            norm(Os::Linux, "/opt/node/v18.20.0/bin/node"),
            "/opt/node/*/bin/node"
        );
        assert_eq!(
            norm(
                Os::Windows,
                r"C:\Program Files\Google\Chrome\Application\130.0.6723.92\chrome.exe"
            ),
            r"c:\program files\google\chrome\application\*\chrome.exe"
        );
        // ファイル名の要素も対象
        assert_eq!(norm(Os::Linux, "/opt/tool/1.2.3-rc1"), "/opt/tool/*");
    }

    #[test]
    fn non_version_elements_are_kept() {
        for element in [
            "python3",
            "x64",
            "win32",
            "7z",
            "3",
            "v1",
            "1.",
            "1.2a",
            "app-",
            "1.2.3-x y",
        ] {
            assert!(!is_version_element(element), "{element}");
        }
        assert_eq!(norm(Os::Linux, "/usr/bin/python3"), "/usr/bin/python3");
        assert_eq!(
            norm(Os::Windows, r"C:\Program Files\x64\win32\a.exe"),
            r"c:\program files\x64\win32\a.exe"
        );
    }

    #[test]
    fn windows_prefix_separator_and_case() {
        assert_eq!(
            norm(Os::Windows, r"\\?\C:\Windows\System32\SvcHost.EXE"),
            r"c:\windows\system32\svchost.exe"
        );
        assert_eq!(
            norm(Os::Windows, "C:/Windows/System32/cmd.exe"),
            r"c:\windows\system32\cmd.exe"
        );
        // 非 ASCII は触らない
        assert_eq!(
            norm(Os::Windows, r"C:\Users\Ä\a.exe"),
            "c:\\users\\Ä\\a.exe"
        );
    }

    #[test]
    fn linux_keeps_case_and_strips_deleted() {
        let id = normalize_path(Os::Linux, "/home/Me/Bin/Tool (deleted)");
        assert_eq!(id.key, "/home/Me/Bin/Tool");
        assert!(id.deleted);
        let id = normalize_path(Os::Linux, "/home/Me/Bin/Tool");
        assert!(!id.deleted);
        // Windows では ` (deleted)` を特別扱いしない
        let id = normalize_path(Os::Windows, r"C:\a (deleted)");
        assert_eq!(id.key, r"c:\a (deleted)");
        assert!(!id.deleted);
    }

    #[test]
    fn name_key_when_path_is_missing() {
        let p = ProcessInfo {
            pid: 4,
            ppid: Some(0),
            name: "System".into(),
            path: None,
            user: None,
            started: None,
        };
        assert_eq!(identify(Os::Windows, &p).unwrap().key, "name:system");
        let q = ProcessInfo {
            path: Some(r"C:\X\a.exe".into()),
            ..p
        };
        assert_eq!(identify(Os::Windows, &q).unwrap().key, r"c:\x\a.exe");
    }

    #[test]
    fn kernel_threads_are_skipped_on_linux_only() {
        let mut kthreadd = info(2, Some(0), None);
        kthreadd.path = None;
        let mut worker = info(30, Some(2), None);
        worker.path = None;
        let mut unreadable = info(500, Some(1), None);
        unreadable.path = None;
        let mut child_with_exe = info(31, Some(2), None);
        child_with_exe.path = Some("/usr/bin/x".into());

        assert!(identify(Os::Linux, &kthreadd).is_none());
        assert!(identify(Os::Linux, &worker).is_none());
        // 親が kthreadd でなければ、読めないだけのプロセスは name: キーで残す
        assert_eq!(identify(Os::Linux, &unreadable).unwrap().key, "name:p500");
        assert!(identify(Os::Linux, &child_with_exe).is_some());
        assert!(identify(Os::Windows, &worker).is_some());
    }

    fn win_roots() -> Roots {
        Roots::new(
            Os::Windows,
            &[
                r"C:\Users\Alice",
                r"C:\Users\Alice\AppData\Local\Temp\",
                r"C:\Users\Public",
                "",
            ],
            Some(r"C:\Windows"),
        )
    }

    #[test]
    fn user_writable_windows() {
        let r = win_roots();
        assert!(is_user_writable(&r, r"C:\Users\Alice\Downloads\a.exe"));
        assert!(is_user_writable(&r, r"\\?\c:\USERS\alice\a.exe"));
        assert!(is_user_writable(&r, r"C:\Users\Public\a.exe"));
        // 前方一致だけで判定しない
        assert!(!is_user_writable(&r, r"C:\Users\AliceX\a.exe"));
        assert!(!is_user_writable(&r, r"C:\Windows\System32\a.exe"));
        assert!(!is_user_writable(&r, r"C:\Program Files\a\a.exe"));
    }

    #[test]
    fn user_writable_linux() {
        let r = Roots::new(
            Os::Linux,
            &["/home/me", "/tmp", "/var/tmp", "/dev/shm", "/"],
            None,
        );
        assert!(is_user_writable(&r, "/home/me/bin/a"));
        assert!(is_user_writable(&r, "/tmp/a"));
        assert!(is_user_writable(&r, "/dev/shm/x/a"));
        assert!(!is_user_writable(&r, "/home/mellow/a"));
        assert!(!is_user_writable(&r, "/usr/bin/a"));
        // 根を渡されても全部が書き込み可能にはならない
        assert!(!is_user_writable(&r, "/opt/a"));
    }

    #[test]
    fn masquerade_true_cases() {
        let r = win_roots();
        assert!(is_masquerade(
            &r,
            "svchost.exe",
            Some(r"C:\Users\Alice\svchost.exe")
        ));
        assert!(is_masquerade(
            &r,
            "SVCHOST.EXE",
            Some(r"C:\Windows\svchost.exe")
        ));
        assert!(is_masquerade(
            &r,
            "lsass.exe",
            Some(r"C:\Windows\System32\drivers\lsass.exe")
        ));
        // explorer.exe は System32 に置かれていたらおかしい
        assert!(is_masquerade(
            &r,
            "explorer.exe",
            Some(r"C:\Windows\System32\explorer.exe")
        ));
        assert!(is_masquerade(
            &r,
            "explorer.exe",
            Some(r"C:\Temp\explorer.exe")
        ));
    }

    #[test]
    fn masquerade_false_cases() {
        let r = win_roots();
        assert!(!is_masquerade(
            &r,
            "svchost.exe",
            Some(r"C:\Windows\System32\svchost.exe")
        ));
        assert!(!is_masquerade(
            &r,
            "svchost.exe",
            Some(r"\\?\C:\WINDOWS\SysWOW64\svchost.exe")
        ));
        // explorer.exe の例外
        assert!(!is_masquerade(
            &r,
            "explorer.exe",
            Some(r"C:\Windows\explorer.exe")
        ));
        // 表に無い名前
        assert!(!is_masquerade(
            &r,
            "notepad.exe",
            Some(r"C:\Users\Alice\notepad.exe")
        ));
        // パスが取れないものは判定しない
        assert!(!is_masquerade(&r, "svchost.exe", None));
        // Linux では常に false
        let linux = Roots::new(Os::Linux, &["/tmp"], None);
        assert!(!is_masquerade(
            &linux,
            "svchost.exe",
            Some("/tmp/svchost.exe")
        ));
    }

    #[test]
    fn masquerade_follows_system_root() {
        let r = Roots::new(Os::Windows, &[], Some(r"D:\WinNT"));
        assert!(!is_masquerade(
            &r,
            "csrss.exe",
            Some(r"D:\WinNT\System32\csrss.exe")
        ));
        assert!(is_masquerade(
            &r,
            "csrss.exe",
            Some(r"C:\Windows\System32\csrss.exe")
        ));
    }

    #[test]
    fn descendants_are_excluded() {
        let list = vec![
            info(1, None, Some(10)),
            info(100, Some(1), Some(100)), // 根
            info(101, Some(100), Some(110)),
            info(102, Some(101), Some(120)),
            info(200, Some(1), Some(130)), // 無関係
        ];
        let kept: Vec<u32> = without_descendants(&list, &[(100, 100)])
            .iter()
            .map(|p| p.pid)
            .collect();
        assert_eq!(kept, vec![1, 200]);
    }

    #[test]
    fn reused_root_pid_excludes_nothing() {
        // 記録した調査プロセス（PID 100、起動時刻 100）は終わっていて、
        // 同じ PID を別のプロセスが後から使っている
        let list = vec![
            info(100, Some(1), Some(900)),
            info(101, Some(100), Some(910)),
        ];
        assert_eq!(without_descendants(&list, &[(100, 100)]).len(), 2);
        // 一覧に根がいなくても同じ
        assert_eq!(without_descendants(&list, &[(555, 100)]).len(), 2);
    }

    #[test]
    fn reused_parent_pid_is_not_followed() {
        // 子 102 の ppid は 101 だが、101 は子より後に起動している。
        // 本当の親は終了済みで、PID 101 が再利用されたとみなす
        let list = vec![
            info(100, Some(1), Some(100)),
            info(101, Some(100), Some(500)),
            info(102, Some(101), Some(200)),
            info(103, Some(101), Some(600)),
        ];
        let kept: Vec<u32> = without_descendants(&list, &[(100, 100)])
            .iter()
            .map(|p| p.pid)
            .collect();
        assert_eq!(kept, vec![102]);
    }

    #[test]
    fn unknown_start_time_is_not_followed() {
        let list = vec![
            info(100, Some(1), Some(100)),
            info(101, Some(100), None),
            info(102, Some(100), Some(150)),
        ];
        let kept: Vec<u32> = without_descendants(&list, &[(100, 100)])
            .iter()
            .map(|p| p.pid)
            .collect();
        assert_eq!(kept, vec![101]);
        // 根自身の起動時刻が不明なら生存を確かめられない
        let list = vec![info(100, Some(1), None), info(101, Some(100), Some(1))];
        assert_eq!(without_descendants(&list, &[(100, 0)]).len(), 2);
    }

    #[test]
    fn parent_cycles_terminate() {
        let list = vec![info(100, Some(101), Some(5)), info(101, Some(100), Some(5))];
        assert!(without_descendants(&list, &[(100, 5)]).is_empty());
    }

    #[test]
    fn glob_basics() {
        assert!(glob_match("abc", "abc"));
        assert!(glob_match("ABC", "abc"));
        assert!(!glob_match("abc", "abcd"));
        assert!(glob_match("*", ""));
        assert!(glob_match("a*c", "abbbc"));
        assert!(!glob_match("a*c", "abbbd"));
        assert!(glob_match("*.exe", r"c:\x\y.exe"));
        assert!(glob_match("a**b", "ab"));
        // バックトラックが要る形
        assert!(glob_match("*ab*ab", "xabyabzab"));
        assert!(!glob_match("*ab*ab", "xabyaxb"));
    }

    #[test]
    fn glob_crosses_separators_and_matches_normalized_paths() {
        let path = norm(
            Os::Windows,
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2409.6-0\MsMpEng.exe",
        );
        assert_eq!(
            path,
            r"c:\programdata\microsoft\windows defender\platform\*\msmpeng.exe"
        );
        assert!(glob_match(
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\*\MsMpEng.exe",
            &path
        ));
        assert!(glob_match(
            r"c:\users\*\documents\projects\*\target\*",
            r"c:\users\alice\documents\projects\github.com\a\target\debug\a.exe"
        ));
    }
}
