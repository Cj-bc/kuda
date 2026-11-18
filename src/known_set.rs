//! プロセスの識別と分類。
//!
//! 識別・フラグ判定・除外・glob は純関数で、環境変数や実行中の OS は関数の中で読まない。
//! 呼び出し側が [`Os`] と [`Roots`] を渡す。こうしておくと、Windows のパス規則のテストを
//! Linux 上でも走らせられる。ストアを使う分類は [`classify`]。

use crate::config::ProcessSpec;
use crate::metrics::{self, Variables};
use crate::os::Os;
use crate::probe::ProcessInfo;
use crate::store::{IdentityStatus, Store};
use anyhow::Result;
use std::collections::{BTreeMap, HashMap, HashSet};

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

/// 自プロセスを `without_descendants` の根にするための (PID, 起動時刻)。
/// 起動時刻は列挙結果から自 PID を引いて得る。見つからなければ除外できない
pub fn own_root(processes: &[ProcessInfo]) -> Option<(u32, i64)> {
    let pid = std::process::id();
    processes
        .iter()
        .find(|p| p.pid == pid)
        .and_then(|p| p.started.map(|started| (pid, started)))
}

/// 1 回の probe で報告対象（pending）になった識別キーと、その代表のプロセス
#[derive(Debug, Clone, PartialEq)]
pub struct PendingProcess {
    pub identity: Identity,
    /// 同じ識別キーのプロセスのうち、PID が最小のもの
    pub process: ProcessInfo,
    pub user_writable: bool,
    pub masquerade: bool,
}

/// 分類の結果。ストアには `record` を呼ぶまで書かない
/// （異常と判定されたとき、学習しない形でやり直すため）
#[derive(Debug, Clone, PartialEq)]
pub struct Classification {
    /// unknown / unknown_user_writable / masquerade / missing / process_count
    pub metrics: Variables,
    /// 今 動いている pending。事件の証拠にする
    pub pending: Vec<PendingProcess>,
    /// 新しく known として登録する識別キーの数
    pub learned: usize,
    /// 今回見た識別キーと、新規のときに登録する status
    seen: Vec<(String, IdentityStatus)>,
}

impl Classification {
    pub fn pending_identities(&self) -> Vec<String> {
        self.pending
            .iter()
            .map(|p| p.identity.key.clone())
            .collect()
    }

    /// 今回見た識別キーを記録する。学習期間の起点もここで決まる
    pub fn record(&self, store: &mut Store, watch: &str, now: i64) -> Result<()> {
        store.start_learning(watch, now)?;
        store.observe_identities(watch, now, &self.seen)
    }
}

/// 識別キーごとにまとめた、今 動いているプロセス
struct Observed<'a> {
    identity: Identity,
    process: &'a ProcessInfo,
    user_writable: bool,
    masquerade: bool,
}

/// 動いているプロセスを既知の集合と照らして分類する。ストアは読むだけ。
///
/// `learn` が true で学習期間中なら、新しく見た識別キーを known にする（masquerade を除く）。
/// それ以外の新しい識別キーは pending にする。`excluded` は kuda 自身と調査プロセスの根
#[allow(clippy::too_many_arguments)]
pub fn classify(
    store: &Store,
    watch: &str,
    spec: &ProcessSpec,
    processes: &[ProcessInfo],
    excluded: &[(u32, i64)],
    roots: &Roots,
    now: i64,
    learn: bool,
) -> Result<Classification> {
    let os = roots.os;
    let mut observed: BTreeMap<String, Observed> = BTreeMap::new();
    for process in without_descendants(processes, excluded) {
        let Some(identity) = identify(os, process) else {
            continue;
        };
        if spec.ignore.iter().any(|g| glob_match(g, &identity.key)) {
            continue;
        }
        let path = process.path.as_deref();
        let masquerade = is_masquerade(roots, &process.name, path);
        let user_writable = path.is_some_and(|p| is_user_writable(roots, p));
        let entry = observed
            .entry(identity.key.clone())
            .or_insert_with(|| Observed {
                identity,
                process,
                user_writable,
                masquerade,
            });
        // 代表は PID が最小のもの。列挙の順序に結果を依存させない
        if process.pid < entry.process.pid {
            entry.process = process;
        }
        entry.masquerade |= masquerade;
    }

    let started = store.learning_started(watch)?.unwrap_or(now);
    let learning = now < started.saturating_add(spec.learn_for.as_secs() as i64);
    let statuses = store.identity_statuses(watch)?;

    let mut seen = Vec::new();
    let mut pending = Vec::new();
    let mut learned = 0;
    for (key, o) in &observed {
        let status = match statuses.get(key) {
            Some(status) => *status,
            // 偽装は、学習期間中でも正常として覚えない
            None if learn && learning && !o.masquerade => {
                learned += 1;
                IdentityStatus::Known
            }
            None => IdentityStatus::Pending,
        };
        seen.push((key.clone(), status));
        if status == IdentityStatus::Pending {
            pending.push(PendingProcess {
                identity: o.identity.clone(),
                process: o.process.clone(),
                user_writable: o.user_writable,
                masquerade: o.masquerade,
            });
        }
    }

    let count = |f: fn(&PendingProcess) -> bool| pending.iter().filter(|p| f(p)).count() as f64;
    let missing = spec
        .expected
        .iter()
        .filter(|g| !observed.keys().any(|key| glob_match(g, key)))
        .count();
    let mut metrics = Variables::new();
    metrics.insert(metrics::UNKNOWN.to_string(), pending.len() as f64);
    metrics.insert(
        metrics::UNKNOWN_USER_WRITABLE.to_string(),
        count(|p| p.user_writable),
    );
    metrics.insert(metrics::MASQUERADE.to_string(), count(|p| p.masquerade));
    metrics.insert(metrics::MISSING.to_string(), missing as f64);
    metrics.insert(metrics::PROCESS_COUNT.to_string(), observed.len() as f64);
    Ok(Classification {
        metrics,
        pending,
        learned,
        seen,
    })
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

    // ---- classify ----

    use std::time::Duration;

    const DAY: i64 = 86_400;

    fn watch(expected: &[&str], ignore: &[&str]) -> ProcessSpec {
        ProcessSpec {
            expected: expected.iter().map(|s| s.to_string()).collect(),
            ignore: ignore.iter().map(|s| s.to_string()).collect(),
            learn_for: Duration::from_secs(7 * 86_400),
        }
    }

    use crate::testutil::process as proc;

    const NOTEPAD: &str = r"C:\Windows\System32\notepad.exe";
    const DROPPER: &str = r"C:\Users\Alice\AppData\Local\Temp\x.exe";
    const FAKE_SVCHOST: &str = r"C:\Users\Alice\svchost.exe";

    /// 分類して、ストアに記録する
    fn observe(
        store: &mut Store,
        spec: &ProcessSpec,
        processes: &[ProcessInfo],
        now: i64,
        learn: bool,
    ) -> Classification {
        let c = classify(store, "w", spec, processes, &[], &win_roots(), now, learn).unwrap();
        c.record(store, "w", now).unwrap();
        c
    }

    fn metric(c: &Classification, name: &str) -> f64 {
        c.metrics[name]
    }

    fn status(store: &Store, key: &str) -> Option<IdentityStatus> {
        store.identity_statuses("w").unwrap().get(key).copied()
    }

    /// classify が出す指標は、process の条件式で使える変数として許可リストに載っている
    #[test]
    fn classification_metrics_are_listed_for_process_watches() {
        let mut store = Store::in_memory().unwrap();
        let w = watch(&[], &[]);
        let procs = [proc(10, "notepad.exe", Some(NOTEPAD))];
        let c = observe(&mut store, &w, &procs, 1000, true);
        let available = crate::metrics::variables_for(crate::config::ProbeKind::Process);
        assert_eq!(c.metrics.len(), 5, "{:?}", c.metrics);
        for name in c.metrics.keys() {
            assert!(available.contains(&name.as_str()), "{name}");
        }
    }

    #[test]
    fn everything_seen_while_learning_is_known() {
        let mut store = Store::in_memory().unwrap();
        let w = watch(&[], &[]);
        let procs = [proc(10, "notepad.exe", Some(NOTEPAD))];
        let c = observe(&mut store, &w, &procs, 1000, true);
        assert_eq!(metric(&c, "unknown"), 0.0);
        assert_eq!(metric(&c, "process_count"), 1.0);
        assert_eq!(c.learned, 1);
        assert_eq!(
            status(&store, r"c:\windows\system32\notepad.exe"),
            Some(IdentityStatus::Known)
        );
    }

    #[test]
    fn new_identities_after_the_learning_period_are_pending() {
        let mut store = Store::in_memory().unwrap();
        let w = watch(&[], &[]);
        let notepad = proc(10, "notepad.exe", Some(NOTEPAD));
        observe(&mut store, &w, std::slice::from_ref(&notepad), 1000, true);
        // 起点は最初の probe。ちょうど 7 日後で期間は終わる
        let end = 1000 + 7 * DAY;
        let procs = [notepad.clone(), proc(11, "x.exe", Some(DROPPER))];
        let c = observe(&mut store, &w, &procs, end - 1, true);
        assert_eq!(metric(&c, "unknown"), 0.0, "期間内は学習する");
        let procs = [notepad, proc(12, "y.exe", Some(r"C:\Users\Alice\y.exe"))];
        let c = observe(&mut store, &w, &procs, end, true);
        assert_eq!(metric(&c, "unknown"), 1.0);
        assert_eq!(metric(&c, "unknown_user_writable"), 1.0);
        assert_eq!(c.pending.len(), 1);
        assert_eq!(c.pending[0].process.pid, 12);
        assert_eq!(c.learned, 0);
    }

    #[test]
    fn shortening_learn_for_ends_the_period_and_keeps_the_set() {
        let mut store = Store::in_memory().unwrap();
        let mut w = watch(&[], &[]);
        let notepad = proc(10, "notepad.exe", Some(NOTEPAD));
        observe(&mut store, &w, std::slice::from_ref(&notepad), 1000, true);
        w.learn_for = Duration::from_secs(60);
        let procs = [notepad, proc(11, "x.exe", Some(DROPPER))];
        let c = observe(&mut store, &w, &procs, 1100, true);
        assert_eq!(metric(&c, "unknown"), 1.0);
    }

    #[test]
    fn masquerade_is_not_learned_as_normal() {
        let mut store = Store::in_memory().unwrap();
        let w = watch(&[], &[]);
        let procs = [
            proc(10, "notepad.exe", Some(NOTEPAD)),
            proc(11, "svchost.exe", Some(FAKE_SVCHOST)),
        ];
        let c = observe(&mut store, &w, &procs, 1000, true);
        assert_eq!(metric(&c, "masquerade"), 1.0);
        assert_eq!(metric(&c, "unknown"), 1.0);
        assert_eq!(c.learned, 1);
        assert_eq!(
            status(&store, r"c:\users\alice\svchost.exe"),
            Some(IdentityStatus::Pending)
        );
    }

    #[test]
    fn nothing_is_learned_when_learning_is_not_allowed() {
        let mut store = Store::in_memory().unwrap();
        let w = watch(&[], &[]);
        let procs = [proc(10, "notepad.exe", Some(NOTEPAD))];
        let c = observe(&mut store, &w, &procs, 1000, false);
        assert_eq!(metric(&c, "unknown"), 1.0);
        assert_eq!(c.learned, 0);
        // pending の登録は行う。学習の再開後も、登録済みの status は変わらない
        let c = observe(&mut store, &w, &procs, 1300, true);
        assert_eq!(metric(&c, "unknown"), 1.0);
        assert_eq!(store.identity_statuses("w").unwrap().len(), 1);
    }

    #[test]
    fn reported_identities_are_not_counted_and_stay_reported() {
        let mut store = Store::in_memory().unwrap();
        let w = watch(&[], &[]);
        observe(&mut store, &w, &[], 1000, true);
        let procs = [proc(11, "x.exe", Some(DROPPER))];
        let c = observe(&mut store, &w, &procs, 1000 + 8 * DAY, true);
        assert_eq!(metric(&c, "unknown"), 1.0);
        store.mark_reported("w", &c.pending_identities()).unwrap();
        let c = observe(&mut store, &w, &procs, 1000 + 9 * DAY, true);
        assert_eq!(metric(&c, "unknown"), 0.0);
        assert!(c.pending.is_empty());
        assert_eq!(metric(&c, "process_count"), 1.0);
        assert_eq!(
            status(&store, r"c:\users\alice\appdata\local\temp\x.exe"),
            Some(IdentityStatus::Reported)
        );
    }

    #[test]
    fn pending_remains_until_reported() {
        // 抑制中は事件を作らず mark_reported も呼ばないので、次の回も pending のまま数える
        let mut store = Store::in_memory().unwrap();
        let w = watch(&[], &[]);
        observe(&mut store, &w, &[], 1000, true);
        let procs = [proc(11, "x.exe", Some(DROPPER))];
        for hours in [200, 201, 202] {
            let c = observe(&mut store, &w, &procs, 1000 + hours * 3600, true);
            assert_eq!(metric(&c, "unknown"), 1.0);
        }
    }

    #[test]
    fn expected_ignore_and_exclusions() {
        let mut store = Store::in_memory().unwrap();
        let w = watch(
            &[r"c:\windows\system32\notepad.exe", r"c:\nothing\*"],
            &[r"c:\users\*\target\*"],
        );
        let mut kuda = proc(100, "kuda.exe", Some(r"C:\kuda\kuda.exe"));
        kuda.started = Some(5);
        let mut child = proc(101, "git.exe", Some(r"C:\git\git.exe"));
        child.ppid = Some(100);
        child.started = Some(6);
        let procs = [
            proc(10, "notepad.exe", Some(NOTEPAD)),
            proc(11, "a.exe", Some(r"C:\Users\Alice\target\a.exe")),
            kuda,
            child,
            proc(12, "svc", None),
        ];
        let c = classify(
            &store,
            "w",
            &w,
            &procs,
            &[(100, 5)],
            &win_roots(),
            1000,
            true,
        )
        .unwrap();
        c.record(&mut store, "w", 1000).unwrap();
        // ignore と kuda 自身（と子孫）は数えない。パスの無いプロセスは name: キーになる
        assert_eq!(metric(&c, "process_count"), 2.0);
        assert_eq!(metric(&c, "missing"), 1.0);
        assert_eq!(status(&store, "name:svc"), Some(IdentityStatus::Known));
        assert_eq!(status(&store, r"c:\users\alice\target\a.exe"), None);
        assert_eq!(status(&store, r"c:\kuda\kuda.exe"), None);
        assert_eq!(status(&store, r"c:\git\git.exe"), None);
    }

    #[test]
    fn instances_share_one_identity() {
        let mut store = Store::in_memory().unwrap();
        let w = watch(&[], &[]);
        observe(&mut store, &w, &[], 1000, true);
        let procs = [
            proc(30, "x.exe", Some(DROPPER)),
            proc(20, "x.exe", Some(DROPPER)),
        ];
        let c = observe(&mut store, &w, &procs, 1000 + 8 * DAY, true);
        assert_eq!(metric(&c, "unknown"), 1.0);
        assert_eq!(c.pending[0].process.pid, 20);
    }

    #[test]
    fn own_root_finds_this_process() {
        let me = std::process::id();
        let mut p = proc(me, "kuda", None);
        p.started = Some(42);
        assert_eq!(own_root(&[proc(me + 1, "x", None), p]), Some((me, 42)));
        let mut unknown_start = proc(me, "kuda", None);
        unknown_start.started = None;
        assert_eq!(own_root(&[unknown_start]), None);
    }
}
