//! 動いているプロセスの一覧。識別キーごとにまとめる。
//!
//! 識別とフラグは kind = "process" の分類と同じ関数（`known_set`）で求める。
//! 判定を二重に書くと、事件の差分と分類で食い違うため。

use crate::investigation;
use crate::known_set::{self, Running};
use crate::paths::Paths;
use crate::probe;
use anyhow::Result;
use serde_json::{Map, Value, json};
use std::collections::BTreeSet;

/// 同じ識別キーで動いている数は、ブラウザやサービスのホストでは絶えず増減する。
/// 証拠としては残すが、差分で比べると毎回の事件に出てしまう
pub(super) const VOLATILE_KEYS: &[&str] = &["instances"];

pub fn collect(paths: &Paths) -> Result<Value> {
    let processes = probe::enumerate()?;
    // kuda 自身と調査プロセス（と子孫）は、分類と同じく入れない
    let excluded = investigation::excluded_roots(paths, &processes);
    let roots = known_set::Roots::from_env();
    Ok(render(&known_set::running(
        &processes,
        &excluded,
        &[],
        &roots,
    )))
}

/// `{ "<identity>": { names, paths, users, instances, flags } }`。
/// PID や起動時刻のように毎回変わる値は入れない。入れると、差分が毎回出てしまう。
/// 名前・パス・ユーザーは同じ識別キーのプロセス全員の値の集合にする。代表の 1 つだけにすると、
/// 代表が終わって別のプロセスに替わったときに、何も起きていないのに差分が出る。
/// `ignore` は collector からは渡らないので、監視から外したパスもここには載る
fn render(running: &Running) -> Value {
    let mut map = Map::new();
    for observed in running.iter() {
        let mut flags = Vec::new();
        if observed.identity.deleted {
            flags.push("deleted");
        }
        if observed.masquerade {
            flags.push("masquerade");
        }
        if observed.user_writable {
            flags.push("user_writable");
        }
        let members = &observed.members;
        let names: BTreeSet<&str> = members.iter().map(|p| p.name.as_str()).collect();
        let paths: BTreeSet<&str> = members.iter().filter_map(|p| p.path.as_deref()).collect();
        let users: BTreeSet<&str> = members.iter().filter_map(|p| p.user.as_deref()).collect();
        map.insert(
            observed.identity.key.clone(),
            json!({
                "names": names,
                "paths": paths,
                "users": users,
                "instances": members.len(),
                "flags": flags,
            }),
        );
    }
    Value::Object(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::known_set::Roots;
    use crate::os::Os;
    use crate::probe::ProcessInfo;
    use crate::testutil::{TempDir, process};

    fn roots() -> Roots {
        Roots::new(Os::Windows, &[r"C:\Users\alice"], Some(r"C:\Windows"))
    }

    fn snapshot(processes: &[ProcessInfo]) -> Value {
        render(&known_set::running(processes, &[], &[], &roots()))
    }

    #[test]
    fn groups_instances_and_sets_flags() {
        let value = snapshot(&[
            process(1, "svchost.exe", Some(r"C:\Windows\System32\svchost.exe")),
            process(2, "svchost.exe", Some(r"C:\Windows\System32\svchost.exe")),
            process(
                3,
                "svchost.exe",
                Some(r"C:\Users\alice\AppData\Local\Temp\svchost.exe"),
            ),
            process(4, "System", None),
        ]);
        let system = &value[r"c:\windows\system32\svchost.exe"];
        assert_eq!(system["instances"], 2);
        assert_eq!(system["flags"], json!([]));
        let fake = &value[r"c:\users\alice\appdata\local\temp\svchost.exe"];
        assert_eq!(fake["flags"], json!(["masquerade", "user_writable"]));
        assert_eq!(value["name:system"]["paths"], json!([]));
    }

    /// 代表（PID 最小）が終わって別のプロセスに替わっても、集合が同じなら出力は同じ
    #[test]
    fn a_new_representative_does_not_change_the_output() {
        let mut root = process(1, "agent", Some(r"C:\Apps\agent.exe"));
        root.user = Some("SYSTEM".to_string());
        let mut alice = process(2, "agent", Some(r"C:\Apps\agent.exe"));
        alice.user = Some("alice".to_string());
        let mut alice_again = alice.clone();
        alice_again.pid = 3;
        let before = snapshot(&[root.clone(), alice.clone()]);
        let after = snapshot(&[alice_again, root]);
        assert_eq!(before, after);
        assert_eq!(
            before[r"c:\apps\agent.exe"]["users"],
            json!(["SYSTEM", "alice"])
        );
    }

    /// PID と起動時刻だけが違う 2 回の列挙は、差分が出ない形でなければならない
    #[test]
    fn differs_only_by_pid_and_start_time_gives_the_same_output() {
        let first = [process(10, "a.exe", Some(r"C:\Apps\a.exe"))];
        let mut second = [process(99, "a.exe", Some(r"C:\Apps\a.exe"))];
        second[0].started = Some(5000);
        assert_eq!(snapshot(&first), snapshot(&second));
    }

    #[test]
    fn collects_from_this_machine() {
        let value = collect(&TempDir::new("processes").paths()).unwrap();
        assert!(!value.as_object().unwrap().is_empty());
    }
}
