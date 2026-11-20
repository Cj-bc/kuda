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

/// `{ "<identity>": { name, path, user, instances, flags } }`。
/// PID や起動時刻のように毎回変わる値は入れない。入れると、差分が毎回出てしまう。
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
        let process = observed.process;
        map.insert(
            observed.identity.key.clone(),
            json!({
                "name": process.name,
                "path": process.path,
                "user": process.user,
                "instances": observed.instances,
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
        assert_eq!(value["name:system"]["path"], Value::Null);
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
