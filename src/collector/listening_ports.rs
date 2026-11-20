//! 待ち受けている TCP/UDP のポートと、それを持つプロセス。
//!
//! 外部コマンド（netstat、ss）は使わない。Windows は IP Helper、Linux は /proc を読む。

use crate::investigation;
use crate::known_set;
use crate::os::Os;
use crate::paths::Paths;
use crate::probe::{self, ProcessInfo};
use anyhow::{Context, Result};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::IpAddr;
use std::ops::RangeInclusive;

/// 一時ポートの番号の一覧。証拠としては残すが、毎回変わるので差分では比べない
pub(super) const VOLATILE_KEYS: &[&str] = &["ephemeral_ports"];

/// 待ち受けの 1 件。UDP は接続を持たないので、束縛されたソケットを待ち受けとみなす
#[derive(Debug, Clone, PartialEq, Eq)]
struct Listener {
    proto: &'static str,
    addr: IpAddr,
    port: u16,
    /// IPv6 のスコープ（インターフェース）。リンクローカルのアドレスはインターフェースごとに
    /// 同じでありうるので、区別に要る。無ければ 0。Linux の /proc/net には載っていない
    scope: u32,
    /// 持ち主。Linux では 1 つのソケットを複数のプロセスが持ちうる（ソケット起動など）。
    /// 空なら持ち主を引けなかった
    pids: Vec<u32>,
}

impl Listener {
    /// UDP は待ち受けと、クライアントが送信のために束縛しただけのソケットを区別できない。
    /// 後者は一時ポートを使い、番号が毎回変わる
    fn is_ephemeral(&self, ephemeral: &RangeInclusive<u16>) -> bool {
        self.proto == "udp" && ephemeral.contains(&self.port)
    }

    /// `tcp:0.0.0.0:80`、`udp:[::]:53`。IPv6 は括弧で囲み、ポートと区切れるようにする。
    /// 一時ポートの UDP は番号の代わりに `ephemeral` とまとめ、番号は `ephemeral_ports` に残す
    fn key(&self, ephemeral: &RangeInclusive<u16>) -> String {
        let port = if self.is_ephemeral(ephemeral) {
            "ephemeral".to_string()
        } else {
            self.port.to_string()
        };
        match self.addr {
            IpAddr::V4(addr) => format!("{}:{addr}:{port}", self.proto),
            IpAddr::V6(addr) if self.scope != 0 => {
                format!("{}:[{addr}%{}]:{port}", self.proto, self.scope)
            }
            IpAddr::V6(addr) => format!("{}:[{addr}]:{port}", self.proto),
        }
    }
}

pub fn collect(paths: &Paths) -> Result<Value> {
    // 持ち主を引けないと、全部が unknown に変わった差分が出て、それが比較の基準にも残る。
    // それより、この collector を失敗にする
    let enumerate = || probe::enumerate().context("cannot enumerate processes");
    // 表を読む前と後に列挙し、両方に同じ起動時刻でいた PID だけを持ち主として信じる。
    // 間に PID が再利用されると、ソケットを別のプロセスのものとしてしまうため
    let before = enumerate()?;
    let listeners = imp::listeners()?;
    let processes = enumerate()?;
    let listeners = only_stable_owners(listeners, &stable_pids(Os::current(), &before, &processes));
    let excluded = excluded_pids(
        &processes,
        &investigation::excluded_roots(paths, &processes),
    );
    let listeners = without_excluded(listeners, &excluded);
    let identities = identities(Os::current(), &processes);
    Ok(render(&listeners, &identities, &imp::ephemeral_ports()))
}

/// 2 回の列挙のどちらにも、同じ起動時刻でいた PID。
/// Windows の保護プロセスなど起動時刻を読めないものは、名前とパスが同じなら同じとみなす
/// （そうしないと、システムのサービスの待ち受けがすべて持ち主不明になる）
fn stable_pids(os: Os, before: &[ProcessInfo], after: &[ProcessInfo]) -> HashSet<u32> {
    after
        .iter()
        .filter(|p| {
            before.iter().any(|q| {
                q.pid == p.pid
                    && match q.started {
                        Some(started) => probe::same_start(os, started, p.started),
                        None => p.started.is_none() && q.name == p.name && q.path == p.path,
                    }
            })
        })
        .map(|p| p.pid)
        .collect()
}

/// 確かめられなかった持ち主を外す。全員が外れた待ち受けは、持ち主の分からないものとして残す
fn only_stable_owners(listeners: Vec<Listener>, stable: &HashSet<u32>) -> Vec<Listener> {
    listeners
        .into_iter()
        .map(|mut l| {
            l.pids.retain(|pid| stable.contains(pid));
            l
        })
        .collect()
}

/// kuda 自身と調査プロセス（と子孫）の PID。processes collector や分類と同じく、
/// それらの待ち受けは入れない
fn excluded_pids(processes: &[ProcessInfo], roots: &[(u32, i64)]) -> HashSet<u32> {
    let kept: HashSet<u32> = known_set::without_descendants(Os::current(), processes, roots)
        .iter()
        .map(|p| p.pid)
        .collect();
    processes
        .iter()
        .map(|p| p.pid)
        .filter(|pid| !kept.contains(pid))
        .collect()
}

/// 除外対象の持ち主を外す。持ち主がすべて除外対象の待ち受けは丸ごと除く。
/// 除外対象と共有しているソケットに除外対象を残すと、調査が動いているかどうかで差分が変わる。
/// 持ち主の分からないものは残す
fn without_excluded(listeners: Vec<Listener>, excluded: &HashSet<u32>) -> Vec<Listener> {
    listeners
        .into_iter()
        .filter_map(|mut l| {
            if l.pids.is_empty() {
                return Some(l);
            }
            l.pids.retain(|pid| !excluded.contains(pid));
            (!l.pids.is_empty()).then_some(l)
        })
        .collect()
}

fn identities(os: Os, processes: &[ProcessInfo]) -> HashMap<u32, String> {
    processes
        .iter()
        .filter_map(|p| Some((p.pid, known_set::identify(os, p)?.key)))
        .collect()
}

/// `{ "<proto:addr:port>": { "processes": ["<identity>", ...] } }`。
/// PID は毎回変わるので入れず、持ち主は識別キーで示す。一時ポートの UDP には、
/// どの持ち主がどの番号を使っていたかを `ephemeral_ports: { "<identity>": [port, ...] }` で添える
fn render(
    listeners: &[Listener],
    identities: &HashMap<u32, String>,
    ephemeral: &RangeInclusive<u16>,
) -> Value {
    type Ports = BTreeMap<String, BTreeSet<u16>>;
    let mut owners: BTreeMap<String, (BTreeSet<String>, Ports)> = BTreeMap::new();
    for listener in listeners {
        let (entry, ports) = owners.entry(listener.key(ephemeral)).or_default();
        let mut known: Vec<String> = listener
            .pids
            .iter()
            .filter_map(|pid| identities.get(pid).cloned())
            .collect();
        // 持ち主が分からない（権限が足りない、列挙の合間に終わった）ことも差分で見えるようにする
        if known.is_empty() {
            known.push("unknown".to_string());
        }
        if listener.is_ephemeral(ephemeral) {
            for owner in &known {
                ports
                    .entry(owner.clone())
                    .or_default()
                    .insert(listener.port);
            }
        }
        entry.extend(known);
    }
    let map: Map<String, Value> = owners
        .into_iter()
        .map(|(key, (owners, ports))| {
            let value = if ports.is_empty() {
                json!({ "processes": owners })
            } else {
                json!({ "processes": owners, "ephemeral_ports": ports })
            };
            (key, value)
        })
        .collect();
    Value::Object(map)
}

#[cfg(windows)]
mod imp {
    use super::Listener;
    use anyhow::{Result, bail};
    use std::ffi::c_void;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
        MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID,
        MIB_UDP6TABLE_OWNER_PID, MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID,
        TCP_TABLE_OWNER_PID_LISTENER, UDP_TABLE_OWNER_PID,
    };
    use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

    /// ポートはネットワークバイトオーダーで、下位 16 ビットに入っている
    fn port(raw: u32) -> u16 {
        u16::from_be(raw as u16)
    }

    /// 表を取る。取得の間に件数が増えると足りなくなるので、数回やり直す。
    /// 8 バイト境界の領域に確保するのは、表の先頭が u32 の件数で、行が u32 だけでできているため
    fn table(fetch: impl Fn(*mut c_void, &mut u32) -> u32) -> Result<Vec<u64>> {
        let mut buffer: Vec<u64> = vec![0; 512];
        for _ in 0..4 {
            let mut size = (buffer.len() * 8) as u32;
            let status = fetch(buffer.as_mut_ptr().cast::<c_void>(), &mut size);
            if status == NO_ERROR.0 {
                return Ok(buffer);
            }
            if status != ERROR_INSUFFICIENT_BUFFER.0 {
                bail!("GetExtended*Table failed: {status}");
            }
            // 件数の増加に備えて余裕を持つ
            buffer = vec![0; (size as usize + 1024).div_ceil(8)];
        }
        bail!("the table kept growing")
    }

    /// 成功した表の行
    macro_rules! rows {
        ($buffer:expr, $table:ty, $row:ty) => {{
            let table = $buffer.as_ptr().cast::<$table>();
            // SAFETY: 成功した呼び出しが buffer に書いた表を指す。行は先頭の件数のあとに並ぶ
            unsafe {
                let count = (*table).dwNumEntries as usize;
                std::slice::from_raw_parts((*table).table.as_ptr().cast::<$row>(), count)
            }
        }};
    }

    pub fn listeners() -> Result<Vec<Listener>> {
        let mut found = Vec::new();

        let v4 = AF_INET.0 as u32;
        let v6 = AF_INET6.0 as u32;

        let buffer = table(|pointer, size| unsafe {
            GetExtendedTcpTable(
                Some(pointer),
                size,
                false,
                v4,
                TCP_TABLE_OWNER_PID_LISTENER,
                0,
            )
        })?;
        for row in rows!(buffer, MIB_TCPTABLE_OWNER_PID, MIB_TCPROW_OWNER_PID) {
            found.push(Listener {
                proto: "tcp",
                addr: IpAddr::V4(Ipv4Addr::from(u32::from_be(row.dwLocalAddr))),
                port: port(row.dwLocalPort),
                scope: 0,
                pids: vec![row.dwOwningPid],
            });
        }

        let buffer = table(|pointer, size| unsafe {
            GetExtendedTcpTable(
                Some(pointer),
                size,
                false,
                v6,
                TCP_TABLE_OWNER_PID_LISTENER,
                0,
            )
        })?;
        for row in rows!(buffer, MIB_TCP6TABLE_OWNER_PID, MIB_TCP6ROW_OWNER_PID) {
            found.push(Listener {
                proto: "tcp",
                addr: IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr)),
                port: port(row.dwLocalPort),
                scope: row.dwLocalScopeId,
                pids: vec![row.dwOwningPid],
            });
        }

        let buffer = table(|pointer, size| unsafe {
            GetExtendedUdpTable(Some(pointer), size, false, v4, UDP_TABLE_OWNER_PID, 0)
        })?;
        for row in rows!(buffer, MIB_UDPTABLE_OWNER_PID, MIB_UDPROW_OWNER_PID) {
            found.push(Listener {
                proto: "udp",
                addr: IpAddr::V4(Ipv4Addr::from(u32::from_be(row.dwLocalAddr))),
                port: port(row.dwLocalPort),
                scope: 0,
                pids: vec![row.dwOwningPid],
            });
        }

        let buffer = table(|pointer, size| unsafe {
            GetExtendedUdpTable(Some(pointer), size, false, v6, UDP_TABLE_OWNER_PID, 0)
        })?;
        for row in rows!(buffer, MIB_UDP6TABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID) {
            found.push(Listener {
                proto: "udp",
                addr: IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr)),
                port: port(row.dwLocalPort),
                scope: row.dwLocalScopeId,
                pids: vec![row.dwOwningPid],
            });
        }
        Ok(found)
    }

    /// Windows Vista 以降の既定の動的ポート範囲。`netsh` で変えられるが、読むには
    /// 外部コマンドが要るので既定値を使う
    pub fn ephemeral_ports() -> std::ops::RangeInclusive<u16> {
        49152..=65535
    }
}

#[cfg(unix)]
mod imp {
    use super::{Listener, parse_port_range, parse_proc_net};
    use anyhow::{Context, Result};
    use std::collections::HashMap;
    use std::fs;
    use std::io::ErrorKind;

    /// 読めなければ Linux の既定値
    pub fn ephemeral_ports() -> std::ops::RangeInclusive<u16> {
        fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
            .ok()
            .and_then(|text| parse_port_range(&text))
            .unwrap_or(32768..=60999)
    }

    /// /proc/net の 4 つの表。(ファイル, プロトコル, 待ち受けを表す状態, IPv6 か)。
    /// TCP は LISTEN（0A）、UDP は束縛されただけで接続していない（07）
    const TABLES: [(&str, &str, &str, bool); 4] = [
        ("/proc/net/tcp", "tcp", "0A", false),
        ("/proc/net/tcp6", "tcp", "0A", true),
        ("/proc/net/udp", "udp", "07", false),
        ("/proc/net/udp6", "udp", "07", true),
    ];

    pub fn listeners() -> Result<Vec<Listener>> {
        let owners = socket_owners();
        let mut found = Vec::new();
        for (path, proto, state, v6) in TABLES {
            let text = match fs::read_to_string(path) {
                Ok(text) => text,
                // IPv6 が無効なホストでは tcp6 / udp6 が無い
                Err(error) if v6 && error.kind() == ErrorKind::NotFound => continue,
                // 一部の表だけで成功させると、読めなかった表の待ち受けが消えたように見え、
                // しかもそれが比較の基準として残る。それより、この collector を失敗にする
                Err(error) => return Err(error).with_context(|| format!("cannot read {path}")),
            };
            for (addr, port, inode) in parse_proc_net(&text, state, v6) {
                found.push(Listener {
                    proto,
                    addr,
                    port,
                    scope: 0,
                    pids: owners.get(&inode).cloned().unwrap_or_default(),
                });
            }
        }
        Ok(found)
    }

    /// ソケットの inode から持ち主の PID を引く。他のユーザーのプロセスの fd は読めないので、
    /// 引けないソケットがあってよい（そのときの持ち主は unknown になる）。
    /// 1 つのソケットを複数のプロセスが持つこと（ソケット起動、fork した子）があるので、全員を返す
    fn socket_owners() -> HashMap<u64, Vec<u32>> {
        let mut owners = HashMap::new();
        let Ok(entries) = fs::read_dir("/proc") else {
            return owners;
        };
        for entry in entries.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<u32>().ok())
            else {
                continue;
            };
            let Ok(fds) = fs::read_dir(entry.path().join("fd")) else {
                continue;
            };
            for fd in fds.flatten() {
                let Ok(target) = fs::read_link(fd.path()) else {
                    continue;
                };
                let target = target.to_string_lossy();
                if let Some(inode) = target
                    .strip_prefix("socket:[")
                    .and_then(|rest| rest.strip_suffix(']'))
                    .and_then(|inode| inode.parse().ok())
                {
                    owners.entry(inode).or_default().push(pid);
                }
            }
        }
        owners
    }
}

/// `ip_local_port_range` の「下限 上限」
#[cfg(any(unix, test))]
fn parse_port_range(text: &str) -> Option<RangeInclusive<u16>> {
    let mut parts = text.split_whitespace().map(str::parse::<u16>);
    let (low, high) = (parts.next()?.ok()?, parts.next()?.ok()?);
    (low <= high).then_some(low..=high)
}

/// /proc/net/{tcp,tcp6,udp,udp6} のうち、状態が `state` の行から (アドレス, ポート, inode) を取る。
/// アドレスはホストのバイト順（x86/ARM ではリトルエンディアン）の 16 進数。
/// IPv6 は 32 ビットの語を 4 つ並べた形で、語ごとに同じ並びになる
#[cfg(any(unix, test))]
fn parse_proc_net(text: &str, state: &str, v6: bool) -> Vec<(IpAddr, u16, u64)> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            // sl local rem st tx:rx tr:when retrnsmt uid timeout inode
            if *fields.get(3)? != state {
                return None;
            }
            let (addr, port) = fields.get(1)?.split_once(':')?;
            let addr = if v6 {
                if addr.len() != 32 || !addr.is_ascii() {
                    return None;
                }
                let mut bytes = [0u8; 16];
                for i in 0..4 {
                    let word = u32::from_str_radix(&addr[i * 8..i * 8 + 8], 16).ok()?;
                    bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
                }
                IpAddr::V6(std::net::Ipv6Addr::from(bytes))
            } else {
                let word = u32::from_str_radix(addr, 16).ok()?;
                IpAddr::V4(std::net::Ipv4Addr::from(word.swap_bytes()))
            };
            let port = u16::from_str_radix(port, 16).ok()?;
            let inode = fields.get(9)?.parse().ok()?;
            Some((addr, port, inode))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{TempDir, process};
    use std::net::{Ipv4Addr, Ipv6Addr};

    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   101        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:9C40 0100007F:0035 01 00000000:00000000 00:00000000 00000000  1000        0 22222 1 0000000000000000 100 0 0 10 0
   2: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 33333 1 0000000000000000 100 0 0 10 0
";

    const TCP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 44444 1 0000000000000000 100 0 0 10 0
";

    #[test]
    fn parses_only_listening_rows() {
        let rows = parse_proc_net(TCP, "0A", false);
        assert_eq!(
            rows,
            [
                (IpAddr::V4(Ipv4Addr::LOCALHOST), 53, 12345),
                (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080, 33333),
            ]
        );
    }

    #[test]
    fn parses_ipv6_addresses() {
        let rows = parse_proc_net(TCP6, "0A", true);
        assert_eq!(rows, [(IpAddr::V6(Ipv6Addr::LOCALHOST), 22, 44444)]);
    }

    fn listener(proto: &'static str, addr: IpAddr, port: u16, pids: &[u32]) -> Listener {
        Listener {
            proto,
            addr,
            port,
            scope: 0,
            pids: pids.to_vec(),
        }
    }

    const EPHEMERAL: RangeInclusive<u16> = 49152..=65535;

    #[test]
    fn keys_and_owners_do_not_depend_on_pid() {
        let v4 = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let v6 = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
        let render_with = |pid: u32| {
            let identities = identities(Os::Linux, &[process(pid, "sshd", Some("/usr/sbin/sshd"))]);
            render(
                &[
                    listener("tcp", v4, 22, &[pid]),
                    listener("tcp", v6, 22, &[pid]),
                    listener("udp", v4, 53, &[9999]),
                ],
                &identities,
                &EPHEMERAL,
            )
        };
        let value = render_with(100);
        assert_eq!(
            value["tcp:0.0.0.0:22"]["processes"],
            json!(["/usr/sbin/sshd"])
        );
        assert_eq!(value["tcp:[::]:22"]["processes"], json!(["/usr/sbin/sshd"]));
        // 持ち主を引けないソケットも載せる
        assert_eq!(value["udp:0.0.0.0:53"]["processes"], json!(["unknown"]));
        // 持ち主の PID が変わっても同じ出力になる
        assert_eq!(value, render_with(200));
    }

    /// クライアントが一時ポートで束縛した UDP は、番号ではなく ephemeral にまとめる。
    /// TCP の待ち受けは、一時ポートの範囲でも番号のまま
    #[test]
    fn ephemeral_udp_ports_are_grouped() {
        let any = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let identities = identities(
            Os::Linux,
            &[
                process(1, "browser", Some("/usr/bin/browser")),
                process(2, "app", Some("/opt/app")),
            ],
        );
        let value = render(
            &[
                listener("udp", any, 50001, &[1]),
                listener("udp", any, 61234, &[2]),
                listener("tcp", any, 50001, &[2]),
            ],
            &identities,
            &EPHEMERAL,
        );
        assert_eq!(
            value["udp:0.0.0.0:ephemeral"]["processes"],
            json!(["/opt/app", "/usr/bin/browser"])
        );
        assert_eq!(value["tcp:0.0.0.0:50001"]["processes"], json!(["/opt/app"]));
        assert_eq!(value.as_object().unwrap().len(), 2);
        // どの持ち主がどの番号を使っていたかは証拠として残すが、差分では比べない
        assert_eq!(
            value["udp:0.0.0.0:ephemeral"]["ephemeral_ports"],
            json!({ "/opt/app": [61234], "/usr/bin/browser": [50001] })
        );
        assert!(crate::collector::is_volatile_key("ephemeral_ports"));
        assert!(value["tcp:0.0.0.0:50001"].get("ephemeral_ports").is_none());
    }

    /// 1 つのソケットを複数のプロセスが持つとき、列挙の順序によらず全員が載る
    #[test]
    fn shared_sockets_list_every_owner() {
        let any = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let identities = identities(
            Os::Linux,
            &[
                process(1, "systemd", Some("/usr/lib/systemd/systemd")),
                process(2, "sshd", Some("/usr/sbin/sshd")),
            ],
        );
        let owners = |pids: &[u32]| {
            render(&[listener("tcp", any, 22, pids)], &identities, &EPHEMERAL)["tcp:0.0.0.0:22"]
                ["processes"]
                .clone()
        };
        let expected = json!(["/usr/lib/systemd/systemd", "/usr/sbin/sshd"]);
        assert_eq!(owners(&[1, 2]), expected);
        assert_eq!(owners(&[2, 1]), expected);
        // 持ち主の一部だけ引けたなら、unknown は付けない
        assert_eq!(owners(&[2, 999]), json!(["/usr/sbin/sshd"]));
    }

    #[test]
    fn parses_the_local_port_range() {
        assert_eq!(parse_port_range("32768\t60999\n"), Some(32768..=60999));
        assert_eq!(parse_port_range("60999 32768"), None);
        assert_eq!(parse_port_range("garbage"), None);
    }

    /// 表を読む間に PID が再利用された持ち主は信じず、持ち主不明として残す
    #[test]
    fn owners_must_be_the_same_process_before_and_after() {
        let any = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let mut sshd = process(22, "sshd", Some("/usr/sbin/sshd"));
        sshd.started = Some(100);
        let mut reused = process(30, "old", Some("/usr/bin/old"));
        reused.started = Some(100);
        let mut replacement = process(30, "new", Some("/usr/bin/new"));
        replacement.started = Some(900);
        // 起動時刻が読めない（保護プロセス）ものは、名前とパスで同じとみなす
        let mut protected = process(4, "svchost.exe", Some(r"C:\Windows\svchost.exe"));
        protected.started = None;

        let before = [sshd.clone(), reused, protected.clone()];
        let after = [sshd, replacement, protected];
        let stable = stable_pids(Os::Linux, &before, &after);
        let kept = only_stable_owners(
            vec![
                listener("tcp", any, 22, &[22]),
                listener("tcp", any, 9999, &[30]),
                listener("tcp", any, 135, &[4]),
            ],
            &stable,
        );
        let owners: Vec<&[u32]> = kept.iter().map(|l| l.pids.as_slice()).collect();
        assert_eq!(owners, [&[22][..], &[], &[4]]);
    }

    /// リンクローカルの同じアドレスでも、インターフェースが違えば別の待ち受け
    #[test]
    fn ipv6_scopes_tell_interfaces_apart() {
        let link_local: IpAddr = "fe80::1".parse().unwrap();
        let on = |scope| Listener {
            scope,
            ..listener("udp", link_local, 546, &[])
        };
        let value = render(&[on(3), on(7)], &HashMap::new(), &EPHEMERAL);
        assert!(value.get("udp:[fe80::1%3]:546").is_some(), "{value}");
        assert!(value.get("udp:[fe80::1%7]:546").is_some(), "{value}");
    }

    /// kuda 自身と調査プロセス（と子孫）だけが持つ待ち受けは載せない
    #[test]
    fn listeners_of_kuda_and_investigations_are_left_out() {
        let any = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let mut kuda = process(100, "kuda", Some("/usr/bin/kuda"));
        kuda.started = Some(5);
        let mut agent = process(101, "claude", Some("/usr/bin/claude"));
        agent.ppid = Some(100);
        agent.started = Some(6);
        let sshd = process(22, "sshd", Some("/usr/sbin/sshd"));
        let excluded = excluded_pids(&[kuda, agent, sshd], &[(100, 5)]);
        let kept = without_excluded(
            vec![
                listener("tcp", any, 9000, &[101]),
                listener("tcp", any, 22, &[22]),
                listener("tcp", any, 8080, &[101, 22]),
                listener("tcp", any, 7000, &[]),
            ],
            &excluded,
        );
        let ports: Vec<u16> = kept.iter().map(|l| l.port).collect();
        assert_eq!(ports, [22, 8080, 7000]);
        // 除外対象と共有していたソケットからは、除外対象の持ち主だけが外れる
        assert_eq!(kept[1].pids, [22]);
    }

    #[test]
    fn collects_from_this_machine() {
        assert!(
            collect(&TempDir::new("listening-ports").paths())
                .unwrap()
                .is_object()
        );
    }
}
