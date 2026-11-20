//! 待ち受けている TCP/UDP のポートと、それを持つプロセス。
//!
//! 外部コマンド（netstat、ss）は使わない。Windows は IP Helper、Linux は /proc を読む。

use crate::known_set;
use crate::os::Os;
use crate::probe::{self, ProcessInfo};
use anyhow::Result;
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;

/// 待ち受けの 1 件。UDP は接続を持たないので、束縛されたソケットを待ち受けとみなす
#[derive(Debug, Clone, PartialEq, Eq)]
struct Listener {
    proto: &'static str,
    addr: IpAddr,
    port: u16,
    pid: Option<u32>,
}

impl Listener {
    /// `tcp:0.0.0.0:80`、`udp:[::]:53`。IPv6 は括弧で囲み、ポートと区切れるようにする
    fn key(&self) -> String {
        match self.addr {
            IpAddr::V4(addr) => format!("{}:{addr}:{}", self.proto, self.port),
            IpAddr::V6(addr) => format!("{}:[{addr}]:{}", self.proto, self.port),
        }
    }
}

pub fn collect() -> Result<Value> {
    let listeners = imp::listeners()?;
    // 持ち主の識別は processes collector と同じ規則。列挙できなくてもポートの一覧は返す
    let processes = probe::enumerate().unwrap_or_default();
    Ok(render(&listeners, &identities(Os::current(), &processes)))
}

fn identities(os: Os, processes: &[ProcessInfo]) -> HashMap<u32, String> {
    processes
        .iter()
        .filter_map(|p| Some((p.pid, known_set::identify(os, p)?.key)))
        .collect()
}

/// `{ "<proto:addr:port>": { "processes": ["<identity>", ...] } }`。
/// PID は毎回変わるので入れず、持ち主は識別キーで示す
fn render(listeners: &[Listener], identities: &HashMap<u32, String>) -> Value {
    let mut owners: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for listener in listeners {
        let owner = listener.pid.and_then(|pid| identities.get(&pid));
        let entry = owners.entry(listener.key()).or_default();
        // 持ち主が分からない（権限が足りない、列挙の合間に終わった）ことも差分で見えるようにする
        entry.insert(owner.cloned().unwrap_or_else(|| "unknown".to_string()));
    }
    let map: Map<String, Value> = owners
        .into_iter()
        .map(|(key, owners)| (key, json!({ "processes": owners })))
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
                pid: Some(row.dwOwningPid),
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
                pid: Some(row.dwOwningPid),
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
                pid: Some(row.dwOwningPid),
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
                pid: Some(row.dwOwningPid),
            });
        }
        Ok(found)
    }
}

#[cfg(unix)]
mod imp {
    use super::{Listener, parse_proc_net};
    use anyhow::{Result, bail};
    use std::collections::HashMap;
    use std::fs;

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
        let mut readable = 0;
        for (path, proto, state, v6) in TABLES {
            // IPv6 が無効なホストでは tcp6 / udp6 が無い
            let Ok(text) = fs::read_to_string(path) else {
                continue;
            };
            readable += 1;
            for (addr, port, inode) in parse_proc_net(&text, state, v6) {
                found.push(Listener {
                    proto,
                    addr,
                    port,
                    pid: owners.get(&inode).copied(),
                });
            }
        }
        if readable == 0 {
            bail!("cannot read /proc/net");
        }
        Ok(found)
    }

    /// ソケットの inode から持ち主の PID を引く。他のユーザーのプロセスの fd は読めないので、
    /// 引けないソケットがあってよい（そのときの持ち主は unknown になる）
    fn socket_owners() -> HashMap<u64, u32> {
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
                    owners.entry(inode).or_insert(pid);
                }
            }
        }
        owners
    }
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
    use crate::testutil::process;
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

    fn listener(proto: &'static str, addr: IpAddr, port: u16, pid: Option<u32>) -> Listener {
        Listener {
            proto,
            addr,
            port,
            pid,
        }
    }

    #[test]
    fn keys_and_owners_do_not_depend_on_pid() {
        let v4 = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let v6 = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
        let render_with = |pid: u32| {
            let identities = identities(Os::Linux, &[process(pid, "sshd", Some("/usr/sbin/sshd"))]);
            render(
                &[
                    listener("tcp", v4, 22, Some(pid)),
                    listener("tcp", v6, 22, Some(pid)),
                    listener("udp", v4, 53, Some(9999)),
                ],
                &identities,
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

    #[test]
    fn collects_from_this_machine() {
        assert!(collect().unwrap().is_object());
    }
}
