//! ルーティングテーブルとデフォルトゲートウェイ。

use anyhow::Result;
use serde_json::Value;
use std::net::IpAddr;

#[cfg(windows)]
pub use self::windows_impl::{collect, default_gateway};

#[cfg(unix)]
pub fn collect() -> Result<Value> {
    use crate::process;
    use anyhow::bail;
    use std::time::Duration;

    let mut routes = Vec::new();
    for family in ["-4", "-6"] {
        let mut command = process::command("ip");
        command.args(["-j", family, "route", "show"]);
        let output = process::run(command, None, Duration::from_secs(5))?;
        if !output.success() {
            bail!("ip -j route failed: {}", output.stderr.trim());
        }
        routes.extend(parse_ip_route(&output.stdout)?);
    }
    Ok(Value::Array(routes))
}

/// `ip` コマンドが無い環境でも動くよう /proc から読む
#[cfg(unix)]
pub fn default_gateway() -> Option<IpAddr> {
    let table = std::fs::read_to_string("/proc/net/route").ok()?;
    parse_proc_net_route(&table).map(IpAddr::V4)
}

/// `ip -j route show` の出力を解釈する
#[cfg(any(unix, test))]
fn parse_ip_route(text: &str) -> Result<Vec<Value>> {
    use serde_json::json;

    // 経路が 1 つも無いと空文字列のことがある
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }
    let routes: Vec<Value> = serde_json::from_str(text)?;
    Ok(routes
        .iter()
        .map(|route| {
            json!({
                "destination": route["dst"],
                "next_hop": route.get("gateway"),
                "interface": route["dev"],
                "metric": route.get("metric"),
            })
        })
        .collect())
}

/// /proc/net/route からメトリック最小のデフォルト経路を選ぶ
#[cfg(any(unix, test))]
fn parse_proc_net_route(table: &str) -> Option<std::net::Ipv4Addr> {
    table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let (destination, gateway, metric) = (fields.get(1)?, fields.get(2)?, fields.get(6)?);
            if *destination != "00000000" {
                return None;
            }
            // 値はホストのバイト順（x86/ARM ではリトルエンディアン）の 16 進数
            let gateway = u32::from_str_radix(gateway, 16).ok()?;
            let metric: u32 = metric.parse().ok()?;
            (gateway != 0).then(|| (metric, std::net::Ipv4Addr::from(gateway.swap_bytes())))
        })
        .min_by_key(|(metric, _)| *metric)
        .map(|(_, gateway)| gateway)
}

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use anyhow::bail;
    use serde_json::json;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::NetworkManagement::IpHelper::{
        FreeMibTable, GetIpForwardTable2, MIB_IPFORWARD_TABLE2,
    };
    use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_INET};

    struct Route {
        destination: IpAddr,
        prefix_len: u8,
        next_hop: IpAddr,
        interface_index: u32,
        metric: u32,
    }

    fn sockaddr_ip(address: &SOCKADDR_INET) -> Option<IpAddr> {
        // SAFETY: si_family はどのバリアントでも先頭にあり、それに応じた型で読む
        unsafe {
            let family = address.si_family;
            if family == AF_INET {
                Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                    address.Ipv4.sin_addr.S_un.S_addr,
                ))))
            } else if family == AF_INET6 {
                Some(IpAddr::V6(Ipv6Addr::from(address.Ipv6.sin6_addr.u.Byte)))
            } else {
                None
            }
        }
    }

    fn routes() -> Result<Vec<Route>> {
        let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
        // SAFETY: 成功時に OS が確保した表を table へ書き込み、下で FreeMibTable する
        let status = unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table) };
        if status != ERROR_SUCCESS {
            bail!("GetIpForwardTable2 failed: {}", status.0);
        }
        // SAFETY: Table は NumEntries 個の要素を持つ可変長配列
        let rows = unsafe {
            std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
        };
        let routes = rows
            .iter()
            .filter_map(|row| {
                Some(Route {
                    destination: sockaddr_ip(&row.DestinationPrefix.Prefix)?,
                    prefix_len: row.DestinationPrefix.PrefixLength,
                    next_hop: sockaddr_ip(&row.NextHop)?,
                    interface_index: row.InterfaceIndex,
                    metric: row.Metric,
                })
            })
            .collect();
        // SAFETY: GetIpForwardTable2 が確保した表で、rows はこれ以降使わない
        unsafe { FreeMibTable(table.cast()) };
        Ok(routes)
    }

    pub fn collect() -> Result<Value> {
        let mut routes = routes()?;
        routes.sort_by_key(|route| (route.destination, route.prefix_len, route.next_hop));
        let routes = routes.iter().map(|route| {
            json!({
                "destination": format!("{}/{}", route.destination, route.prefix_len),
                "next_hop": route.next_hop.to_string(),
                "interface": route.interface_index,
                "metric": route.metric,
            })
        });
        Ok(Value::Array(routes.collect()))
    }

    pub fn default_gateway() -> Option<IpAddr> {
        routes()
            .ok()?
            .into_iter()
            .filter(|route| {
                route.prefix_len == 0
                    && route.destination.is_ipv4()
                    && !route.next_hop.is_unspecified()
            })
            .min_by_key(|route| route.metric)
            .map(|route| route.next_hop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn parses_ip_route_json() {
        let text = r#"[{"dst":"default","gateway":"192.168.1.1","dev":"eth0","metric":100},
                       {"dst":"192.168.1.0/24","dev":"eth0"}]"#;
        let routes = parse_ip_route(text).unwrap();
        assert_eq!(routes[0]["destination"], "default");
        assert_eq!(routes[0]["next_hop"], "192.168.1.1");
        assert_eq!(routes[1]["next_hop"], Value::Null);
        assert!(parse_ip_route("").unwrap().is_empty());
    }

    #[test]
    fn picks_lowest_metric_default_route() {
        let table = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n\
            wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\n\
            eth0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\n\
            eth0\t0000A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\n";
        assert_eq!(
            parse_proc_net_route(table),
            Some(Ipv4Addr::new(192, 168, 0, 1))
        );
    }

    #[test]
    fn no_default_route_means_no_gateway() {
        let table = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n\
            eth0\t0000A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\n";
        assert_eq!(parse_proc_net_route(table), None);
    }

    #[test]
    fn collects_from_this_machine() {
        if cfg!(windows) {
            let routes = collect().unwrap();
            assert!(!routes.as_array().unwrap().is_empty());
        }
    }
}
