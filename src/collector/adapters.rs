//! ネットワークアダプタの一覧。OS をまたいで同じ形の JSON にそろえる。

#[cfg(any(unix, test))]
use anyhow::Result;
#[cfg(any(unix, test))]
use serde_json::Value;

#[cfg(windows)]
pub use self::windows_impl::collect;

#[cfg(windows)]
pub(super) use self::windows_impl::dns_servers;

#[cfg(unix)]
pub fn collect() -> Result<Value> {
    use crate::process;
    use anyhow::{Context, bail};
    use std::time::Duration;

    let mut command = process::command("ip");
    command.args(["-j", "addr", "show"]);
    let output = process::run(command, None, Duration::from_secs(5)).context("ip -j addr")?;
    if !output.success() {
        bail!("ip -j addr failed: {}", output.stderr.trim());
    }
    parse_ip_addr(&output.stdout)
}

/// `ip -j addr show` の出力を解釈する
#[cfg(any(unix, test))]
fn parse_ip_addr(text: &str) -> Result<Value> {
    use serde_json::json;

    let links: Vec<Value> = serde_json::from_str(text)?;
    let adapters = links.iter().map(|link| {
        let mut addresses: Vec<String> = link["addr_info"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|info| {
                let local = info["local"].as_str()?;
                Some(format!("{local}/{}", info["prefixlen"].as_u64()?))
            })
            .collect();
        addresses.sort();
        json!({
            "name": link["ifname"],
            "oper_status": link["operstate"],
            "mac": link["address"],
            "mtu": link["mtu"],
            "addresses": addresses,
        })
    });
    Ok(Value::Array(adapters.collect()))
}

#[cfg(windows)]
mod windows_impl {
    use anyhow::{Result, bail};
    use serde_json::{Value, json};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS};
    use windows::Win32::NetworkManagement::IpHelper::{
        GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST,
        GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_UNICAST_ADDRESS_LH,
    };
    use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6, SOCKET_ADDRESS,
    };

    struct Adapter {
        name: String,
        description: String,
        up: bool,
        mac: String,
        mtu: u32,
        addresses: Vec<String>,
        gateways: Vec<String>,
        dns_servers: Vec<String>,
        dns_suffix: String,
    }

    fn socket_ip(address: &SOCKET_ADDRESS) -> Option<IpAddr> {
        if address.lpSockaddr.is_null() {
            return None;
        }
        // SAFETY: lpSockaddr は GetAdaptersAddresses が返した有効な sockaddr を指し、
        // sa_family に応じた型で読む
        unsafe {
            let family = (*address.lpSockaddr).sa_family;
            if family == AF_INET {
                let v4 = address.lpSockaddr.cast::<SOCKADDR_IN>().read_unaligned();
                Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                    v4.sin_addr.S_un.S_addr,
                ))))
            } else if family == AF_INET6 {
                let v6 = address.lpSockaddr.cast::<SOCKADDR_IN6>().read_unaligned();
                Some(IpAddr::V6(Ipv6Addr::from(v6.sin6_addr.u.Byte)))
            } else {
                None
            }
        }
    }

    /// 連結リストを辿って IP アドレスを文字列で集める
    macro_rules! collect_ips {
        ($head:expr, $format:expr) => {{
            let mut items = Vec::new();
            let mut node = $head;
            while !node.is_null() {
                // SAFETY: リストは adapters() のバッファ内にあり、null 終端である
                let current = unsafe { &*node };
                if let Some(ip) = socket_ip(&current.Address) {
                    items.push($format(current, ip));
                }
                node = current.Next;
            }
            items.sort();
            items
        }};
    }

    fn adapters() -> Result<Vec<Adapter>> {
        let flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
        let mut size: u32 = 32 * 1024;
        let mut buffer: Vec<u64>;
        // 呼び出しの間にアダプタが増えると足りなくなるので数回やり直す
        let mut attempts = 0;
        loop {
            buffer = vec![0; (size as usize).div_ceil(8)];
            let head = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
            // SAFETY: head は size バイト以上で 8 バイト境界の書き込み可能な領域を指す
            let status = unsafe {
                GetAdaptersAddresses(AF_UNSPEC.0.into(), flags, None, Some(head), &mut size)
            };
            attempts += 1;
            if status == ERROR_SUCCESS.0 {
                break;
            }
            if status != ERROR_BUFFER_OVERFLOW.0 || attempts >= 4 {
                bail!("GetAdaptersAddresses failed: {status}");
            }
        }

        let mut result = Vec::new();
        let mut node = buffer.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        while !node.is_null() {
            // SAFETY: 成功時の node は buffer 内の null 終端リストを指す。アダプタが
            // 1 つも無い場合は先頭がゼロのままなので、下の名前チェックで打ち切る
            let adapter = unsafe { &*node };
            if adapter.AdapterName.is_null() {
                break;
            }
            let mac_len = (adapter.PhysicalAddressLength as usize).min(8);
            let mac: Vec<String> = adapter.PhysicalAddress[..mac_len]
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            result.push(Adapter {
                // SAFETY: これらの文字列は OS が埋めた null 終端の UTF-16
                name: unsafe { adapter.FriendlyName.to_string() }.unwrap_or_default(),
                description: unsafe { adapter.Description.to_string() }.unwrap_or_default(),
                dns_suffix: unsafe { adapter.DnsSuffix.to_string() }.unwrap_or_default(),
                up: adapter.OperStatus == IfOperStatusUp,
                mac: mac.join(":"),
                mtu: adapter.Mtu,
                addresses: collect_ips!(
                    adapter.FirstUnicastAddress,
                    |node: &IP_ADAPTER_UNICAST_ADDRESS_LH, ip: IpAddr| {
                        format!("{ip}/{}", node.OnLinkPrefixLength)
                    }
                ),
                gateways: collect_ips!(adapter.FirstGatewayAddress, |_: &_, ip: IpAddr| ip
                    .to_string()),
                dns_servers: collect_ips!(adapter.FirstDnsServerAddress, |_: &_, ip: IpAddr| ip
                    .to_string()),
            });
            node = adapter.Next;
        }
        result.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(result)
    }

    pub fn collect() -> Result<Value> {
        let adapters = adapters()?.into_iter().map(|adapter| {
            json!({
                "name": adapter.name,
                "description": adapter.description,
                "oper_status": if adapter.up { "up" } else { "down" },
                "mac": adapter.mac,
                "mtu": adapter.mtu,
                "addresses": adapter.addresses,
                "gateways": adapter.gateways,
            })
        });
        Ok(Value::Array(adapters.collect()))
    }

    /// 稼働中のアダプタごとの DNS 設定
    pub fn dns_servers() -> Result<Value> {
        let adapters = adapters()?
            .into_iter()
            .filter(|adapter| adapter.up && !adapter.dns_servers.is_empty())
            .map(|adapter| {
                json!({
                    "adapter": adapter.name,
                    "servers": adapter.dns_servers,
                    "suffix": adapter.dns_suffix,
                })
            });
        Ok(Value::Array(adapters.collect()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ip_addr_json() {
        let text = r#"[{"ifname":"eth0","operstate":"UP","address":"aa:bb:cc:dd:ee:ff","mtu":1500,
            "addr_info":[{"family":"inet6","local":"fe80::1","prefixlen":64},
                         {"family":"inet","local":"192.168.1.5","prefixlen":24}]}]"#;
        let adapters = parse_ip_addr(text).unwrap();
        assert_eq!(adapters[0]["name"], "eth0");
        assert_eq!(adapters[0]["oper_status"], "UP");
        assert_eq!(adapters[0]["addresses"][0], "192.168.1.5/24");
        assert_eq!(adapters[0]["addresses"][1], "fe80::1/64");
    }

    #[test]
    fn collects_from_this_machine() {
        // Linux のビルド環境には ip が無いことがあるので Windows でだけ確かめる
        if cfg!(windows) {
            let adapters = collect().unwrap();
            assert!(!adapters.as_array().unwrap().is_empty());
            assert!(adapters[0]["name"].is_string());
        }
    }
}
