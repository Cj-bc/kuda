//! ICMP echo。Windows は IcmpSendEcho2、Linux は非特権の ping ソケットを使う。IPv4 のみ。

use super::{Sample, dns};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

pub fn check(host: &str, timeout: Duration) -> Result<Sample, String> {
    let ip = resolve_v4(host, timeout)?;
    echo(ip, timeout).map(Sample::rtt)
}

fn resolve_v4(host: &str, timeout: Duration) -> Result<Ipv4Addr, String> {
    if let Ok(ip) = host.parse() {
        return Ok(ip);
    }
    dns::resolve(host, 0, timeout)?
        .into_iter()
        .find_map(|address| match address.ip() {
            IpAddr::V4(ip) => Some(ip),
            IpAddr::V6(_) => None,
        })
        .ok_or_else(|| format!("no IPv4 address for {host}"))
}

#[cfg(windows)]
pub fn echo(ip: Ipv4Addr, timeout: Duration) -> Result<f64, String> {
    use windows::Win32::NetworkManagement::IpHelper::{
        ICMP_ECHO_REPLY, IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho2,
    };

    const PAYLOAD: [u8; 32] = [0x6b; 32];
    // SAFETY: 引数なし。失敗は Result で返る
    let handle = unsafe { IcmpCreateFile() }.map_err(|e| e.to_string())?;

    // 応答バッファには ICMP_ECHO_REPLY、データ、ICMP エラー分の余裕が要る
    let mut reply = [0u64; (size_of::<ICMP_ECHO_REPLY>() + PAYLOAD.len() + 8 + 64).div_ceil(8)];
    let reply_size = size_of_val(&reply) as u32;
    // SAFETY: バッファはこの呼び出しの間有効で、reply_size は実際の大きさと一致する。
    // イベントも APC も渡さないので同期呼び出しになる
    let count = unsafe {
        IcmpSendEcho2(
            handle,
            None,
            None,
            None,
            u32::from_ne_bytes(ip.octets()),
            PAYLOAD.as_ptr().cast(),
            PAYLOAD.len() as u16,
            None,
            reply.as_mut_ptr().cast(),
            reply_size,
            timeout.as_millis().try_into().unwrap_or(u32::MAX),
        )
    };
    let error = std::io::Error::last_os_error();
    // SAFETY: IcmpCreateFile が返したハンドルを 1 度だけ閉じる
    let _ = unsafe { IcmpCloseHandle(handle) };

    if count == 0 {
        return Err(format!("{ip}: {error}"));
    }
    // SAFETY: count > 0 なら先頭に ICMP_ECHO_REPLY が書き込まれている
    let first = unsafe { &*reply.as_ptr().cast::<ICMP_ECHO_REPLY>() };
    if first.Status != 0 {
        return Err(format!("{ip}: ICMP status {}", first.Status));
    }
    Ok(f64::from(first.RoundTripTime))
}

#[cfg(unix)]
pub fn echo(ip: Ipv4Addr, timeout: Duration) -> Result<f64, String> {
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    use std::net::{SocketAddr, UdpSocket};
    use std::time::Instant;

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))
        .map_err(|e| format!("ping socket unavailable (see net.ipv4.ping_group_range): {e}"))?;
    socket
        .connect(&SockAddr::from(SocketAddr::new(IpAddr::V4(ip), 0)))
        .map_err(|e| e.to_string())?;
    let socket = UdpSocket::from(socket);
    socket
        .set_read_timeout(Some(timeout))
        .map_err(|e| e.to_string())?;

    let sequence: u16 = 1;
    let started = Instant::now();
    socket
        .send(&encode_echo(sequence))
        .map_err(|e| format!("{ip}: {e}"))?;

    // カーネルが識別子で振り分けるので、届くのはこのソケット宛ての応答だけ
    let mut reply = [0; 128];
    loop {
        let size = socket.recv(&mut reply).map_err(|e| format!("{ip}: {e}"))?;
        if size >= 8 && reply[0] == 0 && reply[6..8] == sequence.to_be_bytes() {
            return Ok(started.elapsed().as_secs_f64() * 1000.0);
        }
    }
}

/// echo request。識別子とチェックサムはカーネルが埋める
#[cfg(unix)]
fn encode_echo(sequence: u16) -> Vec<u8> {
    let mut packet = vec![8, 0, 0, 0, 0, 0];
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(b"kuda");
    packet
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_literals_without_dns() {
        let timeout = Duration::from_secs(1);
        assert_eq!(
            resolve_v4("192.0.2.1", timeout),
            Ok(Ipv4Addr::new(192, 0, 2, 1))
        );
    }

    #[test]
    fn pings_loopback() {
        // Linux のビルド環境では ping ソケットが許可されていないことがある
        if cfg!(windows) {
            let sample = check("127.0.0.1", Duration::from_secs(2)).unwrap();
            assert!(sample.rtt_ms.is_some());
        }
    }

    #[test]
    fn unreachable_address_fails() {
        if cfg!(windows) {
            assert!(check("192.0.2.1", Duration::from_millis(300)).is_err());
        }
    }
}
