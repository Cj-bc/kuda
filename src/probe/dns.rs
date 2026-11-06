use super::Sample;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const QUERY_ID: u16 = 0x4b44;

/// OS のリゾルバで名前解決する。標準 API にタイムアウトが無いのでスレッドで待つ
pub fn resolve(host: &str, port: u16, timeout: Duration) -> Result<Vec<SocketAddr>, String> {
    let (sender, receiver) = mpsc::channel();
    let owned = host.to_string();
    std::thread::spawn(move || {
        let _ = sender.send((owned.as_str(), port).to_socket_addrs().map(Vec::from_iter));
    });
    match receiver.recv_timeout(timeout) {
        Ok(Ok(addresses)) => Ok(addresses),
        Ok(Err(error)) => Err(format!("failed to resolve {host}: {error}")),
        Err(_) => Err(format!("timed out resolving {host}")),
    }
}

pub fn check(target: &str, server: Option<&str>, timeout: Duration) -> Result<Sample, String> {
    let started = Instant::now();
    match server {
        Some(server) => query(target, parse_server(server)?, timeout)?,
        None => {
            resolve(target, 0, timeout)?;
        }
    }
    Ok(Sample::rtt(started.elapsed().as_secs_f64() * 1000.0))
}

fn parse_server(server: &str) -> Result<SocketAddr, String> {
    server
        .parse::<SocketAddr>()
        .or_else(|_| server.parse::<IpAddr>().map(|ip| SocketAddr::new(ip, 53)))
        .map_err(|_| format!("invalid DNS server: {server}"))
}

/// 指定サーバーへ A レコードを問い合わせる
fn query(name: &str, server: SocketAddr, timeout: Duration) -> Result<(), String> {
    let bind = if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind).map_err(|e| e.to_string())?;
    socket.connect(server).map_err(|e| e.to_string())?;
    socket
        .set_read_timeout(Some(timeout))
        .map_err(|e| e.to_string())?;
    socket
        .send(&encode_query(name)?)
        .map_err(|e| format!("{server}: {e}"))?;

    let mut reply = [0; 512];
    let size = socket
        .recv(&mut reply)
        .map_err(|e| format!("{server}: {e}"))?;
    check_reply(&reply[..size])
}

fn encode_query(name: &str) -> Result<Vec<u8>, String> {
    let mut packet = Vec::with_capacity(name.len() + 18);
    packet.extend_from_slice(&QUERY_ID.to_be_bytes());
    // RD ビットのみ、質問 1 件
    packet.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(format!("invalid DNS name: {name}"));
        }
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    // ルートラベル、QTYPE=A、QCLASS=IN
    packet.extend_from_slice(&[0, 0, 1, 0, 1]);
    Ok(packet)
}

fn check_reply(reply: &[u8]) -> Result<(), String> {
    if reply.len() < 12 || reply[..2] != QUERY_ID.to_be_bytes() || reply[2] & 0x80 == 0 {
        return Err("malformed DNS reply".to_string());
    }
    match reply[3] & 0x0f {
        0 if u16::from_be_bytes([reply[6], reply[7]]) > 0 => Ok(()),
        0 => Err("DNS reply has no answers".to_string()),
        rcode => Err(format!("DNS server returned rcode {rcode}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TIMEOUT: Duration = Duration::from_secs(5);

    /// 1 回だけ問い合わせに応える UDP サーバーを立て、そのアドレスを返す
    fn mock_server(rcode: u8, answers: u8) -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buffer = [0; 512];
            let (size, peer) = socket.recv_from(&mut buffer).unwrap();
            let mut reply = buffer[..size].to_vec();
            reply[2] |= 0x80;
            reply[3] |= rcode;
            reply[7] = answers;
            socket.send_to(&reply, peer).unwrap();
        });
        address
    }

    #[test]
    fn encodes_query_labels() {
        let packet = encode_query("a.bc").unwrap();
        assert_eq!(&packet[12..], [1, b'a', 2, b'b', b'c', 0, 0, 1, 0, 1]);
        assert!(encode_query("a..b").is_err());
    }

    #[test]
    fn answer_from_server_succeeds() {
        let server = mock_server(0, 1).to_string();
        let sample = check("example.com", Some(&server), TIMEOUT).unwrap();
        assert!(sample.rtt_ms.is_some());
    }

    #[test]
    fn nxdomain_and_empty_answers_fail() {
        let server = mock_server(3, 0).to_string();
        assert!(check("example.com", Some(&server), TIMEOUT).is_err());
        let server = mock_server(0, 0).to_string();
        assert!(check("example.com", Some(&server), TIMEOUT).is_err());
    }

    #[test]
    fn silent_server_times_out() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = socket.local_addr().unwrap().to_string();
        let timeout = Duration::from_millis(200);
        assert!(check("example.com", Some(&server), timeout).is_err());
    }

    #[test]
    fn resolves_localhost_with_system_resolver() {
        assert!(check("localhost", None, TIMEOUT).is_ok());
    }

    #[test]
    fn parses_server_forms() {
        assert_eq!(parse_server("1.1.1.1").unwrap().port(), 53);
        assert_eq!(parse_server("1.1.1.1:5353").unwrap().port(), 5353);
        assert_eq!(parse_server("::1").unwrap().port(), 53);
        assert!(parse_server("nope").is_err());
    }
}
