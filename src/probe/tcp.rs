use super::{Sample, dns};
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

/// ポート無しの `gateway` で試すポート。ルーターで開いていることが多い順
const GATEWAY_PORTS: [u16; 3] = [53, 80, 443];

pub fn check(target: &str, gateway: Option<IpAddr>, timeout: Duration) -> Result<Sample, String> {
    if target == "gateway" {
        let ip = gateway.ok_or("no default gateway")?;
        return check_gateway(ip, timeout);
    }
    let (host, port) = target
        .rsplit_once(':')
        .ok_or_else(|| format!("target needs a port: {target}"))?;
    let port: u16 = port.parse().map_err(|_| format!("invalid port: {port}"))?;

    let addresses = if host == "gateway" {
        vec![SocketAddr::new(gateway.ok_or("no default gateway")?, port)]
    } else {
        let host = host.trim_matches(['[', ']']);
        dns::resolve(host, port, timeout)?
    };

    let mut last_error = format!("no addresses for {host}");
    for address in addresses {
        match connect(address, timeout) {
            Ok(rtt_ms) => return Ok(Sample::rtt(rtt_ms)),
            Err(error) => last_error = format!("{address}: {error}"),
        }
    }
    Err(last_error)
}

fn connect(address: SocketAddr, timeout: Duration) -> std::io::Result<f64> {
    let started = Instant::now();
    TcpStream::connect_timeout(&address, timeout)?;
    Ok(started.elapsed().as_secs_f64() * 1000.0)
}

fn check_gateway(ip: IpAddr, timeout: Duration) -> Result<Sample, String> {
    let mut last_error = String::new();
    for port in GATEWAY_PORTS {
        match connect(SocketAddr::new(ip, port), timeout) {
            Ok(rtt_ms) => return Ok(Sample::rtt(rtt_ms)),
            // RST が返るなら到達はできている。ただし Windows は RST 後も SYN を
            // 再送するので、この所要時間は RTT として記録しない
            Err(error) if error.kind() == ErrorKind::ConnectionRefused => {
                return Ok(Sample::default());
            }
            Err(error) => last_error = format!("{ip}:{port}: {error}"),
        }
    }
    Err(last_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, TcpListener};

    const TIMEOUT: Duration = Duration::from_secs(5);

    fn closed_port() -> u16 {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.local_addr().unwrap().port()
    }

    #[test]
    fn open_port_reports_rtt() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let target = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
        let sample = check(&target, None, TIMEOUT).unwrap();
        assert!(sample.rtt_ms.is_some());
    }

    #[test]
    fn closed_port_is_a_failure() {
        let target = format!("127.0.0.1:{}", closed_port());
        assert!(check(&target, None, TIMEOUT).is_err());
    }

    #[test]
    fn gateway_with_explicit_port_is_substituted() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let target = format!("gateway:{}", listener.local_addr().unwrap().port());
        let gateway = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert!(check(&target, gateway, TIMEOUT).is_ok());
        assert!(check(&target, None, TIMEOUT).is_err());
    }

    #[test]
    fn refused_gateway_counts_as_reachable_without_rtt() {
        // 127.0.0.1 の 53/80/443 が開いていても閉じていても成功し、閉じていれば RTT は無い
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert!(check_gateway(ip, TIMEOUT).is_ok());
    }

    #[test]
    fn missing_gateway_is_a_failure() {
        assert!(check("gateway", None, TIMEOUT).is_err());
    }
}
