use super::Sample;
use std::time::{Duration, Instant};

pub fn check(url: &str, expect: Option<u16>, timeout: Duration) -> Result<Sample, String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .http_status_as_error(false)
        .build()
        .into();
    let started = Instant::now();
    let response = agent.get(url).call().map_err(|e| e.to_string())?;
    let rtt_ms = started.elapsed().as_secs_f64() * 1000.0;

    let status = response.status().as_u16();
    let ok = expect.map_or((200..400).contains(&status), |expect| status == expect);
    if ok {
        Ok(Sample::rtt(rtt_ms))
    } else {
        Err(format!("unexpected status {status}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    const TIMEOUT: Duration = Duration::from_secs(5);

    fn mock_server(status: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0; 1024];
            let _ = stream.read(&mut buffer);
            let reply = format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n");
            let _ = stream.write_all(reply.as_bytes());
        });
        url
    }

    #[test]
    fn success_status_passes() {
        let sample = check(&mock_server("204 No Content"), None, TIMEOUT).unwrap();
        assert!(sample.rtt_ms.is_some());
    }

    #[test]
    fn server_error_fails_by_default() {
        let error = check(&mock_server("503 Unavailable"), None, TIMEOUT).unwrap_err();
        assert!(error.contains("503"));
    }

    #[test]
    fn expected_status_overrides_the_default() {
        let url = mock_server("503 Unavailable");
        assert!(check(&url, Some(503), TIMEOUT).is_ok());
        assert!(check(&mock_server("200 OK"), Some(204), TIMEOUT).is_err());
    }
}
