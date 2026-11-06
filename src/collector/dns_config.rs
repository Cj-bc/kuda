//! DNS リゾルバの設定。

use anyhow::Result;
use serde_json::Value;

#[cfg(windows)]
pub fn collect() -> Result<Value> {
    super::adapters::dns_servers()
}

#[cfg(unix)]
pub fn collect() -> Result<Value> {
    use anyhow::Context;

    let text = std::fs::read_to_string("/etc/resolv.conf").context("/etc/resolv.conf")?;
    Ok(parse_resolv_conf(&text))
}

#[cfg(any(unix, test))]
fn parse_resolv_conf(text: &str) -> Value {
    let mut servers = Vec::new();
    let mut search = Vec::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        match fields.next() {
            Some("nameserver") => servers.extend(fields.next().map(str::to_string)),
            Some("search" | "domain") => search.extend(fields.map(str::to_string)),
            _ => {}
        }
    }
    serde_json::json!({ "servers": servers, "search": search })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_resolv_conf() {
        let text = "# comment\nnameserver 192.168.1.1\nnameserver 1.1.1.1\nsearch lan example.com\noptions edns0\n";
        let config = parse_resolv_conf(text);
        assert_eq!(config["servers"][1], "1.1.1.1");
        assert_eq!(config["search"][0], "lan");
        assert_eq!(config["search"].as_array().unwrap().len(), 2);
    }
}
