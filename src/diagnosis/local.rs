//! OpenAI 互換 API のローカル LLM。ツールは渡さず、事件ファイルだけを分析させる。

use super::{Backend, Request};
use crate::config::LocalBackend;
use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::fmt::Write as _;
use std::path::Path;
use std::time::Duration;

const EVIDENCE_FILES: [&str; 3] = ["summary.md", "diff.md", "metrics.csv"];
/// 小さいモデルのコンテキストを溢れさせないための、ファイルごとの上限
const MAX_FILE_BYTES: usize = 24 * 1024;

pub struct Local(pub LocalBackend);

fn agent(timeout: Duration) -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .build()
        .into()
}

fn truncate(text: &str, max_bytes: usize) -> &str {
    if text.len() <= max_bytes {
        return text;
    }
    let mut end = max_bytes;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

fn evidence(incident_dir: &Path) -> String {
    let mut text = "ツールは使えません。次の内容だけから分析してください。\n".to_string();
    for name in EVIDENCE_FILES {
        let Ok(contents) = std::fs::read_to_string(incident_dir.join(name)) else {
            continue;
        };
        let _ = writeln!(
            text,
            "\n--- {name} ---\n{}",
            truncate(&contents, MAX_FILE_BYTES)
        );
    }
    text
}

impl Local {
    fn url(&self, path: &str) -> String {
        format!("{}/{path}", self.0.endpoint.trim_end_matches('/'))
    }
}

impl Backend for Local {
    fn available(&self) -> Result<String, String> {
        let url = self.url("models");
        agent(Duration::from_secs(2))
            .get(&url)
            .call()
            .map(|_| self.0.endpoint.clone())
            .map_err(|error| format!("{url}: {error}"))
    }

    fn run(&self, request: &Request) -> Result<String> {
        let body = json!({
            "model": self.0.model,
            "messages": [
                { "role": "system", "content": request.prompt },
                { "role": "user", "content": evidence(request.incident_dir) },
            ],
        });
        let mut response = agent(request.timeout)
            .post(&self.url("chat/completions"))
            .content_type("application/json")
            .send(body.to_string())
            .context("request to the local LLM failed")?;
        let text = response.body_mut().read_to_string()?;
        let reply: Value = serde_json::from_str(&text).context("reply is not JSON")?;
        reply["choices"][0]["message"]["content"]
            .as_str()
            .filter(|content| !content.trim().is_empty())
            .map(str::to_string)
            .context("reply has no message content")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LocalMode;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;

    /// 1 件のリクエストに応答し、受け取った内容を返すサーバー
    fn mock_server(status: &'static str, body: String) -> (String, mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/v1/", listener.local_addr().unwrap());
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_millis(300)))
                .unwrap();
            let mut received = Vec::new();
            let mut chunk = [0; 4096];
            while let Ok(n) = stream.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                received.extend_from_slice(&chunk[..n]);
            }
            let reply = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(reply.as_bytes());
            let _ = sender.send(String::from_utf8_lossy(&received).into_owned());
        });
        (url, receiver)
    }

    fn backend(endpoint: String) -> Local {
        Local(LocalBackend {
            endpoint,
            model: "test-model".to_string(),
            mode: LocalMode::AnalyzeOnly,
        })
    }

    fn with_incident_dir<T>(name: &str, test: impl FnOnce(&Path) -> T) -> T {
        let dir = std::env::temp_dir().join(format!("kuda-local-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("summary.md"), "summary-marker").unwrap();
        let result = test(&dir);
        std::fs::remove_dir_all(dir).unwrap();
        result
    }

    fn request(dir: &Path) -> Request<'_> {
        Request {
            prompt: "prompt-marker",
            incident_dir: dir,
            allowed_commands: &[],
            timeout: Duration::from_secs(5),
        }
    }

    #[test]
    fn sends_prompt_and_evidence_and_reads_the_reply() {
        let reply = json!({ "choices": [{ "message": { "content": "## 症状" } }] });
        let (url, received) = mock_server("200 OK", reply.to_string());
        let text = with_incident_dir("ok", |dir| backend(url).run(&request(dir)).unwrap());
        assert_eq!(text, "## 症状");
        let sent = received.recv().unwrap();
        assert!(sent.starts_with("POST /v1/chat/completions"));
        for marker in ["prompt-marker", "summary-marker", "test-model"] {
            assert!(sent.contains(marker), "{marker}");
        }
    }

    #[test]
    fn empty_reply_is_an_error() {
        let reply = json!({ "choices": [{ "message": { "content": " " } }] });
        let (url, _received) = mock_server("200 OK", reply.to_string());
        with_incident_dir("empty", |dir| {
            assert!(backend(url).run(&request(dir)).is_err());
        });
    }

    #[test]
    fn server_error_is_an_error() {
        let (url, _received) = mock_server("500 Oops", String::new());
        with_incident_dir("500", |dir| {
            assert!(backend(url).run(&request(dir)).is_err());
        });
    }

    #[test]
    fn availability_follows_the_models_endpoint() {
        let (url, _received) = mock_server("200 OK", "{}".to_string());
        assert!(backend(url).available().is_ok());
        let closed = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/v1", closed.local_addr().unwrap());
        drop(closed);
        assert!(backend(url).available().is_err());
    }

    #[test]
    fn truncates_on_char_boundaries() {
        assert_eq!(truncate("あいう", 4), "あ");
        assert_eq!(truncate("abc", 10), "abc");
    }
}
