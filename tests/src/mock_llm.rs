//! Scripted OpenAI-compatible chat-completions server for E2E tests of the
//! LLM monitor. Runs on a loopback port; every POST is matched against the
//! script in order and the first entry whose `needle` occurs in the request
//! body decides the reply (an empty needle matches everything).

use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

/// What the mock answers.
#[derive(Clone, Debug)]
pub enum Reply {
    /// A well-formed verdict.
    Verdict {
        verdict: &'static str,
        reason: &'static str,
        clause: &'static str,
    },
    /// HTTP 500 with an error body.
    Http500,
    /// HTTP 200 whose content is not a verdict JSON.
    Garbage,
    /// Sleep this long, then answer `allow` (drives client timeouts).
    Sleep(u64),
}

pub struct MockLlm {
    server: Arc<tiny_http::Server>,
    thread: Option<JoinHandle<()>>,
    port: u16,
    seen: Arc<Mutex<Vec<String>>>,
}

impl MockLlm {
    pub fn start(script: Vec<(&'static str, Reply)>) -> Self {
        let server =
            Arc::new(tiny_http::Server::http("127.0.0.1:0").expect("bind mock LLM server"));
        let port = match server.server_addr() {
            tiny_http::ListenAddr::IP(addr) => addr.port(),
            #[cfg(unix)]
            tiny_http::ListenAddr::Unix(_) => unreachable!("mock LLM binds TCP"),
        };
        let seen = Arc::new(Mutex::new(Vec::new()));
        let thread = {
            let server = Arc::clone(&server);
            let seen = Arc::clone(&seen);
            std::thread::spawn(move || {
                for mut req in server.incoming_requests() {
                    let mut body = String::new();
                    let _ = req.as_reader().read_to_string(&mut body);
                    seen.lock().unwrap().push(body.clone());
                    let reply = script
                        .iter()
                        .find(|(needle, _)| needle.is_empty() || body.contains(needle))
                        .map(|(_, r)| r.clone())
                        .unwrap_or(Reply::Http500);
                    let (status, text) = match reply {
                        Reply::Verdict {
                            verdict,
                            reason,
                            clause,
                        } => (
                            200,
                            completion(&format!(
                                r#"{{"verdict":"{verdict}","reason":"{reason}","roe_clause":"{clause}"}}"#
                            )),
                        ),
                        Reply::Http500 => {
                            (500, r#"{"error":{"message":"mock outage"}}"#.to_string())
                        }
                        Reply::Garbage => (200, completion("I cannot decide, sorry.")),
                        Reply::Sleep(ms) => {
                            std::thread::sleep(Duration::from_millis(ms));
                            (200, completion(r#"{"verdict":"allow","reason":"late"}"#))
                        }
                    };
                    let header = tiny_http::Header::from_bytes(
                        &b"Content-Type"[..],
                        &b"application/json"[..],
                    )
                    .unwrap();
                    let response = tiny_http::Response::from_string(text)
                        .with_status_code(status)
                        .with_header(header);
                    let _ = req.respond(response);
                }
            })
        };
        MockLlm {
            server,
            thread: Some(thread),
            port,
            seen,
        }
    }

    /// Base URL to configure as `monitor.endpoint`.
    pub fn endpoint(&self) -> String {
        format!("http://127.0.0.1:{}/v1", self.port)
    }

    /// Request bodies received so far.
    pub fn requests(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }
}

impl Drop for MockLlm {
    fn drop(&mut self) {
        self.server.unblock();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Wrap assistant text in a chat-completions envelope.
fn completion(content: &str) -> String {
    serde_json::json!({
        "id": "mock",
        "object": "chat.completion",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}],
    })
    .to_string()
}
