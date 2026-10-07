//! HTTP steps against the local test server.
//!
//! P0-SIM-03 owns `sim serve`. Until that exists, a refused connection is a
//! recorded failure (`ok: false`), not a crash, so `sim run` can still exit 0
//! for the process-tree parts of smoke.

use std::io::Read;
use std::time::Duration;

use ureq::Agent;

const TIMEOUT: Duration = Duration::from_secs(2);
const MAX_DOWNLOAD: u64 = 16 * 1024 * 1024;

#[derive(Debug)]
pub struct HttpOutcome {
    pub app_bytes: u64,
    pub ok: bool,
    pub error: Option<String>,
}

pub fn upload(url: &str, bytes: u64) -> HttpOutcome {
    let body = bait_body(bytes);
    let agent = agent();
    match agent.post(url).send(&body[..]) {
        Ok(resp) => {
            let status = resp.status().as_u16();
            if (200..300).contains(&status) {
                HttpOutcome {
                    app_bytes: bytes,
                    ok: true,
                    error: None,
                }
            } else {
                HttpOutcome {
                    app_bytes: bytes,
                    ok: false,
                    error: Some(format!("http status {status}")),
                }
            }
        }
        Err(err) => fail(err.to_string()),
    }
}

pub fn download(url: &str) -> HttpOutcome {
    let agent = agent();
    match agent.get(url).call() {
        Ok(mut resp) => {
            let status = resp.status().as_u16();
            let mut buf = Vec::new();
            let read = resp
                .body_mut()
                .as_reader()
                .take(MAX_DOWNLOAD)
                .read_to_end(&mut buf);
            match read {
                Ok(n) if (200..300).contains(&status) => HttpOutcome {
                    app_bytes: n as u64,
                    ok: true,
                    error: None,
                },
                Ok(n) => HttpOutcome {
                    app_bytes: n as u64,
                    ok: false,
                    error: Some(format!("http status {status}")),
                },
                Err(err) => HttpOutcome {
                    app_bytes: buf.len() as u64,
                    ok: false,
                    error: Some(err.to_string()),
                },
            }
        }
        Err(err) => fail(err.to_string()),
    }
}

fn agent() -> Agent {
    let config = Agent::config_builder()
        .timeout_global(Some(TIMEOUT))
        .https_only(false)
        .build();
    Agent::new_with_config(config)
}

fn bait_body(bytes: u64) -> Vec<u8> {
    crate::paths::bait_bytes(bytes)
}

fn fail(error: String) -> HttpOutcome {
    HttpOutcome {
        app_bytes: 0,
        ok: false,
        error: Some(error),
    }
}
