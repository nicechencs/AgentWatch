//! HTTP steps against the local test server.
//!
//! P0-SIM-03 owns `sim serve`. Until that exists, a refused connection is a
//! recorded failure (`ok: false`), not a crash, so `sim run` can still exit 0
//! for the process-tree parts of smoke.

use std::io::Read;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use ureq::tls::{Certificate, RootCerts, TlsConfig};
use ureq::Agent;

const MAX_DOWNLOAD: u64 = 16 * 1024 * 1024;

#[derive(Debug)]
pub struct HttpOutcome {
    pub app_bytes: u64,
    pub ok: bool,
    pub error: Option<String>,
    pub local: Option<String>,
    pub remote: Option<String>,
}

pub fn upload(url: &str, bytes: u64, cert_pem: Option<&Path>) -> HttpOutcome {
    let body = bait_body(bytes);
    let agent = agent(cert_pem, timeout_for(bytes));
    let remote = remote_of(url);
    match agent.post(url).send(&body[..]) {
        Ok(resp) => {
            let status = resp.status().as_u16();
            if (200..300).contains(&status) {
                HttpOutcome {
                    app_bytes: bytes,
                    ok: true,
                    error: None,
                    local: None,
                    remote: remote.clone(),
                }
            } else {
                HttpOutcome {
                    app_bytes: bytes,
                    ok: false,
                    error: Some(format!("http status {status}")),
                    local: None,
                    remote,
                }
            }
        }
        Err(err) => fail(err.to_string(), remote),
    }
}

pub fn download(url: &str, cert_pem: Option<&Path>) -> HttpOutcome {
    let agent = agent(cert_pem, timeout_for(bytes_hint(url)));
    let remote = remote_of(url);
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
                    local: None,
                    remote: remote.clone(),
                },
                Ok(n) => HttpOutcome {
                    app_bytes: n as u64,
                    ok: false,
                    error: Some(format!("http status {status}")),
                    local: None,
                    remote,
                },
                Err(err) => HttpOutcome {
                    app_bytes: buf.len() as u64,
                    ok: false,
                    error: Some(err.to_string()),
                    local: None,
                    remote,
                },
            }
        }
        Err(err) => fail(err.to_string(), remote),
    }
}

fn agent(cert_pem: Option<&Path>, timeout: Duration) -> Agent {
    let mut builder = Agent::config_builder()
        .timeout_global(Some(timeout))
        .https_only(false);
    if let Some(path) = cert_pem {
        if let Some(tls) = trust_only(path) {
            builder = builder.tls_config(tls);
        }
    }
    Agent::new_with_config(builder.build())
}

/// Trust exactly the cert `sim serve` wrote for this run. No system store.
fn trust_only(path: &Path) -> Option<TlsConfig> {
    let pem = std::fs::read(path).ok()?;
    let cert = Certificate::from_pem(&pem).ok()?;
    Some(
        TlsConfig::builder()
            .root_certs(RootCerts::new_with_certs(&[cert]))
            .build(),
    )
}

/// A few seconds plus about 1 s per MiB, capped. Enough for 10 MiB on a local socket.
fn timeout_for(bytes: u64) -> Duration {
    let extra = bytes / (1024 * 1024);
    Duration::from_secs(10 + extra.min(50))
}

fn bytes_hint(url: &str) -> u64 {
    url.split_once("bytes=")
        .and_then(|(_, rest)| rest.split(['&', '#']).next())
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(1024 * 1024)
}

fn remote_of(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let host = rest.split('/').next().unwrap_or(rest);
    host.parse::<SocketAddr>().ok().map(|addr| addr.to_string())
}

fn bait_body(bytes: u64) -> Vec<u8> {
    crate::paths::bait_bytes(bytes)
}

fn fail(error: String, remote: Option<String>) -> HttpOutcome {
    HttpOutcome {
        app_bytes: 0,
        ok: false,
        error: Some(error),
        local: None,
        remote,
    }
}
