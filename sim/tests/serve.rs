//! `sim serve` on 127.0.0.1: a 10 MiB upload and a known download.
//!
//! Upload size is `10 * 1024 * 1024` bytes (10 MiB, 10_485_760), not 10_000_000.
//! The client trusts only the cert the server wrote under `--cert-out`. Nothing
//! in this test installs a CA or sets `SSL_CERT_FILE`.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::ClientConfig;

const TEN_MIB: usize = 10 * 1024 * 1024;
const DOWNLOAD_PATTERN: &[u8] = b"SIM-DOWNLOAD-v1\n";

struct Server {
    child: Child,
    // Keep the banner pipe open while the server finishes writing it.
    _stdout: std::process::ChildStdout,
    http_port: u16,
    https_port: u16,
    cert_pem: PathBuf,
    truth: PathBuf,
    scratch: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.scratch);
    }
}

fn spawn_server() -> Server {
    // The tests in this file run in parallel in one process. On macOS
    // `SystemTime` has microsecond resolution, so pid + nanos alone gave two
    // servers the same scratch dir: one overwrote the other's cert.pem
    // (BadSignature) and its Drop deleted the other's truth log (NotFound).
    // The per-process sequence number makes every dir distinct.
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let scratch = std::env::temp_dir().join(format!(
        "sim-serve-test-{}-{seq}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&scratch).expect("scratch");
    let truth = scratch.join("truth.jsonl");
    let cert_out = scratch.join("cert");
    let mut child = Command::new(env!("CARGO_BIN_EXE_sim"))
        .arg("serve")
        .arg("--http")
        .arg("127.0.0.1:0")
        .arg("--https")
        .arg("127.0.0.1:0")
        .arg("--truth")
        .arg(&truth)
        .arg("--cert-out")
        .arg(&cert_out)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn sim serve");

    let mut stdout = child.stdout.take().expect("stdout");
    let (http_port, https_port) = read_ports(&mut stdout);
    Server {
        child,
        _stdout: stdout,
        http_port,
        https_port,
        cert_pem: cert_out.join("cert.pem"),
        truth,
        scratch,
    }
}

fn read_ports(stdout: impl Read) -> (u16, u16) {
    let mut reader = std::io::BufReader::new(stdout);
    let mut http_port = None;
    let mut https_port = None;
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline && (http_port.is_none() || https_port.is_none()) {
        let mut line = String::new();
        let n = std::io::BufRead::read_line(&mut reader, &mut line).expect("read banner");
        if n == 0 {
            break;
        }
        let line = line.trim();
        if let Some(port) = line.strip_prefix("http://127.0.0.1:") {
            http_port = port.parse().ok();
        } else if let Some(port) = line.strip_prefix("https://127.0.0.1:") {
            https_port = port.parse().ok();
        }
    }
    (
        http_port.expect("http banner"),
        https_port.expect("https banner"),
    )
}

fn http_exchange(port: u16, request_head: &str, body: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect http");
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .expect("timeout");
    stream.write_all(request_head.as_bytes()).expect("head");
    stream.write_all(body).expect("body");
    stream.flush().expect("flush");
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).expect("response");
    buf
}

fn split_http(raw: &[u8]) -> (u16, &[u8]) {
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("header terminator");
    let head = std::str::from_utf8(&raw[..end]).expect("headers utf-8");
    let status = head
        .split_whitespace()
        .nth(1)
        .expect("status")
        .parse()
        .expect("status code");
    (status, &raw[end + 4..])
}

fn truth_lines(path: &Path) -> Vec<serde_json::Value> {
    let text = std::fs::read_to_string(path).expect("truth log");
    text.lines()
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_str(line).expect("json line"))
        .collect()
}

fn client_config(cert_pem: &Path) -> Arc<ClientConfig> {
    // Trust exactly the cert `sim serve` wrote. No webpki-roots, no system store.
    let pem = std::fs::read(cert_pem).expect("cert.pem");
    let der = CertificateDer::from_pem_slice(&pem).expect("parse cert");
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der).expect("trust the generated cert");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    Arc::new(config)
}

fn https_exchange(port: u16, cert_pem: &Path, request_head: &str, body: &[u8]) -> Vec<u8> {
    let config = client_config(cert_pem);
    let tcp = TcpStream::connect(("127.0.0.1", port)).expect("connect https");
    tcp.set_read_timeout(Some(Duration::from_secs(60)))
        .expect("timeout");
    let name = ServerName::try_from("127.0.0.1").expect("server name");
    let conn = rustls::ClientConnection::new(config, name).expect("client conn");
    let mut tls = rustls::StreamOwned::new(conn, tcp);
    tls.write_all(request_head.as_bytes()).expect("head");
    tls.write_all(body).expect("body");
    tls.flush().expect("flush");
    let mut buf = Vec::new();
    // The server closes the TCP socket after one response and does not send
    // close_notify. rustls reports that as UnexpectedEof once the bytes are in.
    match tls.read_to_end(&mut buf) {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {}
        Err(err) => panic!("response: {err}"),
    }
    buf
}

#[test]
fn http_upload_ten_mib_matches_truth_and_download_is_the_pattern() {
    let server = spawn_server();
    let payload = vec![0xA5u8; TEN_MIB];
    let head = format!(
        "POST /upload HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {TEN_MIB}\r\nConnection: close\r\n\r\n"
    );
    let raw = http_exchange(server.http_port, &head, &payload);
    let (status, body) = split_http(&raw);
    assert_eq!(status, 200, "{raw:?}");
    let count: serde_json::Value = serde_json::from_slice(body).expect("count json");
    assert_eq!(count["count"].as_u64(), Some(TEN_MIB as u64));
    assert_eq!(
        body.iter().filter(|b| **b == 0xA5).count(),
        0,
        "upload response must not echo the body"
    );

    let download_n = 100u64;
    let get = format!(
        "GET /download?bytes={download_n} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    );
    let raw = http_exchange(server.http_port, &get, b"");
    let (status, body) = split_http(&raw);
    assert_eq!(status, 200);
    assert_eq!(body.len() as u64, download_n);
    assert!(body.starts_with(DOWNLOAD_PATTERN));
    for (i, byte) in body.iter().enumerate() {
        assert_eq!(*byte, DOWNLOAD_PATTERN[i % DOWNLOAD_PATTERN.len()]);
    }

    let lines = truth_lines(&server.truth);
    let upload = lines
        .iter()
        .find(|line| line["direction"] == "upload")
        .expect("upload truth");
    assert_eq!(upload["app_bytes"].as_u64(), Some(TEN_MIB as u64));
    assert_eq!(upload["ok"], true);
    assert!(
        upload["tls_bytes"].is_null(),
        "plain HTTP does not measure TLS"
    );
    assert!(upload.get("connection_id").is_some());
    let text = std::fs::read_to_string(&server.truth).expect("truth text");
    assert!(
        !text.contains("Authorization")
            && !text.as_bytes().windows(4).any(|w| w == b"\xA5\xA5\xA5\xA5"),
        "truth log must not contain the upload body"
    );

    let download = lines
        .iter()
        .find(|line| line["direction"] == "download")
        .expect("download truth");
    assert_eq!(download["app_bytes"].as_u64(), Some(download_n));
    assert_eq!(download["ok"], true);
    assert!(download["tls_bytes"].is_null());
}

#[test]
fn https_download_uses_only_the_written_cert() {
    let server = spawn_server();
    let n = 64u64;
    let get =
        format!("GET /download?bytes={n} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    let raw = https_exchange(server.https_port, &server.cert_pem, &get, b"");
    let (status, body) = split_http(&raw);
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&raw));
    assert_eq!(body.len() as u64, n);
    let prefix = n.min(DOWNLOAD_PATTERN.len() as u64) as usize;
    assert!(body.starts_with(&DOWNLOAD_PATTERN[..prefix]));

    let lines = truth_lines(&server.truth);
    let download = lines
        .iter()
        .find(|line| line["direction"] == "download" && line["tls_bytes"].is_number())
        .expect("https truth");
    let tls_bytes = download["tls_bytes"].as_u64().expect("tls_bytes");
    assert!(tls_bytes > n, "on-wire TLS bytes should exceed the payload");
    assert_eq!(download["app_bytes"].as_u64(), Some(n));
    assert_eq!(download["ok"], true);
}

#[test]
fn download_over_the_cap_is_400() {
    let server = spawn_server();
    let get =
        "GET /download?bytes=33554433 HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    let raw = http_exchange(server.http_port, get, b"");
    let (status, body) = split_http(&raw);
    assert_eq!(status, 400);
    assert!(
        body.len() < 1024,
        "rejection must not be a truncated payload"
    );
    let line = truth_lines(&server.truth)
        .into_iter()
        .find(|line| line["direction"] == "download")
        .expect("download truth");
    assert_eq!(line["ok"], false);
    assert_eq!(line["app_bytes"].as_u64(), Some(0));
    assert!(line["error"].as_str().is_some());
}
