//! Localhost byte sink and source for traffic calibration (P0-SIM-03).
//!
//! Listens only on `127.0.0.1`. `POST /upload` counts the body and discards it.
//! `GET /download?bytes=N` returns exactly N bytes of a fixed pattern, capped
//! at [`MAX_DOWNLOAD_BYTES`] (over the cap is HTTP 400, not a shorter body).
//!
//! Download pattern: the ASCII prefix `SIM-DOWNLOAD-v1\n` repeated and truncated
//! to N. A client can check the length and that the body starts with that prefix.
//!
//! The truth log is JSONL of byte counts only. `tls_bytes` is JSON `null` when
//! the listener is plain HTTP. On HTTPS it is the TCP byte total (handshake plus
//! records, both directions) counted around the socket rustls already uses. It
//! is not a rustls record-inspector total, and it is captured before the HTTP
//! response is written, so the response records themselves are not included.
//! `0` is never written to mean unknown.
//!
//! Optional UDP and DNS stubs also bind `127.0.0.1` only. The DNS stub answers
//! `*.agentwatch.test` except names that start with `nx-`. It is not a recursive
//! resolver and never queries the public network. A platform that cannot bind it
//! is reported; the scenario runner then marks DNS steps `skip`.

mod cert;
mod http;
mod truth_log;

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;

use truth_log::{TruthLog, TruthRecord};

/// Largest `bytes` query `GET /download` will generate.
/// A larger request is HTTP 400; the handler does not truncate.
pub const MAX_DOWNLOAD_BYTES: u64 = 32 * 1024 * 1024;

/// Fixed download payload. Repeated and then truncated to the requested length.
pub const DOWNLOAD_PATTERN: &[u8] = b"SIM-DOWNLOAD-v1\n";

const HELP: &str = "\
usage: sim serve --truth <file> [options]

Localhost HTTP and HTTPS byte server. Both listeners bind 127.0.0.1 only.
Port 0 asks the OS for an ephemeral port. The actual addresses are printed
once, as `http://127.0.0.1:<port>` and `https://127.0.0.1:<port>`.

Options:
  --http <ip:port>      HTTP listen address (default 127.0.0.1:0)
  --https <ip:port>     HTTPS listen address (default 127.0.0.1:0)
  --truth <file>        JSONL byte-count log (required)
  --cert-out <dir>      Where to write cert.pem and key.pem (default: a new
                        directory under the system temp dir)
  --udp <ip:port>       UDP echo on 127.0.0.1 (default: off)
  --dns <ip:port>       DNS stub for *.agentwatch.test (default: off)
  -h, --help            Show this text

Routes:
  POST /upload          Read the body, count bytes, discard them.
                        Responds 200 with {\"count\":N}. The body is not echoed.
  GET /download?bytes=N Exactly N bytes of the repeating pattern
                        SIM-DOWNLOAD-v1\\n. N above 32 MiB is HTTP 400.

The truth log records connection id, direction (upload or download),
app_bytes, tls_bytes (null on HTTP; TCP byte total on HTTPS), ok, and error.
It does not record bodies, URLs, or request headers.

The certificate is self-signed and written only under --cert-out. It is not
installed into any trust store. Clients must be given cert.pem explicitly.

UDP echoes the datagram and records its length, never its payload.
The DNS stub answers only *.agentwatch.test with 127.0.0.1. A name whose first
label starts with nx- is NXDOMAIN. It never forwards a query.
";

struct ServeOpts {
    http: SocketAddr,
    https: SocketAddr,
    udp: Option<SocketAddr>,
    dns: Option<SocketAddr>,
    truth: PathBuf,
    cert_out: PathBuf,
}

/// Entry point for `sim serve`.
pub fn serve(args: Vec<String>) -> Result<(), String> {
    if args.iter().any(|arg| arg == "-h" || arg == "--help") {
        print!("{HELP}");
        return Ok(());
    }
    let opts = parse_args(args)?;
    let material = cert::generate().map_err(|err| format!("generate certificate: {err}"))?;
    cert::write_pem(&opts.cert_out, &material)
        .map_err(|err| format!("write certificate: {err}"))?;

    let http_listener = bind_loopback(opts.http).map_err(|err| format!("bind http: {err}"))?;
    let https_listener = bind_loopback(opts.https).map_err(|err| format!("bind https: {err}"))?;
    let http_addr = http_listener
        .local_addr()
        .map_err(|err| format!("http local address: {err}"))?;
    let https_addr = https_listener
        .local_addr()
        .map_err(|err| format!("https local address: {err}"))?;

    // One line each, no per-request URLs. Tests read these to learn port 0.
    println!("http://{http_addr}");
    println!("https://{https_addr}");
    println!("cert {}", opts.cert_out.join("cert.pem").display());
    let stop = Arc::new(AtomicBool::new(false));
    let udp_socket = match opts.udp {
        Some(addr) => Some(bind_udp(addr).map_err(|err| format!("bind udp: {err}"))?),
        None => None,
    };
    let dns_socket = match opts.dns {
        Some(addr) => Some(bind_udp(addr).map_err(|err| format!("bind dns: {err}"))?),
        None => None,
    };
    if let Some(sock) = &udp_socket {
        println!(
            "udp://{}",
            sock.local_addr()
                .map_err(|err| format!("udp local address: {err}"))?
        );
    }
    if let Some(sock) = &dns_socket {
        println!(
            "dns://{}",
            sock.local_addr()
                .map_err(|err| format!("dns local address: {err}"))?
        );
    }
    let _ = std::io::stdout().flush();

    let log = Arc::new(TruthLog::create(&opts.truth).map_err(|err| format!("truth log: {err}"))?);
    let tls = server_config(&material)?;
    let next_id = Arc::new(AtomicU64::new(1));

    let http_log = Arc::clone(&log);
    let http_ids = Arc::clone(&next_id);
    let http_stop = Arc::clone(&stop);
    let http_thread = std::thread::Builder::new()
        .name("sim-serve-http".to_string())
        .spawn(move || accept_loop(http_listener, http_log, http_ids, None, http_stop))
        .map_err(|err| format!("spawn http: {err}"))?;

    let https_log = Arc::clone(&log);
    let https_ids = Arc::clone(&next_id);
    let https_stop = Arc::clone(&stop);
    let https_thread = std::thread::Builder::new()
        .name("sim-serve-https".to_string())
        .spawn(move || accept_loop(https_listener, https_log, https_ids, Some(tls), https_stop))
        .map_err(|err| format!("spawn https: {err}"))?;

    let mut extras = Vec::new();
    if let Some(sock) = udp_socket {
        let log = Arc::clone(&log);
        let ids = Arc::clone(&next_id);
        let stop = Arc::clone(&stop);
        extras.push(
            std::thread::Builder::new()
                .name("sim-serve-udp".to_string())
                .spawn(move || udp_loop(sock, log, ids, stop))
                .map_err(|err| format!("spawn udp: {err}"))?,
        );
    }
    if let Some(sock) = dns_socket {
        let log = Arc::clone(&log);
        let ids = Arc::clone(&next_id);
        let stop = Arc::clone(&stop);
        extras.push(
            std::thread::Builder::new()
                .name("sim-serve-dns".to_string())
                .spawn(move || dns_loop(sock, log, ids, stop))
                .map_err(|err| format!("spawn dns: {err}"))?,
        );
    }

    // HTTP and HTTPS run until the process is killed. UDP and DNS are optional
    // and stop with them. A join error is a thread panic.
    http_thread
        .join()
        .map_err(|_| "http accept thread stopped".to_string())?;
    stop.store(true, Ordering::Relaxed);
    https_thread
        .join()
        .map_err(|_| "https accept thread stopped".to_string())?;
    for thread in extras {
        let _ = thread.join();
    }
    Ok(())
}

fn parse_args(args: Vec<String>) -> Result<ServeOpts, String> {
    let mut http: Option<SocketAddr> = None;
    let mut https: Option<SocketAddr> = None;
    let mut udp: Option<SocketAddr> = None;
    let mut dns: Option<SocketAddr> = None;
    let mut truth: Option<PathBuf> = None;
    let mut cert_out: Option<PathBuf> = None;
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--http" => {
                let raw = iter
                    .next()
                    .ok_or_else(|| "--http needs ip:port".to_string())?;
                http = Some(parse_listen("--http", &raw)?);
            }
            "--https" => {
                let raw = iter
                    .next()
                    .ok_or_else(|| "--https needs ip:port".to_string())?;
                https = Some(parse_listen("--https", &raw)?);
            }
            "--udp" => {
                let raw = iter
                    .next()
                    .ok_or_else(|| "--udp needs ip:port".to_string())?;
                udp = Some(parse_listen("--udp", &raw)?);
            }
            "--dns" => {
                let raw = iter
                    .next()
                    .ok_or_else(|| "--dns needs ip:port".to_string())?;
                dns = Some(parse_listen("--dns", &raw)?);
            }
            "--truth" => {
                truth = Some(PathBuf::from(
                    iter.next()
                        .ok_or_else(|| "--truth needs a path".to_string())?,
                ));
            }
            "--cert-out" => {
                cert_out = Some(PathBuf::from(
                    iter.next()
                        .ok_or_else(|| "--cert-out needs a directory".to_string())?,
                ));
            }
            other => return Err(format!("unknown flag `{other}`\n{HELP}")),
        }
    }
    let cert_out = match cert_out {
        Some(path) => path,
        None => {
            let path = std::env::temp_dir().join(format!("sim-serve-{}", std::process::id()));
            std::fs::create_dir_all(&path).map_err(|err| format!("create cert dir: {err}"))?;
            path
        }
    };
    Ok(ServeOpts {
        http: http.unwrap_or(SocketAddr::from(([127, 0, 0, 1], 0))),
        https: https.unwrap_or(SocketAddr::from(([127, 0, 0, 1], 0))),
        udp,
        dns,
        truth: truth.ok_or_else(|| "missing --truth <file>".to_string())?,
        cert_out,
    })
}

/// Accept only IPv4 `127.0.0.1`. `0.0.0.0`, other addresses, and `::1` are refused.
fn parse_listen(flag: &str, raw: &str) -> Result<SocketAddr, String> {
    let addr: SocketAddr = raw
        .parse()
        .map_err(|_| format!("{flag} must be 127.0.0.1:<port>, got `{raw}`"))?;
    match addr.ip() {
        IpAddr::V4(ip) if ip == Ipv4Addr::LOCALHOST => Ok(addr),
        _ => Err(format!(
            "{flag} must be 127.0.0.1 (refusing `{raw}`); the byte server does not listen on any other address"
        )),
    }
}

fn bind_loopback(addr: SocketAddr) -> Result<TcpListener, String> {
    if addr.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) {
        return Err(format!("refusing to bind {addr}"));
    }
    let listener = TcpListener::bind(addr).map_err(|err| format!("{addr}: {err}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("http nonblocking: {err}"))?;
    Ok(listener)
}

fn bind_udp(addr: SocketAddr) -> Result<UdpSocket, String> {
    if addr.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) {
        return Err(format!("refusing to bind {addr}"));
    }
    let socket = UdpSocket::bind(addr).map_err(|err| format!("{addr}: {err}"))?;
    socket
        .set_read_timeout(Some(Duration::from_millis(200)))
        .map_err(|err| format!("udp timeout: {err}"))?;
    Ok(socket)
}

fn server_config(material: &cert::Material) -> Result<Arc<ServerConfig>, String> {
    // Pass ring explicitly. `ServerConfig::builder()` would panic unless a
    // process-default provider were installed, and ureq may already own that slot.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(material.key_der.clone()));
    let chain = vec![CertificateDer::from(material.cert_der.clone())];
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|err| format!("tls versions: {err}"))?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|err| format!("tls certificate: {err}"))?;
    Ok(Arc::new(config))
}

fn accept_loop(
    listener: TcpListener,
    log: Arc<TruthLog>,
    next_id: Arc<AtomicU64>,
    tls: Option<Arc<ServerConfig>>,
    stop: Arc<AtomicBool>,
) {
    while !stop.load(Ordering::Relaxed) {
        let (stream, peer) = match listener.accept() {
            Ok(pair) => pair,
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => {
                eprintln!("sim serve: accept: {err}");
                continue;
            }
        };
        if !peer.ip().is_loopback() {
            eprintln!("sim serve: dropping non-loopback peer");
            drop(stream);
            continue;
        }
        let id = next_id.fetch_add(1, Ordering::Relaxed);
        let log = Arc::clone(&log);
        let tls = tls.clone();
        if std::thread::Builder::new()
            .name(format!("sim-serve-{id}"))
            .spawn(move || {
                if let Err(err) = handle_connection(id, stream, &log, tls.as_deref()) {
                    if err != "idle" {
                        eprintln!("sim serve: connection {id}: {err}");
                    }
                }
            })
            .is_err()
        {
            eprintln!("sim serve: failed to spawn connection {id}");
        }
    }
}

fn handle_connection(
    id: u64,
    stream: TcpStream,
    log: &TruthLog,
    tls: Option<&ServerConfig>,
) -> Result<(), String> {
    // `accept` on a nonblocking listener returns a nonblocking socket. Put it
    // back into blocking mode so a TLS handshake can wait for the whole record.
    stream
        .set_nonblocking(false)
        .map_err(|err| format!("blocking: {err}"))?;
    // A `long_conn` step holds the socket and never sends a request. The timeout
    // lets that handler return instead of pinning a thread for the whole hold,
    // and the accept loop is already concurrent so other transfers still proceed.
    // Longer than basic_proc_net's 30 s hold, so that step is not closed first.
    // A client that goes away still unblocks the handler instead of pinning it.
    let _ = stream.set_read_timeout(Some(Duration::from_secs(45)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(60)));
    match tls {
        None => {
            let mut io = stream;
            http::serve_one(&mut io, |exchange| commit(id, log, None, exchange))
        }
        Some(config) => {
            let (counter, tls_bytes) = CountingSocket::new(stream);
            let conn = rustls::ServerConnection::new(Arc::new(config.clone()))
                .map_err(|err| format!("tls handshake setup: {err}"))?;
            let mut io = rustls::StreamOwned::new(conn, counter);
            let result = http::serve_one(&mut io, |exchange| {
                // Bytes on the TCP socket so far (handshake + request records).
                // The HTTP response has not been written yet. The counter lives
                // in an atomic so this closure does not borrow `io`.
                commit(id, log, Some(tls_bytes.load(Ordering::Relaxed)), exchange)
            });
            let _ = io.flush();
            result
        }
    }
}

fn commit(
    id: u64,
    log: &TruthLog,
    tls_bytes: Option<u64>,
    exchange: http::Exchange,
) -> Result<(), String> {
    log.append(&TruthRecord {
        connection_id: id,
        direction: exchange.direction,
        app_bytes: exchange.app_bytes,
        tls_bytes,
        ok: exchange.ok,
        error: exchange.error,
    })
}

/// Counts bytes rustls reads and writes on the TCP socket.
///
/// The running total is shared so the HTTP callback can read it without
/// borrowing the `StreamOwned` that owns this socket.
struct CountingSocket {
    inner: TcpStream,
    total: Arc<AtomicU64>,
}

impl CountingSocket {
    fn new(inner: TcpStream) -> (Self, Arc<AtomicU64>) {
        let total = Arc::new(AtomicU64::new(0));
        (
            Self {
                inner,
                total: Arc::clone(&total),
            },
            total,
        )
    }
}

impl Read for CountingSocket {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.total.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
}

impl Write for CountingSocket {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.total.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Echo each datagram and record its length. The payload is not written anywhere.
fn udp_loop(socket: UdpSocket, log: Arc<TruthLog>, next_id: Arc<AtomicU64>, stop: Arc<AtomicBool>) {
    let mut buf = [0u8; 2048];
    while !stop.load(Ordering::Relaxed) {
        match socket.recv_from(&mut buf) {
            Ok((n, peer)) => {
                if !peer.ip().is_loopback() {
                    continue;
                }
                let id = next_id.fetch_add(1, Ordering::Relaxed);
                let _ = socket.send_to(&buf[..n], peer);
                let _ = log.append(&TruthRecord {
                    connection_id: id,
                    direction: truth_log::Direction::Udp,
                    app_bytes: n as u64,
                    tls_bytes: None,
                    ok: true,
                    error: None,
                });
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(err) if err.kind() == std::io::ErrorKind::TimedOut => {}
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) => eprintln!("sim serve: udp: {err}"),
        }
    }
}

/// Answer `*.agentwatch.test` with `127.0.0.1`. A first label starting with `nx-`
/// is NXDOMAIN. Any other name is refused. Nothing is forwarded.
fn dns_loop(socket: UdpSocket, log: Arc<TruthLog>, next_id: Arc<AtomicU64>, stop: Arc<AtomicBool>) {
    let mut buf = [0u8; 512];
    while !stop.load(Ordering::Relaxed) {
        match socket.recv_from(&mut buf) {
            Ok((n, peer)) => {
                if !peer.ip().is_loopback() {
                    continue;
                }
                let id = next_id.fetch_add(1, Ordering::Relaxed);
                match dns_reply(&buf[..n]) {
                    Some(reply) => {
                        let _ = socket.send_to(&reply, peer);
                        let _ = log.append(&TruthRecord {
                            connection_id: id,
                            direction: truth_log::Direction::Dns,
                            app_bytes: n as u64,
                            tls_bytes: None,
                            ok: true,
                            error: None,
                        });
                    }
                    None => {
                        let _ = log.append(&TruthRecord {
                            connection_id: id,
                            direction: truth_log::Direction::Dns,
                            app_bytes: n as u64,
                            tls_bytes: None,
                            ok: false,
                            error: Some("dns query rejected".to_string()),
                        });
                    }
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(err) if err.kind() == std::io::ErrorKind::TimedOut => {}
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) => eprintln!("sim serve: dns: {err}"),
        }
    }
}

/// Build a response for one question. Returns `None` when the packet is not a
/// single-question query this stub is willing to answer.
fn dns_reply(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let qd = u16::from_be_bytes([query[4], query[5]]);
    if qd != 1 {
        return None;
    }
    let (name, next) = read_name(query, 12)?;
    if next + 4 > query.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([query[next], query[next + 1]]);
    let qclass = u16::from_be_bytes([query[next + 2], query[next + 3]]);
    let question_end = next + 4;
    if qclass != 1 || (qtype != 1 && qtype != 255) {
        return None;
    }
    let nx = name_is_nxdomain(&name);
    let allowed = name_is_test_zone(&name);
    if !nx && !allowed {
        return None;
    }
    let mut out = query[..question_end].to_vec();
    // QR=1, RD copied, RA=0, RCODE 0 or 3.
    out[2] = 0x80 | (query[2] & 0x01);
    out[3] = if nx { 0x03 } else { 0x00 };
    if nx {
        out[6] = 0;
        out[7] = 0;
        return Some(out);
    }
    out[6] = 0;
    out[7] = 1; // one answer
                // Compression pointer back to the question name.
    out.extend_from_slice(&[0xC0, 0x0C]);
    out.extend_from_slice(&1u16.to_be_bytes()); // A
    out.extend_from_slice(&1u16.to_be_bytes()); // IN
    out.extend_from_slice(&60u32.to_be_bytes());
    out.extend_from_slice(&4u16.to_be_bytes());
    out.extend_from_slice(&[127, 0, 0, 1]);
    Some(out)
}

fn name_is_test_zone(name: &str) -> bool {
    let name = name.trim_end_matches('.');
    name.eq_ignore_ascii_case("agentwatch.test")
        || name.to_ascii_lowercase().ends_with(".agentwatch.test")
}

fn name_is_nxdomain(name: &str) -> bool {
    let first = name.split('.').next().unwrap_or("");
    first.to_ascii_lowercase().starts_with("nx-") && name_is_test_zone(name)
}

/// Read one uncompressed DNS name. Pointers are rejected: this stub only sees
/// queries it just received, which a normal client sends uncompressed.
fn read_name(packet: &[u8], mut at: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    for _ in 0..32 {
        if at >= packet.len() {
            return None;
        }
        let len = packet[at] as usize;
        at += 1;
        if len == 0 {
            let name = if labels.is_empty() {
                ".".to_string()
            } else {
                labels.join(".")
            };
            return Some((name, at));
        }
        if len > 63 || at + len > packet.len() {
            return None;
        }
        let label = std::str::from_utf8(&packet[at..at + len]).ok()?;
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return None;
        }
        labels.push(label.to_string());
        at += len;
    }
    None
}
