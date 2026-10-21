//! `aw mcp-tap -- <cmd>` from the real binary (P5-SEC-03).
//!
//! Unit tests call `copy_gated_for_test` and never pass clap, so they cannot
//! see a dispatch that returns "not in this build" before the wrapper runs.
//! This test parses arguments, spawns the built `aw`, and that process spawns
//! [`mcp_echo`](./fixtures/mcp_echo.rs).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

fn aw() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_aw"));
    cmd.env_remove("AW_TOKEN");
    cmd.env_remove("AW_POLICY");
    cmd
}

fn echo_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_mcp_echo"))
}

/// Policy files live under the crate's `target/` directory, not `/tmp`.
/// Cargo already gitignores that tree, and the test deletes the directory.
fn scratch(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(format!(
            "aw-mcp-tap-cli-{}-{}-{name}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch");
    dir
}

fn write_policy(dir: &std::path::Path, body: &str) -> PathBuf {
    let path = dir.join("policy.toml");
    std::fs::write(&path, body).expect("policy");
    path
}

/// One JSON-RPC line in, one line out. `aw` must exit after the child does.
fn exchange(policy: Option<&std::path::Path>, request: &str) -> (i32, String, String) {
    exchange_at(policy, None, None, request)
}

/// `socket` is `--socket`. `http` is `--http` plus a throwaway bearer, which
/// that flag requires. Either one is the audit address.
fn exchange_at(
    policy: Option<&std::path::Path>,
    socket: Option<&std::path::Path>,
    http: Option<&str>,
    request: &str,
) -> (i32, String, String) {
    let echo = echo_bin();
    let mut cmd = aw();
    if let Some(path) = socket {
        cmd.arg("--socket").arg(path);
    }
    if let Some(url) = http {
        cmd.arg("--http")
            .arg(url)
            .arg("--token")
            .arg("mcp-tap-test");
    }
    cmd.args(["mcp-tap", "--"]).arg(&echo);
    if let Some(path) = policy {
        cmd.env("AW_POLICY", path);
    }
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn aw mcp-tap");
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    stdin.write_all(request.as_bytes()).expect("write request");
    stdin.write_all(b"\n").expect("write newline");
    drop(stdin);

    let reader = std::thread::spawn(move || {
        let mut line = String::new();
        let mut reader = BufReader::new(stdout);
        let _ = reader.read_line(&mut line);
        line
    });

    let status = wait_child(&mut child, Duration::from_secs(15));
    let stdout = reader.join().expect("reader");
    let stderr = read_to_string(child.stderr.take().expect("stderr"));
    (status, stdout, stderr)
}

fn wait_child(child: &mut std::process::Child, limit: Duration) -> i32 {
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.code().unwrap_or(1),
            Ok(None) if start.elapsed() < limit => std::thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("aw mcp-tap did not exit within {limit:?}");
            }
            Err(err) => panic!("wait: {err}"),
        }
    }
}

fn read_to_string(mut reader: impl std::io::Read) -> String {
    let mut buf = String::new();
    let _ = reader.read_to_string(&mut buf);
    buf
}

const DENY: &str = r#"
version = 1
enabled = true
on_error = "deny"

[[rule]]
id = "no-rm"
layer = ["mcp"]
match.mcp_method = { exact = "tools/call" }
match.command = { prefix = "rm " }
action = "deny"
reason = "不允许删除"
"#;

const REWRITE: &str = r#"
version = 1
enabled = true

[[rule]]
id = "plan-only"
layer = ["mcp"]
match.command = { prefix = "terraform apply" }
action = "rewrite"
rewrite.command = { replace = ["terraform apply", "terraform plan"] }
"#;

#[test]
fn empty_command_is_usage() {
    let out = aw().args(["mcp-tap"]).output().expect("spawn aw");
    let err = String::from_utf8(out.stderr).expect("utf8");
    assert_eq!(out.status.code(), Some(2), "{err}");
    assert!(err.contains("`aw mcp-tap` 需要提供要包装的命令"), "{err}");
    assert!(
        !err.contains("本版本未接入"),
        "empty command must be usage, not unwired: {err}"
    );
}

#[test]
fn help_names_the_wrapper_and_does_not_say_unwired() {
    let out = aw().args(["mcp-tap", "--help"]).output().expect("spawn aw");
    let text = String::from_utf8(out.stdout).expect("utf8");
    let err = String::from_utf8(out.stderr).expect("utf8");
    assert!(out.status.success(), "{err}");
    assert!(text.contains("stdio 透明包装器"), "{text}");
    assert!(!text.contains("本版本未接入"), "{text}");
}

#[test]
fn deny_answers_the_client_and_does_not_reach_the_server() {
    let dir = scratch("deny");
    let policy = write_policy(&dir, DENY);
    let init = exchange(
        Some(&policy),
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
    );
    assert_eq!(init.0, 0, "stderr: {}", init.2);
    assert!(
        init.1.contains("\"protocolVersion\""),
        "initialize was not forwarded: {}",
        init.1
    );

    let denied = exchange(
        Some(&policy),
        r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"run","arguments":{"command":"rm -rf /tmp"}}}"#,
    );
    assert_eq!(denied.0, 0, "stderr: {}", denied.2);
    assert!(denied.1.contains("\"id\":7"), "missing id: {}", denied.1);
    assert!(
        denied.1.contains("不允许删除"),
        "deny reason missing: {}",
        denied.1
    );
    assert!(
        !denied.1.contains("rm -rf"),
        "denied command text was written to the client: {}",
        denied.1
    );
    assert!(
        !denied.1.contains("\"command\""),
        "the server answered a denied call: {}",
        denied.1
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rewrite_is_what_the_server_receives() {
    let dir = scratch("rewrite");
    let policy = write_policy(&dir, REWRITE);
    let rewritten = exchange(
        Some(&policy),
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"run","arguments":{"command":"terraform apply"}}}"#,
    );
    assert_eq!(rewritten.0, 0, "stderr: {}", rewritten.2);
    assert!(
        rewritten.1.contains("terraform plan"),
        "server did not see the rewrite: {}",
        rewritten.1
    );
    assert!(
        !rewritten.1.contains("terraform apply"),
        "original command reached the server: {}",
        rewritten.1
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A daemon that stores the audit. The rewrite is what the child sees, and
/// the posted body names the rule. The same request against a socket nobody
/// listens on is a deny: a rewrite with no record must not be forwarded.
#[test]
fn rewrite_is_posted_and_a_dead_daemon_denies_it() {
    let dir = scratch("audit");
    let policy = write_policy(&dir, REWRITE);
    let request = r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"run","arguments":{"command":"terraform apply"}}}"#;

    let posted = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let (address, server) = stand_in(std::sync::Arc::clone(&posted));
    let live = exchange_at(Some(&policy), address.socket(), address.http(), request);
    drop(server);
    assert_eq!(live.0, 0, "stderr: {}", live.2);
    assert!(
        live.1.contains("terraform plan"),
        "a recorded rewrite did not reach the server: {}",
        live.1
    );
    let bodies = posted.lock().expect("posted").clone();
    assert!(
        bodies.iter().any(|body| body.contains("plan-only")),
        "the audit never arrived: {bodies:?}"
    );
    assert!(
        bodies
            .iter()
            .any(|body| body.contains("command=terraform apply")),
        "the audit lost the field that was rewritten: {bodies:?}"
    );
    assert!(
        bodies
            .iter()
            .all(|body| !body.contains("jsonrpc") && !body.contains("params")),
        "the audit stored the whole frame: {bodies:?}"
    );

    let dead = address.dead();
    let started = std::time::Instant::now();
    let denied = exchange_at(Some(&policy), dead.socket(), dead.http(), request);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "a daemon that is not listening held the call for {:?}",
        started.elapsed()
    );
    assert_eq!(denied.0, 0, "stderr: {}", denied.2);
    assert!(
        denied.2.contains("intercept_audit_dropped"),
        "the drop was not reported: {}",
        denied.2
    );
    assert!(
        !denied.1.contains("terraform plan"),
        "the rewrite was forwarded with no audit: {}",
        denied.1
    );
    assert!(
        denied.1.contains("\"id\":4"),
        "the downgraded deny did not answer the client: {}",
        denied.1
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `AW_SOCKET` is the address `aw` uses when no flag was passed. A broken
/// policy's deny has to arrive there too, and the body must not carry the
/// policy file's text.
#[cfg(unix)]
#[test]
fn broken_policy_deny_uses_aw_socket() {
    let dir = scratch("broken");
    let policy = dir.join("broken.toml");
    std::fs::write(&policy, "this is not a policy\n").expect("policy");
    let socket = dir.join("api.sock");
    let posted = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let saved = std::sync::Arc::clone(&posted);
    let listener = std::os::unix::net::UnixListener::bind(&socket).expect("bind");
    let worker = std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let mut buf = [0_u8; 16 * 1024];
        let Ok(n) = std::io::Read::read(&mut stream, &mut buf) else {
            return;
        };
        *saved.lock().expect("posted") = String::from_utf8_lossy(&buf[..n]).into_owned();
        let _ = std::io::Write::write_all(
            &mut stream,
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}",
        );
    });
    let echo = echo_bin();
    let mut cmd = aw();
    cmd.env("AW_POLICY", &policy).env("AW_SOCKET", &socket);
    cmd.env_remove("AW_INTERCEPT_AUDIT");
    cmd.args(["mcp-tap", "--"]).arg(&echo);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn");
    let mut stdin = child.stdin.take().expect("stdin");
    stdin
        .write_all(
            br#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"run","arguments":{"command":"echo hello"}}}"#,
        )
        .expect("write");
    stdin.write_all(b"\n").expect("newline");
    drop(stdin);
    let stdout = child.stdout.take().expect("stdout");
    let reader = std::thread::spawn(move || {
        let mut line = String::new();
        let _ = std::io::BufRead::read_line(&mut BufReader::new(stdout), &mut line);
        line
    });
    let status = wait_child(&mut child, Duration::from_secs(15));
    let answer = reader.join().expect("reader");
    let _ = worker.join();
    assert_eq!(status, 0, "{answer}");
    assert!(answer.contains("\"id\":9"), "{answer}");
    let body = posted.lock().expect("posted").clone();
    assert!(body.contains("/api/v1/agent/intercept"), "{body}");
    assert!(body.contains("echo hello"), "{body}");
    assert!(body.contains("规则文件读不了"), "{body}");
    assert!(!body.contains("this is not a policy"), "{body}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Where the audit goes, and the same address with nothing listening.
struct AuditAddress {
    socket: Option<std::path::PathBuf>,
    http: Option<String>,
    dead_socket: Option<std::path::PathBuf>,
    dead_http: Option<String>,
}

impl AuditAddress {
    fn socket(&self) -> Option<&std::path::Path> {
        self.socket.as_deref()
    }

    fn http(&self) -> Option<&str> {
        self.http.as_deref()
    }

    fn dead(&self) -> Self {
        Self {
            socket: self.dead_socket.clone(),
            http: self.dead_http.clone(),
            dead_socket: None,
            dead_http: None,
        }
    }
}

/// One local listener that records `POST /api/v1/agent/intercept` bodies.
///
/// Unix uses a socket. Windows uses loopback HTTP: the named-pipe server needs
/// the daemon's tokio runtime, and `--http` is the channel `aw` already speaks
/// on every system. The dead address is the same kind with nobody listening.
fn stand_in(posted: std::sync::Arc<std::sync::Mutex<Vec<String>>>) -> (AuditAddress, StandIn) {
    #[cfg(unix)]
    {
        let dir = scratch("sock");
        let path = dir.join("api.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind");
        let worker = std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut buf = [0_u8; 16 * 1024];
            let Ok(n) = std::io::Read::read(&mut stream, &mut buf) else {
                return;
            };
            let text = String::from_utf8_lossy(&buf[..n]).into_owned();
            posted.lock().expect("posted").push(text);
            let _ = std::io::Write::write_all(
                &mut stream,
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}",
            );
        });
        let dead = dir.join("dead.sock");
        (
            AuditAddress {
                socket: Some(path),
                http: None,
                dead_socket: Some(dead),
                dead_http: None,
            },
            StandIn {
                worker: Some(worker),
            },
        )
    }
    #[cfg(not(unix))]
    {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let worker = std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut buf = [0_u8; 16 * 1024];
            let Ok(n) = std::io::Read::read(&mut stream, &mut buf) else {
                return;
            };
            let text = String::from_utf8_lossy(&buf[..n]).into_owned();
            posted.lock().expect("posted").push(text);
            let _ = std::io::Write::write_all(
                &mut stream,
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}",
            );
        });
        let dead = std::net::TcpListener::bind("127.0.0.1:0").expect("dead");
        let dead_port = dead.local_addr().expect("addr").port();
        drop(dead);
        (
            AuditAddress {
                socket: None,
                http: Some(format!("http://127.0.0.1:{port}")),
                dead_socket: None,
                dead_http: Some(format!("http://127.0.0.1:{dead_port}")),
            },
            StandIn {
                worker: Some(worker),
            },
        )
    }
}

struct StandIn {
    worker: Option<std::thread::JoinHandle<()>>,
}

impl Drop for StandIn {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
