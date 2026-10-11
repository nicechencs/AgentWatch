//! macOS: a daemon running as the current user samples a long-running program
//! it launches. No root. The hold stage is this same binary; the program is
//! `sleep 20`, and the session's process list must contain its pid.
//!
//! GitHub's macOS runner can run this: it does not need a privileged daemon
//! and it does not grant Full Disk Access. The poll sampler reads process
//! identity through `proc_pidinfo`, which is available to an ordinary user.

#![cfg(target_os = "macos")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use serde_json::Value;

fn daemon_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_agentwatchd"))
}

struct Daemon {
    root: PathBuf,
    child: Child,
}

impl Daemon {
    fn start() -> Self {
        let root = PathBuf::from(format!("/tmp/aw-e2e-mac-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("run")).unwrap();
        std::fs::create_dir_all(root.join("home")).unwrap();
        let config = root.join("config.toml");
        std::fs::write(
            &config,
            format!(
                "[storage]\ndata_dir = \"{}\"\n[api]\nhttp_port = 0\n",
                root.join("data").display()
            ),
        )
        .unwrap();
        let log = std::fs::File::create(root.join("daemon.out")).unwrap();
        let child = Command::new(daemon_bin())
            .args(["--foreground", "--config"])
            .arg(&config)
            .env("AW_SOCKET", root.join("api.sock"))
            .env("AW_SYSTEM_SOCKET", root.join("api.sock"))
            .env("HOME", root.join("home"))
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn agentwatchd");
        let daemon = Self { root, child };
        let started = Instant::now();
        while UnixStream::connect(daemon.socket()).is_err() {
            assert!(
                started.elapsed() < Duration::from_secs(15),
                "daemon did not answer: {}",
                daemon.log()
            );
            sleep(Duration::from_millis(50));
        }
        daemon
    }

    fn socket(&self) -> PathBuf {
        self.root.join("api.sock")
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.root.join("daemon.out")).unwrap_or_default()
    }

    fn http(&self, method: &str, path: &str, body: &str) -> (u16, Value) {
        let mut stream = UnixStream::connect(self.socket()).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        write!(
            stream,
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        let text = String::from_utf8_lossy(&reply).to_string();
        let status = text
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .unwrap_or(0);
        let body = text.split_once("\r\n\r\n").map_or("", |(_, body)| body);
        (status, serde_json::from_str(body).unwrap_or(Value::Null))
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn tree_contains(nodes: &Value, pid: u64) -> bool {
    nodes.as_array().is_some_and(|nodes| {
        nodes
            .iter()
            .any(|node| node["pid"] == pid || tree_contains(&node["children"], pid))
    })
}

/// The daemon, running as this user, launches `sleep 20` and the poll sampler
/// records that pid. Same assertion as the Linux root e2e, without sudo.
#[test]
fn daemon_samples_long_running_program() {
    let daemon = Daemon::start();
    let (status, body) = daemon.http(
        "POST",
        "/api/v1/sessions",
        r#"{"mode":"launch","argv":["/bin/sleep","20"]}"#,
    );
    assert_eq!(status, 201, "{body} / {}", daemon.log());
    let pid = body["root_pid"].as_u64().expect("root_pid");
    let sid = body["id"].as_str().expect("id");

    let started = Instant::now();
    let mut sampled = false;
    let mut last = Value::Null;
    while started.elapsed() < Duration::from_secs(15) {
        let (status, body) = daemon.http("GET", &format!("/api/v1/sessions/{sid}/processes"), "");
        if status == 200 && tree_contains(&body["processes"], pid) {
            sampled = true;
            break;
        }
        last = serde_json::json!({ "status": status, "body": body });
        sleep(Duration::from_millis(200));
    }
    let _ = Command::new("kill").arg(pid.to_string()).status();
    assert!(
        sampled,
        "daemon did not store a sampled row for pid {pid}: {last}; log: {}",
        daemon.log()
    );
}
