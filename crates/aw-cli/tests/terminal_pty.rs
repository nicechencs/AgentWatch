//! Real-pseudoterminal coverage for `aw run` job control.
//!
//! The helper drives both `--no-daemon` and the daemon-backed route. The
//! latter uses this small protocol stub because terminal ownership belongs to
//! the CLI, not the collector implementation.

#![cfg(unix)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::Command;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

struct DaemonStub {
    socket: PathBuf,
    running: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl DaemonStub {
    fn start() -> Self {
        let root = std::env::temp_dir().join(format!("aw-pty-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create pty test directory");
        let socket = root.join("api.sock");
        let listener = UnixListener::bind(&socket).expect("bind daemon stub socket");
        listener
            .set_nonblocking(true)
            .expect("make daemon stub nonblocking");
        let running = Arc::new(AtomicBool::new(true));
        let worker_running = Arc::clone(&running);
        let worker = thread::spawn(move || {
            while worker_running.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => answer(&mut stream),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            socket,
            running,
            worker: Some(worker),
        }
    }
}

impl Drop for DaemonStub {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Release);
        // Wake `accept`; closing immediately makes the helper's read return.
        drop(UnixStream::connect(&self.socket));
        if let Some(worker) = self.worker.take() {
            worker.join().expect("join daemon stub");
        }
        if let Some(root) = self.socket.parent() {
            let _ = std::fs::remove_dir_all(root);
        }
    }
}

fn answer(stream: &mut UnixStream) {
    let mut bytes = [0_u8; 4096];
    let Ok(read) = stream.read(&mut bytes) else {
        return;
    };
    let request = String::from_utf8_lossy(&bytes[..read]);
    let (status, body) = if request.starts_with("GET /health ") {
        (200, r#"{"status":"ok"}"#)
    } else if request.starts_with("POST /api/v1/sessions/run ") {
        (201, r#"{"id":"s-pty","ticket":"pty-ticket"}"#)
    } else if request.starts_with("POST /api/v1/sessions/s-pty/adopt ")
        || request.starts_with("POST /api/v1/sessions/s-pty/commit ")
        || request.starts_with("POST /api/v1/sessions/s-pty/exit ")
    {
        (200, "{}")
    } else {
        (500, r#"{"code":"unexpected_request"}"#)
    };
    let reason = if status == 200 {
        "OK"
    } else if status == 201 {
        "Created"
    } else {
        "Internal Server Error"
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
}

#[test]
fn pty_default_and_no_daemon_cover_input_signals_and_terminal_close() {
    if Command::new("python3").arg("--version").output().is_err() {
        panic!("python3 is required for the pty terminal regression");
    }
    let daemon = DaemonStub::start();
    let helper = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/terminal_pty.py");
    let output = Command::new("python3")
        .arg(helper)
        .arg(env!("CARGO_BIN_EXE_aw"))
        .env("AW_SOCKET", &daemon.socket)
        .env_remove("AW_TOKEN")
        .output()
        .expect("run pty terminal helper");
    assert!(
        output.status.success(),
        "pty helper failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
