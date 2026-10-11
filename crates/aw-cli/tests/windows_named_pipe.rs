//! Windows-only R1 coverage for the real CLI named-pipe client.
//!
//! This deliberately does not inject a `Transport`: every request comes from
//! a separate built `aw` process, opens an actual named pipe, passes the
//! client-side server-token check, writes its HTTP request, and is identified
//! by the server from the pipe token after that read. Losing either the QoS
//! flag or the server's read-before-impersonate order makes this test fail.

#![cfg(windows)]
#![allow(clippy::expect_used)]

use std::ffi::OsString;
use std::os::windows::io::AsRawHandle;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use aw_collector_windows::pipe::{create_server, flush_server, pipe_sddl};
use aw_platform::{identify_pipe_peer, platform, Owner};
use tokio::net::windows::named_pipe::NamedPipeServer;

static SEQ: AtomicU32 = AtomicU32::new(0);

fn pipe_name() -> PathBuf {
    PathBuf::from(format!(
        r"\\.\pipe\agentwatch-cli-real-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::SeqCst)
    ))
}

#[test]
fn separate_aw_processes_are_identified_and_each_get_a_fresh_pipe_instance() {
    let path = pipe_name();
    let name = path.as_os_str().to_owned();
    let sddl = pipe_sddl();
    let expected = platform().current_owner().expect("current token owner");
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let (done_tx, done_rx) = mpsc::sync_channel(1);

    let server = thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let result = runtime.block_on(serve_three(name, sddl, expected, ready_tx));
        let _ = done_tx.send(result);
    });
    ready_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("temporary pipe listener ready");

    for attempt in 0..3 {
        let output = Command::new(env!("CARGO_BIN_EXE_aw"))
            .env("AW_SOCKET", &path)
            .args(["daemon", "status"])
            .output()
            .unwrap_or_else(|err| panic!("spawn aw attempt {attempt}: {err}"));
        assert!(
            output.status.success(),
            "aw attempt {attempt} failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("running"),
            "unexpected aw output: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }

    done_rx
        .recv_timeout(Duration::from_secs(15))
        .expect("server result")
        .unwrap_or_else(|err| panic!("server: {err}"));
    server.join().expect("server thread");
}

async fn serve_three(
    name: OsString,
    sddl: String,
    expected: Owner,
    ready: mpsc::SyncSender<()>,
) -> Result<(), String> {
    let mut server = create_server(&name, true, &sddl).map_err(|err| err.to_string())?;
    ready.send(()).map_err(|err| err.to_string())?;
    for request_no in 0..3 {
        server.connect().await.map_err(|err| err.to_string())?;
        // Match production ordering: reserve the next instance before serving
        // this request, so a sequential client can never race a closed pipe.
        let next = create_server(&name, false, &sddl).map_err(|err| err.to_string())?;
        read_request(&server).await?;
        let peer = identify_pipe_peer(server.as_raw_handle()).map_err(|err| err.to_string())?;
        assert_eq!(peer.owner(), &expected, "request {request_no} owner");
        write_all(
            &server,
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 18\r\nConnection: close\r\n\r\n{\"version\":\"test\"}",
        )
        .await?;
        // This exact pair is required for the one-request-per-instance
        // protocol: first guarantee the reply is visible, then disconnect.
        flush_server(server.as_raw_handle()).map_err(|err| err.to_string())?;
        server.disconnect().map_err(|err| err.to_string())?;
        server = next;
    }
    Ok(())
}

async fn read_request(server: &NamedPipeServer) -> Result<(), String> {
    let mut bytes = Vec::new();
    let mut buf = [0_u8; 1024];
    loop {
        server.readable().await.map_err(|err| err.to_string())?;
        match server.try_read(&mut buf) {
            Ok(0) => return Err("client closed before a complete request".to_owned()),
            Ok(n) => {
                bytes.extend_from_slice(&buf[..n]);
                if bytes.windows(4).any(|chunk| chunk == b"\r\n\r\n") {
                    return Ok(());
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(err) => return Err(err.to_string()),
        }
    }
}

async fn write_all(server: &NamedPipeServer, mut bytes: &[u8]) -> Result<(), String> {
    while !bytes.is_empty() {
        server.writable().await.map_err(|err| err.to_string())?;
        match server.try_write(bytes) {
            Ok(n) => bytes = &bytes[n..],
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(err) => return Err(err.to_string()),
        }
    }
    Ok(())
}
