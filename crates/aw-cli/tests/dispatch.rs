//! Process-level checks for the `aw` binary.
//!
//! These tests do not pass `--http` and strip `AW_TOKEN`, so the binary takes
//! the platform socket or pipe and returns unreachable without dialing.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Command;

fn aw() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_aw"));
    cmd.env_remove("AW_TOKEN");
    cmd
}

fn output(args: &[&str]) -> std::process::Output {
    aw().args(args).output().expect("spawn aw")
}

#[test]
fn help_exits_0_and_lists_subcommands() {
    let out = output(&["--help"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let help = String::from_utf8(out.stdout).expect("utf8");
    for name in ["run", "ps", "sessions", "daemon", "version", "mcp-tap"] {
        assert!(
            help.lines()
                .any(|line| line.split_whitespace().next() == Some(name)),
            "missing `{name}`"
        );
    }
}

#[test]
fn version_exits_0() {
    let out = output(&["version"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).expect("utf8");
    assert!(text.contains("0.1.0"), "{text}");
}

#[test]
fn version_check_exits_1_and_does_not_claim_a_network_call() {
    let out = output(&["version", "--check"]);
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8(out.stderr).expect("utf8");
    assert!(err.contains("does not contact the network"), "{err}");
}

#[test]
fn ps_without_a_daemon_exits_3() {
    // A socket nobody listens on, so a daemon running on this machine (system
    // or per-user socket) cannot answer for the missing one.
    let missing = std::env::temp_dir().join(format!("aw-cli-nodaemon-{}.sock", std::process::id()));
    let out = aw()
        .env("AW_SOCKET", &missing)
        .arg("ps")
        .output()
        .expect("spawn aw");
    assert_eq!(
        out.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8(out.stderr).expect("utf8");
    assert!(err.contains("aw daemon start"), "{err}");
    assert!(err.contains("--no-daemon"), "{err}");
}

#[test]
fn unknown_command_exits_2() {
    let out = output(&["not-a-command"]);
    assert_eq!(out.status.code(), Some(2));
}

/// Real-window #144 blocker 3: `aw ps` asks the daemon over the internal
/// channel (`AW_SOCKET`) and prints what it answers. The listener here only
/// plays the daemon's `/api/v1/processes` reply; the daemon side is tested
/// in `aw-daemon` (`process_table_over_the_socket_lists_a_live_sleep`).
#[cfg(unix)]
#[test]
fn ps_reads_the_daemon_table_over_the_socket() {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;

    let dir = std::env::temp_dir().join(format!("aw-cli-ps-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    let path = dir.join("api.sock");
    let listener = UnixListener::bind(&path).expect("bind");
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).expect("read");
        let head = String::from_utf8_lossy(&buf[..n]).into_owned();
        let body = r#"{"available":true,"scope":"own","processes":[{"pid":4242,"ppid":1,"name":"sleep","user_id":"1000"}]}"#;
        let reply = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(reply.as_bytes()).expect("write");
        head
    });
    let out = aw()
        .env("AW_SOCKET", &path)
        .args(["ps", "--filter", "sleep"])
        .output()
        .expect("spawn aw");
    let head = server.join().expect("server");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(head.starts_with("GET /api/v1/processes"), "{head}");
    assert!(
        !head.to_ascii_lowercase().contains("authorization"),
        "{head}"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("sleep") && stdout.contains("4242"),
        "{stdout}"
    );
}
