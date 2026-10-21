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
    let echo = echo_bin();
    let mut cmd = aw();
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
