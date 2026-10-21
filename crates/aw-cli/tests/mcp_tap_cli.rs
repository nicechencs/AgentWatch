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
    isolate(&mut cmd);
    cmd
}

/// Drop every address and policy the parent shell might have exported.
///
/// A previous run inherited `AW_SOCKET` from the outer shell and a rewrite
/// looked recorded when this test had given it nowhere to go. The child must
/// see only what this test sets.
fn isolate(cmd: &mut Command) {
    cmd.env_remove("AW_TOKEN");
    cmd.env_remove("AW_POLICY");
    cmd.env_remove("AW_SOCKET");
    cmd.env_remove("AW_SYSTEM_SOCKET");
    cmd.env_remove("AW_INTERCEPT_AUDIT");
    cmd.env_remove("AW_HTTP");
    cmd.env_remove("AW_SESSION");
    cmd.env_remove("XDG_STATE_HOME");
    cmd.env_remove("LOCALAPPDATA");
    // A cleared `AW_POLICY` falls through to the user config. Point that at an
    // empty directory this process owns, so a developer machine's real policy
    // file is not what the child reads. One directory per process: the tests
    // in this file share it and never write a policy there.
    use std::sync::Once;
    static ONCE: Once = Once::new();
    let home = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(format!("aw-mcp-home-{}", std::process::id()));
    ONCE.call_once(|| {
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).expect("config home");
    });
    cmd.env("XDG_CONFIG_HOME", &home);
    cmd.env("HOME", &home);
    cmd.env("APPDATA", &home);
}

fn echo_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_mcp_echo"))
}

/// Policy files and sockets live under the crate's `target/` directory, not
/// `/tmp` (test assets stay in the gitignored build tree). Cargo deletes
/// nothing here; each test removes its own directory.
///
/// The directory name is a counter, not a timestamp. A Unix socket path has
/// to stay under `SUN_LEN` (108 bytes on Linux, 104 on macOS). The absolute
/// `target/` path on a GitHub runner
/// (`/home/runner/work/AgentWatch/AgentWatch/...`) is already past that, so a
/// socket is never named by this absolute path. [`exchange_at`] runs `aw` with
/// this directory as its cwd and passes a short relative socket name; the
/// kernel resolves that against cwd, and the sockaddr stays short on every
/// runner. Windows has no `sockaddr_un` limit; it uses loopback HTTP instead.
fn scratch(name: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(format!("aw-mcp-{}-{}-{name}", std::process::id(), n));
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
    exchange_with(policy, None, None, None, request)
}

/// `socket` is `--socket`. `http` is `--http` plus a throwaway bearer, which
/// that flag requires. Either one is the audit address.
fn exchange_at(
    policy: Option<&std::path::Path>,
    socket: Option<&std::path::Path>,
    http: Option<&str>,
    request: &str,
) -> (i32, String, String) {
    exchange_with(policy, socket, http, None, request)
}

/// Same as [`exchange_with`], but `server` is the wrapped program and every
/// line the client receives is kept. A batch deny writes one error per refused
/// element, then the server's reply, so one `read_line` is not the whole answer.
fn exchange_all(
    policy: Option<&std::path::Path>,
    audit: Option<&std::path::Path>,
    server: &std::path::Path,
    request: &str,
) -> (i32, String, String) {
    exchange_all_env(policy, audit, server, request, &[])
}

/// [`exchange_all`] plus extra environment variables for the wrapped server.
///
/// `AW_MCP_RESULT_TEXT` is how a test asks the result stand-in to answer with
/// text other than `SECRET`. Every other `AW_*` variable stays cleared by
/// [`isolate`].
fn exchange_all_env(
    policy: Option<&std::path::Path>,
    audit: Option<&std::path::Path>,
    server: &std::path::Path,
    request: &str,
    extra_env: &[(&str, &str)],
) -> (i32, String, String) {
    let mut cmd = aw();
    cmd.arg("--socket").arg("aw-mcp-tap-nobody");
    cmd.args(["mcp-tap", "--"]).arg(server);
    if let Some(path) = policy {
        cmd.env("AW_POLICY", path);
    }
    if let Some(path) = audit {
        cmd.env("AW_INTERCEPT_AUDIT", path);
    }
    for (key, value) in extra_env {
        cmd.env(key, value);
    }
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn aw mcp-tap");
    let mut stdin = child.stdin.take().expect("stdin");
    stdin.write_all(request.as_bytes()).expect("write request");
    if !request.ends_with('\n') {
        stdin.write_all(b"\n").expect("write newline");
    }
    drop(stdin);
    let stdout = child.stdout.take().expect("stdout");
    let reader = std::thread::spawn(move || read_to_string(stdout));
    let status = wait_child(&mut child, Duration::from_secs(15));
    let stdout = reader.join().expect("reader");
    let stderr = read_to_string(child.stderr.take().expect("stderr"));
    (status, stdout, stderr)
}

/// `audit` is `AW_INTERCEPT_AUDIT`: a local jsonl line, so a rewrite has a
/// record even when no daemon is listening. `None` leaves the variable unset.
fn exchange_with(
    policy: Option<&std::path::Path>,
    socket: Option<&std::path::Path>,
    http: Option<&str>,
    audit: Option<&std::path::Path>,
    request: &str,
) -> (i32, String, String) {
    let echo = echo_bin();
    let mut cmd = aw();
    if let Some(path) = socket {
        // Bind used the absolute path. `--socket` gets only the file name, and
        // cwd is that file's directory: `aw` dials the name as given, and
        // `SUN_LEN` counts those bytes, not the runner's absolute prefix.
        cmd.current_dir(path.parent().expect("socket parent"));
        cmd.arg("--socket").arg(
            path.file_name()
                .expect("socket file name")
                .to_str()
                .expect("socket name is utf-8"),
        );
    }
    if let Some(url) = http {
        cmd.arg("--http")
            .arg(url)
            .arg("--token")
            .arg("mcp-tap-test");
    }
    // No `--socket` and no `--http`: `aw` would dial the platform default and,
    // on a machine running the daemon, write this test's audit into the real
    // database. Give it a relative name nobody listens on. The rewrite tests
    // pass `AW_INTERCEPT_AUDIT`, so a dead socket only drops the post.
    if socket.is_none() && http.is_none() {
        cmd.arg("--socket").arg("aw-mcp-tap-nobody");
    }
    cmd.args(["mcp-tap", "--"]).arg(&echo);
    if let Some(path) = policy {
        cmd.env("AW_POLICY", path);
    }
    if let Some(path) = audit {
        cmd.env("AW_INTERCEPT_AUDIT", path);
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
    // A rewrite with nowhere to record it is a deny (design §5.3). This test
    // checks the bytes the server sees, so the audit goes to a file in `dir`,
    // not to whatever `AW_SOCKET` the parent happened to export.
    let rewritten = exchange_with(
        Some(&policy),
        None,
        None,
        Some(&dir.join("audit.jsonl")),
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

const REDACT_RESULT: &str = r#"
version = 1
enabled = true

[[rule]]
id = "note-call"
layer = ["mcp"]
match.direction = { exact = "c2s" }
match.mcp_method = { exact = "tools/call" }
action = "rewrite"
rewrite.command = { replace = ["echo", "echo"] }

[[rule]]
id = "redact-result"
layer = ["mcp"]
match.direction = { exact = "s2c" }
match.arg.text = { regex = "SECRET" }
action = "rewrite"
rewrite.arg.text = { replace = ["SECRET", "XXX"] }
"#;

/// The server answers `{"result":{"text":"SECRET"}}`. The client must see
/// `XXX`, and the audit row must name the tool, the method, and the direction.
#[test]
fn response_rewrite_reaches_the_client() {
    let dir = scratch("resp");
    let policy = write_policy(&dir, REDACT_RESULT);
    let audit = dir.join("audit.jsonl");
    let server = PathBuf::from(env!("CARGO_BIN_EXE_mcp_result"));
    let (status, stdout, stderr) = exchange_all(
        Some(&policy),
        Some(&audit),
        &server,
        r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"run","arguments":{"command":"echo"}}}"#,
    );
    assert_eq!(status, 0, "stderr: {stderr}");
    assert!(
        stdout.contains("\"text\":\"XXX\""),
        "client did not see the rewritten result: {stdout}"
    );
    assert!(
        !stdout.contains("SECRET"),
        "original result reached the client: {stdout}"
    );
    let body = std::fs::read_to_string(&audit).unwrap_or_default();
    let request_row = body
        .lines()
        .find(|line| line.contains("\"event\":\"c2s\""))
        .unwrap_or("");
    assert!(
        request_row.contains("\"tool\":\"run\""),
        "audit lost the tool: {body}"
    );
    assert!(
        request_row.contains("\"mcp_method\":\"tools/call\""),
        "audit lost the method: {body}"
    );
    let response_row = body
        .lines()
        .find(|line| line.contains("\"event\":\"s2c\""))
        .unwrap_or("");
    assert!(
        response_row.contains("\"effective_action\":\"rewrite\""),
        "the response rewrite was not recorded: {body}"
    );
    assert!(
        response_row.contains("XXX"),
        "the response audit does not name the replacement: {body}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A response-direction deny, a rewrite that does not land, and a rewrite whose
/// audit cannot be written must all answer the client with a JSON-RPC error
/// for the same id. The tool already ran; the result must not reach the client,
/// and the error message must not quote it.
const RESPONSE_REQUEST: &str = r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"run","arguments":{"command":"echo"}}}"#;

/// The last audit row that names the response direction, or empty.
fn last_s2c(body: &str) -> &str {
    let mut found = "";
    for line in body.lines() {
        if line.contains("\"event\":\"s2c\"") {
            found = line;
        }
    }
    found
}

/// The client's stdout is one JSON-RPC error for id 5, and it does not contain
/// `secret` (any case). `audit` is the jsonl the tap wrote, when a path was
/// given; `None` means the test expected no file.
fn assert_response_error(stdout: &str, audit: Option<&str>) {
    let line = stdout
        .lines()
        .find(|line| line.contains("\"error\""))
        .unwrap_or_else(|| panic!("client did not get an error: {stdout}"));
    let value: serde_json::Value = serde_json::from_str(line)
        .unwrap_or_else(|err| panic!("error is not JSON ({err}): {line}"));
    assert_eq!(value["id"], serde_json::json!(5), "{value}");
    assert_eq!(value["error"]["code"], serde_json::json!(-32000), "{value}");
    let message = value["error"]["message"].as_str().unwrap_or("");
    assert!(!message.is_empty(), "error has no message: {value}");
    assert!(
        !message.to_ascii_lowercase().contains("secret"),
        "error quotes the result: {message}"
    );
    assert!(
        !stdout.to_ascii_lowercase().contains("secret"),
        "original result reached the client: {stdout}"
    );
    assert!(
        !stdout.contains("\"result\""),
        "a result object reached the client: {stdout}"
    );
    if let Some(body) = audit {
        let row = last_s2c(body);
        assert!(
            row.contains("\"effective_action\":\"deny\""),
            "the response was not recorded as a deny: {row}"
        );
        // The row names the field that matched, the way a request deny names
        // the command. It must not store the frame itself.
        assert!(
            !row.contains("\"result\""),
            "audit stored the response frame: {row}"
        );
    }
}

/// The rule matches `secret` and rewrites only the uppercase form. The server
/// answers `my secret`, the replacement does not land, and the client must see
/// an error rather than the original result (N1).
#[test]
fn response_rewrite_that_misses_is_an_error() {
    let dir = scratch("resp-miss");
    let policy = write_policy(
        &dir,
        r#"
version = 1
enabled = true

[[rule]]
id = "redact-result"
layer = ["mcp"]
match.direction = { exact = "s2c" }
match.arg.text = { regex = "(?i)secret" }
action = "rewrite"
rewrite.arg.text = { replace = ["SECRET", "XXX"] }
"#,
    );
    let audit = dir.join("audit.jsonl");
    let server = PathBuf::from(env!("CARGO_BIN_EXE_mcp_result"));
    let (status, stdout, stderr) = exchange_all_env(
        Some(&policy),
        Some(&audit),
        &server,
        RESPONSE_REQUEST,
        &[("AW_MCP_RESULT_TEXT", "my secret")],
    );
    assert_eq!(status, 0, "stderr: {stderr}");
    let body = std::fs::read_to_string(&audit).unwrap_or_default();
    assert_response_error(&stdout, Some(&body));
    let row = last_s2c(&body);
    assert!(
        row.contains("判定出错"),
        "audit does not say the decision failed: {row}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The rule rewrites `result.summary`, which this result does not have. The
/// decision fails (`判定出错`), and the client must see an error for that,
/// recorded as the deny that actually happened. `set_dotted` would invent the
/// field if the decision ever produced one, so this path is the decision
/// error, not a rewrite that failed to land.
#[test]
fn response_rewrite_of_a_missing_field_is_an_error() {
    let dir = scratch("resp-missing");
    let policy = write_policy(
        &dir,
        r#"
version = 1
enabled = true

[[rule]]
id = "redact-result"
layer = ["mcp"]
match.direction = { exact = "s2c" }
match.arg.text = { regex = "SECRET" }
action = "rewrite"
rewrite.arg.summary = { replace = ["SECRET", "XXX"] }
"#,
    );
    let audit = dir.join("audit.jsonl");
    let server = PathBuf::from(env!("CARGO_BIN_EXE_mcp_result"));
    let (status, stdout, stderr) =
        exchange_all(Some(&policy), Some(&audit), &server, RESPONSE_REQUEST);
    assert_eq!(status, 0, "stderr: {stderr}");
    let body = std::fs::read_to_string(&audit).unwrap_or_default();
    assert_response_error(&stdout, Some(&body));
    let row = last_s2c(&body);
    assert!(
        row.contains("判定出错"),
        "audit does not say the decision failed: {row}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A rewrite whose audit file cannot be created is a deny. The result must not
/// reach the client just because the record was dropped.
#[test]
fn response_rewrite_with_a_dropped_audit_is_an_error() {
    let dir = scratch("resp-dropped");
    let policy = write_policy(
        &dir,
        r#"
version = 1
enabled = true

[[rule]]
id = "redact-result"
layer = ["mcp"]
match.direction = { exact = "s2c" }
match.arg.text = { regex = "SECRET" }
action = "rewrite"
rewrite.arg.text = { replace = ["SECRET", "XXX"] }
"#,
    );
    // A path whose parent is a file cannot be created, so both the local backup
    // and the dead socket fail. No session directory either: isolate clears
    // AW_SESSION and the state variables.
    let blocked = dir.join("not-a-directory");
    std::fs::write(&blocked, "x").expect("blocker");
    let audit = blocked.join("audit.jsonl");
    let server = PathBuf::from(env!("CARGO_BIN_EXE_mcp_result"));
    let (status, stdout, stderr) =
        exchange_all(Some(&policy), Some(&audit), &server, RESPONSE_REQUEST);
    assert_eq!(status, 0, "stderr: {stderr}");
    assert!(
        stderr.contains("intercept_audit_dropped"),
        "a dropped audit was not reported: {stderr}"
    );
    assert_response_error(&stdout, None);
    assert!(
        !audit.exists(),
        "the unwritable audit path was created: {}",
        audit.display()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A deny rule on the response direction must not forward the result. The tool
/// already ran; the client gets an error for the same id and no audit of a
/// refusal that did not happen.
#[test]
fn response_deny_is_an_error_and_is_audited() {
    let dir = scratch("resp-deny");
    let policy = write_policy(
        &dir,
        r#"
version = 1
enabled = true

[[rule]]
id = "no-secret"
layer = ["mcp"]
match.direction = { exact = "s2c" }
match.arg.text = { regex = "SECRET" }
action = "deny"
reason = "不允许把这段结果交给模型"
"#,
    );
    let audit = dir.join("audit.jsonl");
    let server = PathBuf::from(env!("CARGO_BIN_EXE_mcp_result"));
    let (status, stdout, stderr) =
        exchange_all(Some(&policy), Some(&audit), &server, RESPONSE_REQUEST);
    assert_eq!(status, 0, "stderr: {stderr}");
    let body = std::fs::read_to_string(&audit).unwrap_or_default();
    assert_response_error(&stdout, Some(&body));
    assert!(
        stdout.contains("不允许把这段结果交给模型"),
        "deny reason missing: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A response batch with one element the rewrite cannot land on. That element
/// becomes its own JSON-RPC error; the element that does not match is forwarded.
#[test]
fn response_batch_element_that_misses_is_an_error() {
    let dir = scratch("resp-batch");
    let policy = write_policy(
        &dir,
        r#"
version = 1
enabled = true

[[rule]]
id = "redact-result"
layer = ["mcp"]
match.direction = { exact = "s2c" }
match.arg.text = { regex = "(?i)secret" }
action = "rewrite"
rewrite.arg.text = { replace = ["SECRET", "XXX"] }
"#,
    );
    let request = concat!(
        r#"[{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"run","arguments":{"command":"echo"}}},"#,
        r#"{"jsonrpc":"2.0","id":6,"method":"initialize","params":{}}]"#
    );
    let server = PathBuf::from(env!("CARGO_BIN_EXE_mcp_result"));
    let (status, stdout, stderr) = exchange_all_env(
        Some(&policy),
        Some(&dir.join("audit.jsonl")),
        &server,
        request,
        &[("AW_MCP_RESULT_TEXT", "my secret")],
    );
    assert_eq!(status, 0, "stderr: {stderr}");
    assert!(
        stdout.contains("\"id\":5"),
        "the missed element was not answered: {stdout}"
    );
    assert!(
        stdout.contains("-32000"),
        "the missed element was not an error: {stdout}"
    );
    assert!(
        !stdout.to_ascii_lowercase().contains("secret"),
        "the original result reached the client: {stdout}"
    );
    assert!(
        stdout.contains("protocolVersion"),
        "the unmatched element was not forwarded: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A deny that does not name a direction matches a request only. The same
/// command text inside a response is forwarded, and no audit row is written
/// for a refusal that did not happen.
#[test]
fn response_is_not_denied_by_a_rule_without_a_direction() {
    let dir = scratch("resp-default");
    let policy = write_policy(
        &dir,
        r#"
version = 1
enabled = true

[[rule]]
id = "no-rm"
layer = ["mcp"]
match.command = { regex = "rm" }
action = "deny"
reason = "不允许删除"
"#,
    );
    let audit = dir.join("audit.jsonl");
    let server = PathBuf::from(env!("CARGO_BIN_EXE_mcp_result"));
    let (status, stdout, stderr) = exchange_all_env(
        Some(&policy),
        Some(&audit),
        &server,
        RESPONSE_REQUEST,
        &[("AW_MCP_RESULT_TEXT", "rm -rf /")],
    );
    assert_eq!(status, 0, "stderr: {stderr}");
    assert!(
        stdout.contains("rm -rf /"),
        "the response was not forwarded: {stdout}"
    );
    assert!(
        !stdout.contains("\"error\""),
        "a direction-less rule denied the response: {stdout}"
    );
    let body = std::fs::read_to_string(&audit).unwrap_or_default();
    assert!(
        !body.contains("\"event\":\"s2c\""),
        "the response was audited: {body}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// One batch: the `rm` element is answered with its own id, the `echo`
/// element is what the server receives, the `terraform` element is rewritten.
#[test]
fn batch_denies_rewrites_and_forwards_per_element() {
    let dir = scratch("batch");
    let policy = write_policy(
        &dir,
        r#"
version = 1
enabled = true

[[rule]]
id = "no-rm"
layer = ["mcp"]
match.command = { prefix = "rm " }
action = "deny"
reason = "不允许删除"

[[rule]]
id = "plan-only"
layer = ["mcp"]
match.command = { prefix = "terraform apply" }
action = "rewrite"
rewrite.command = { replace = ["terraform apply", "terraform plan"] }
"#,
    );
    let request = concat!(
        r#"[{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"run","arguments":{"command":"rm -rf /"}}},"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"run","arguments":{"command":"echo ok"}}},"#,
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"run","arguments":{"command":"terraform apply"}}}]"#
    );
    let (status, stdout, stderr) = exchange_all(
        Some(&policy),
        Some(&dir.join("audit.jsonl")),
        &echo_bin(),
        request,
    );
    assert_eq!(status, 0, "stderr: {stderr}");
    assert!(
        stdout.contains("\"id\":2"),
        "denied element did not answer with its id: {stdout}"
    );
    assert!(
        stdout.contains("不允许删除"),
        "deny reason missing: {stdout}"
    );
    assert!(!stdout.contains("rm -rf"), "denied text echoed: {stdout}");
    assert!(
        stdout.contains("echo ok"),
        "allowed element was not answered by the server: {stdout}"
    );
    assert!(
        stdout.contains("terraform plan"),
        "rewritten element kept the original command: {stdout}"
    );
    assert!(
        !stdout.contains("terraform apply"),
        "original command reached the server: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A policy file that is not TOML. A `tools/call` inside a batch is denied;
/// `initialize` in the same batch is forwarded.
#[test]
fn broken_policy_denies_tools_call_inside_a_batch() {
    let dir = scratch("broken-batch");
    let policy = dir.join("broken.toml");
    std::fs::write(&policy, "this is not a policy\n").expect("policy");
    let request = concat!(
        r#"[{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}},"#,
        r#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"run","arguments":{"command":"echo hello"}}}]"#
    );
    let (status, stdout, stderr) = exchange_all(
        Some(&policy),
        Some(&dir.join("audit.jsonl")),
        &echo_bin(),
        request,
    );
    assert_eq!(status, 0, "stderr: {stderr}");
    assert!(
        stdout.contains("protocolVersion"),
        "initialize was not forwarded: {stdout}"
    );
    assert!(
        stdout.contains("\"id\":9"),
        "the tools/call was not answered: {stdout}"
    );
    assert!(
        stdout.contains("规则文件读不了"),
        "deny reason missing: {stdout}"
    );
    assert!(
        !stdout.contains("echo hello"),
        "the call reached the server: {stdout}"
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
    // Relative name, resolved by `aw` against `dir`. Binding uses the absolute
    // path (this process's cwd is not `dir`); connecting uses the short name.
    let socket = dir.join("s");
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
        let reply_body = "{\"stored\":true}";
        let reply = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{reply_body}",
            reply_body.len()
        );
        let _ = std::io::Write::write_all(&mut stream, reply.as_bytes());
    });
    let echo = echo_bin();
    let mut cmd = aw();
    cmd.current_dir(&dir);
    cmd.env("AW_POLICY", &policy).env("AW_SOCKET", "s");
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
        // `s` / `d` stay under SUN_LEN once `aw` resolves them from `dir`.
        let path = dir.join("s");
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
            // `{}` is a 200 the client used to treat as stored. The route's
            // success body is `{"stored": true}`; anything else downgrades a
            // rewrite to a deny.
            let reply_body = "{\"stored\":true}";
            let reply = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{reply_body}",
                reply_body.len()
            );
            let _ = std::io::Write::write_all(&mut stream, reply.as_bytes());
        });
        let dead = dir.join("d");
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
            let reply_body = "{\"stored\":true}";
            let reply = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{reply_body}",
                reply_body.len()
            );
            let _ = std::io::Write::write_all(&mut stream, reply.as_bytes());
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
