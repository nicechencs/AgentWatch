//! End-to-end: the built `aw` and raw HTTP against a real `agentwatchd
//! --foreground` over its Unix socket (Linux; the poll sampler reads process
//! identity only there).
//!
//! Every daemon here gets its own short root `/tmp/aw-e2e-<pid>-<seq>` (socket
//! paths stay well under the 104/108-byte limit), its own `AW_SOCKET`,
//! `AW_SYSTEM_SOCKET`, `XDG_RUNTIME_DIR` and `HOME`, and no HTTP port. None
//! of them touches `/run/agentwatch`.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;
use std::thread::sleep;
use std::time::{Duration, Instant};

use serde_json::Value;

static SEQ: AtomicUsize = AtomicUsize::new(0);

fn daemon_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_agentwatchd"))
}

/// `aw`, built next to `agentwatchd`. `cargo test -p aw-daemon` alone does not
/// build it, so build it once here; a missing binary fails the test.
fn aw_bin() -> PathBuf {
    static BUILT: OnceLock<PathBuf> = OnceLock::new();
    BUILT
        .get_or_init(|| {
            let aw = daemon_bin().with_file_name("aw");
            if !aw.is_file() {
                let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
                let status = Command::new(cargo)
                    .args(["build", "-p", "aw-cli", "--bin", "aw"])
                    .status()
                    .expect("cargo build aw");
                assert!(status.success(), "building aw failed");
            }
            assert!(aw.is_file(), "aw binary missing at {}", aw.display());
            aw
        })
        .clone()
}

/// How the daemon of a [`Daemon`] is started.
enum As {
    /// This test's own account.
    Me,
    /// root through `sudo -n` (the root-gated test only).
    Root,
}

struct Daemon {
    root: PathBuf,
    child: Child,
    as_root: bool,
}

impl Daemon {
    fn start(how: As) -> Self {
        let seq = SEQ.fetch_add(1, Ordering::SeqCst);
        let root = PathBuf::from(format!("/tmp/aw-e2e-{}-{seq}", std::process::id()));
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
        let as_root = matches!(how, As::Root);
        let mut command = if as_root {
            let mut sudo = Command::new("sudo");
            sudo.arg("-n").arg("env");
            for (key, val) in env_for(&root) {
                sudo.arg(format!("{key}={}", val.display()));
            }
            sudo.arg(daemon_bin());
            sudo
        } else {
            let mut own = Command::new(daemon_bin());
            own.envs(env_for(&root));
            own
        };
        let child = command
            .args(["--foreground", "--config"])
            .arg(&config)
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .expect("spawn agentwatchd");
        let daemon = Self {
            root,
            child,
            as_root,
        };
        let started = Instant::now();
        while UnixStream::connect(daemon.socket()).is_err() {
            assert!(
                started.elapsed() < Duration::from_secs(10),
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

    fn aw(&self, args: &[&str]) -> Output {
        let mut command = if self.as_root && my_uid() == 0 {
            let mut sudo = Command::new("sudo");
            sudo.args(["-n", "-u"])
                .arg(format!("#{}", caller_uid()))
                .arg("env");
            for (key, value) in env_for(&self.root) {
                sudo.arg(format!("{key}={}", value.display()));
            }
            sudo.arg(aw_bin());
            sudo
        } else {
            let mut own = Command::new(aw_bin());
            own.envs(env_for(&self.root));
            own
        };
        command
            .env_remove("AW_TOKEN")
            .env("AW_DAEMON_CONFIG", self.root.join("config.toml"))
            .args(args)
            .stdin(Stdio::null())
            .output()
            .expect("spawn aw")
    }

    /// Run the CLI as root for administrator-only daemon operations. This is
    /// used only with an isolated root daemon and its temporary socket.
    fn aw_as_root(&self, args: &[&str]) -> Output {
        let mut command = Command::new("sudo");
        command.arg("-n").arg("env");
        for (key, value) in env_for(&self.root) {
            command.arg(format!("{key}={}", value.display()));
        }
        command
            .arg(format!(
                "AW_DAEMON_CONFIG={}",
                self.root.join("config.toml").display()
            ))
            .arg(aw_bin())
            .args(args)
            .stdin(Stdio::null())
            .output()
            .expect("spawn root aw")
    }

    /// One HTTP/1.1 request over the socket; the peer credential is the caller.
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

    /// Make one request as the original non-root caller when this ignored test
    /// is itself invoked through sudo in CI. The root daemon must not see the
    /// test runner's root credential as the launch caller.
    fn http_as_caller(&self, method: &str, path: &str, body: &str) -> (u16, Value) {
        if !(self.as_root && my_uid() == 0) {
            return self.http(method, path, body);
        }
        let out = Command::new("sudo")
            .args(["-n", "-u"])
            .arg(format!("#{}", caller_uid()))
            .arg("curl")
            .args([
                "--silent",
                "--show-error",
                "--unix-socket",
                self.socket().to_str().expect("utf-8 socket path"),
                "--request",
                method,
                "--header",
                "Content-Type: application/json",
                "--data",
                body,
                "--write-out",
                "\n%{http_code}",
            ])
            .arg(format!("http://localhost{path}"))
            .output()
            .expect("curl as caller");
        assert!(
            out.status.success(),
            "curl as caller: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let text = String::from_utf8(out.stdout).expect("curl response utf-8");
        let (body, status) = text.rsplit_once('\n').expect("curl status line");
        (
            status.parse().expect("HTTP status"),
            serde_json::from_str(body).unwrap_or(Value::Null),
        )
    }

    fn sessions(&self) -> Vec<Value> {
        let out = self.aw(&["sessions", "list", "--json"]);
        assert!(
            out.status.success(),
            "aw sessions list: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let value: Value = serde_json::from_slice(&out.stdout).expect("sessions json");
        value["sessions"].as_array().cloned().unwrap_or_default()
    }

    fn procs(&self, sid: &str) -> Value {
        let out = self.aw(&["procs", sid, "--tree", "--json"]);
        assert!(
            out.status.success(),
            "aw procs {sid}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).expect("processes json")
    }

    /// Poll the API until `sid` has ended; the session object.
    fn wait_ended(&self, sid: &str, timeout: Duration) -> Value {
        let started = Instant::now();
        loop {
            let (status, body) = self.http("GET", &format!("/api/v1/sessions/{sid}"), "");
            if status == 200 && !body["ended_ns"].is_null() {
                return body;
            }
            assert!(
                started.elapsed() < timeout,
                "session {sid} did not end ({status} {body}); log: {}",
                self.log()
            );
            sleep(Duration::from_millis(100));
        }
    }
}

/// Restart must not start a replacement while the old foreground loop still
/// owns the data-dir and IPC locks. This is deliberately a real process test:
/// the race only exists between the CLI's health polling and daemon teardown.
#[test]
fn daemon_restart_releases_locks_before_every_replacement() {
    let daemon = Daemon::start(As::Me);
    for round in 0..31 {
        let out = daemon.aw(&["daemon", "restart"]);
        assert!(
            out.status.success(),
            "restart {round} failed: {} / {}",
            String::from_utf8_lossy(&out.stderr),
            daemon.log()
        );
        let status = daemon.aw(&["daemon", "status"]);
        assert!(
            status.status.success(),
            "daemon was not up after restart {round}: {}",
            String::from_utf8_lossy(&status.stderr)
        );
    }
    let out = daemon.aw(&["daemon", "stop"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let started = Instant::now();
    while UnixStream::connect(daemon.socket()).is_ok() {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "replacement did not stop"
        );
        sleep(Duration::from_millis(50));
    }
}

/// A config update patches one schema key in the source TOML; it must neither
/// replace unrelated sections nor accept a typo as an inert setting.
#[test]
#[ignore = "needs passwordless sudo for an isolated root daemon"]
fn config_set_merges_validates_and_shows_effective_defaults() {
    let daemon = Daemon::start(As::Root);
    let config = daemon.root.join("config.toml");
    let source = std::fs::read_to_string(&config).expect("config");
    std::fs::write(
        &config,
        format!("# keep this comment\n{source}\n[debug]\npreview_ui = false # keep too\n"),
    )
    .expect("rewrite config before set");

    let out = daemon.aw_as_root(&["config", "set", "collectors.linux.tls_uprobe", "false"]);
    assert!(
        out.status.success(),
        "config set: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = std::fs::read_to_string(&config).expect("merged config");
    assert!(text.contains("# keep this comment"));
    assert!(text.contains("[storage]"));
    assert!(text.contains("[api]"));

    let get = daemon.aw_as_root(&["config", "get", "api.http_port"]);
    assert!(
        get.status.success(),
        "{}",
        String::from_utf8_lossy(&get.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&get.stdout).trim(), "0");

    let show = daemon.aw_as_root(&["config", "show"]);
    assert!(
        show.status.success(),
        "{}",
        String::from_utf8_lossy(&show.stderr)
    );
    let shown = String::from_utf8_lossy(&show.stdout);
    assert!(shown.contains("[storage]"), "{shown}");
    assert!(shown.contains("[api]"), "{shown}");

    let unknown = daemon.aw_as_root(&["config", "set", "nope.key", "1"]);
    assert_eq!(unknown.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&unknown.stderr).contains("未知配置键 \u{0060}nope.key\u{0060}"),
        "{}",
        String::from_utf8_lossy(&unknown.stderr)
    );
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let stop = self.root.join("data").join("agentwatchd.stop");
        if self.as_root {
            let _ = Command::new("sudo")
                .arg("-n")
                .arg("touch")
                .arg(&stop)
                .status();
        } else {
            let _ = std::fs::write(&stop, b"");
        }
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(5) {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                break;
            }
            sleep(Duration::from_millis(50));
        }
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        if self.as_root {
            let _ = Command::new("sudo")
                .args(["-n", "rm", "-rf"])
                .arg(&self.root)
                .status();
        } else {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
}

fn env_for(root: &Path) -> Vec<(&'static str, PathBuf)> {
    vec![
        ("AW_SOCKET", root.join("api.sock")),
        ("AW_SYSTEM_SOCKET", root.join("system.sock")),
        ("XDG_RUNTIME_DIR", root.join("run")),
        ("HOME", root.join("home")),
    ]
}

fn proc_ids(pid: u64, key: &str) -> Vec<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).expect("status");
    let line = status.lines().find(|l| l.starts_with(key)).expect(key);
    line[key.len()..]
        .split_whitespace()
        .map(|id| id.parse().expect("id"))
        .collect()
}

fn my_uid() -> u32 {
    proc_ids(u64::from(std::process::id()), "Uid:")[0]
}

/// The ordinary account that called `sudo` for the CI root-test command. When
/// this test binary itself is not root, it is already that account.
fn caller_uid() -> u32 {
    if my_uid() == 0 {
        std::env::var("SUDO_UID")
            .expect("run root tests through sudo so SUDO_UID names the caller")
            .parse()
            .expect("SUDO_UID is numeric")
    } else {
        my_uid()
    }
}

fn caller_name() -> String {
    if my_uid() == 0 {
        return std::env::var("SUDO_USER").expect("run root tests through sudo");
    }
    String::from_utf8(
        Command::new("id")
            .arg("-un")
            .output()
            .expect("id -un")
            .stdout,
    )
    .unwrap()
    .trim()
    .to_owned()
}

fn caller_primary_gid() -> u32 {
    if my_uid() == 0 {
        std::env::var("SUDO_GID")
            .expect("run root tests through sudo so SUDO_GID names the caller")
            .parse()
            .expect("SUDO_GID is numeric")
    } else {
        proc_ids(u64::from(std::process::id()), "Gid:")[0]
    }
}

/// `id -G <name>` as a sorted set: the account's login group list.
fn login_groups(name: &str) -> Vec<u32> {
    let out = Command::new("id")
        .args(["-G", name])
        .output()
        .expect("id -G");
    assert!(out.status.success(), "id -G {name}");
    let mut groups: Vec<u32> = String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .map(|g| g.parse().expect("gid"))
        .collect();
    groups.sort_unstable();
    groups.dedup();
    groups
}

/// `aw run` passes the exit code through and the session is recorded; `aw
/// attach` + `aw stop @last` end the watch and leave the process running.
#[test]
fn aw_run_attach_stop_against_a_real_daemon() {
    let daemon = Daemon::start(As::Me);
    let out = daemon.aw(&["run", "-q", "--", "sh", "-c", "sleep 1; exit 7"]);
    assert_eq!(
        out.status.code(),
        Some(7),
        "aw run: {} / {}",
        String::from_utf8_lossy(&out.stderr),
        daemon.log()
    );
    let launch = daemon
        .sessions()
        .into_iter()
        .find(|s| s["mode"] == "launch")
        .expect("aw run session listed");
    let sid = launch["id"].as_str().unwrap().to_owned();
    let ended = daemon.wait_ended(&sid, Duration::from_secs(10));
    assert!(
        ended["stats"]["process_count"].as_u64().unwrap_or(0) >= 1,
        "the root process is recorded: {ended}"
    );
    assert_eq!(ended["exit_code"], 7, "exit code recorded: {ended}");
    assert_root_exit_code(&daemon, &sid);

    // A very short-lived root may be recorded from the adopt hint. When it is
    // present, its process row must carry the caller-reaped status as well.
    let out = daemon.aw(&["run", "-q", "--", "sh", "-c", "exit 7"]);
    assert_eq!(out.status.code(), Some(7));
    let fast = daemon
        .sessions()
        .into_iter()
        .find(|s| s["mode"] == "launch" && s["id"] != sid)
        .expect("fast aw run session listed");
    let fast_id = fast["id"].as_str().unwrap().to_owned();
    let fast_ended = daemon.wait_ended(&fast_id, Duration::from_secs(10));
    if fast_ended["stats"]["process_count"].as_u64().unwrap_or(0) > 0 {
        assert_root_exit_code(&daemon, &fast_id);
    }

    let mut sleeper = Command::new("sleep").arg("30").spawn().expect("sleep");
    let pid = sleeper.id().to_string();
    let out = daemon.aw(&["attach", "--pid", &pid]);
    assert!(
        out.status.success(),
        "aw attach: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let attach = daemon
        .sessions()
        .into_iter()
        .find(|s| s["mode"] == "attach" && s["id"] != "daemon-sample")
        .expect("attach session listed");
    let attach_id = attach["id"].as_str().unwrap().to_owned();
    assert!(attach["ended_ns"].is_null(), "watching: {attach}");
    let out = daemon.aw(&["stop", "@last"]);
    assert!(
        out.status.success(),
        "aw stop: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    daemon.wait_ended(&attach_id, Duration::from_secs(10));
    assert!(
        matches!(sleeper.try_wait(), Ok(None)),
        "stopping the watch must not end the process"
    );
    let _ = sleeper.kill();
    let _ = sleeper.wait();
}

fn assert_root_exit_code(daemon: &Daemon, sid: &str) {
    let procs = daemon.procs(sid);
    let roots: Vec<&Value> = procs["processes"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|row| row["depth"] == 0)
        .collect();
    assert_eq!(roots.len(), 1, "one depth-0 root row: {procs}");
    assert_eq!(
        roots[0]["exit_code"], 7,
        "the launched root process row records its own exit code: {procs}"
    );
}

/// A program the daemon launches (the App's `POST /sessions` launch) starts
/// as the caller and is tracked to its end by the poll sampler. That path has
/// no cgroup step at all, so it works on a machine without cgroup v2
/// delegation; this test runs on both and asserts the same thing either way.
#[test]
fn daemon_launch_starts_and_tracks_without_cgroup() {
    let delegated = std::fs::read_to_string("/sys/fs/cgroup/cgroup.subtree_control")
        .map(|controllers| !controllers.trim().is_empty())
        .unwrap_or(false);
    eprintln!("cgroup v2 controllers delegated at the root: {delegated}");
    let daemon = Daemon::start(As::Me);
    let (status, body) = daemon.http(
        "POST",
        "/api/v1/sessions",
        r#"{"mode":"launch","argv":["sh","-c","sleep 1; exit 7"]}"#,
    );
    assert_eq!(status, 201, "{body} / {}", daemon.log());
    let pid = body["root_pid"].as_u64().expect("root_pid");
    let sid = body["id"].as_str().expect("id").to_owned();
    assert_eq!(
        proc_ids(pid, "Uid:"),
        vec![my_uid(); 4],
        "runs as the caller"
    );
    // Recording while the program runs: not ended before it exits.
    let (_, live) = daemon.http("GET", &format!("/api/v1/sessions/{sid}"), "");
    assert!(
        live["ended_ns"].is_null(),
        "ended while the program runs: {live}"
    );
    assert!(
        Path::new(&format!("/proc/{pid}")).exists(),
        "program still running"
    );
    let alive_ns = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    )
    .unwrap();
    let ended = daemon.wait_ended(&sid, Duration::from_secs(15));
    assert!(
        ended["ended_ns"].as_i64().unwrap_or(0) > alive_ns,
        "ended only after the program was seen running: {ended}"
    );
    let modes: Vec<&str> = ended["collectors"]
        .as_array()
        .map(|c| c.iter().filter_map(|c| c["mode"].as_str()).collect())
        .unwrap_or_default();
    assert!(
        modes.contains(&"poll"),
        "tracked by the poll sampler: {ended}"
    );
    assert!(
        ended["stats"]["process_count"].as_u64().unwrap_or(0) >= 1,
        "the root process is recorded: {ended}"
    );
    assert_eq!(ended["exit_code"], 7, "exit code recorded: {ended}");
}

/// A session created by the very first request after the daemon starts is
/// not swept up by the startup recovery of the last run's open sessions.
#[test]
fn a_session_created_right_after_start_stays_recording() {
    let mut sleeper = Command::new("sleep").arg("30").spawn().expect("sleep");
    let daemon = Daemon::start(As::Me);
    let (status, body) = daemon.http(
        "POST",
        "/api/v1/sessions",
        &format!(r#"{{"mode":"attach","pid":{}}}"#, sleeper.id()),
    );
    assert_eq!(status, 201, "{body} / {}", daemon.log());
    let sid = body["id"].as_str().expect("id").to_owned();
    sleep(Duration::from_millis(1_500));
    let (_, now) = daemon.http("GET", &format!("/api/v1/sessions/{sid}"), "");
    assert!(now["ended_ns"].is_null(), "still recording: {now}");
    let _ = sleeper.kill();
    let _ = sleeper.wait();
}

/// Root daemon (via `sudo -n`), this test's account as the caller: the
/// launched program's uid is the caller's and its group list is exactly the
/// caller's login groups (`id -G`), supplementary groups included. Needs
/// passwordless sudo and a caller in at least one supplementary group:
/// `cargo test -p aw-daemon --test e2e_cli -- --ignored root_daemon`.
#[test]
#[ignore = "needs passwordless sudo to start a root daemon"]
fn root_daemon_launch_carries_the_callers_login_groups() {
    let me = caller_uid();
    assert_ne!(
        me, 0,
        "run as an ordinary account; the daemon is the root one"
    );
    let name = caller_name();
    let want = login_groups(&name);
    let primary = caller_primary_gid();
    assert!(
        want.iter().any(|g| *g != primary),
        "the caller must be in a supplementary group: {want:?}"
    );
    let daemon = Daemon::start(As::Root);
    let (status, body) = daemon.http_as_caller(
        "POST",
        "/api/v1/sessions",
        r#"{"mode":"launch","argv":["sleep","10"]}"#,
    );
    assert_eq!(status, 201, "{body} / {}", daemon.log());
    let pid = body["root_pid"].as_u64().expect("root_pid");
    assert_eq!(proc_ids(pid, "Uid:"), vec![me; 4]);
    assert_eq!(proc_ids(pid, "Gid:"), vec![primary; 4]);
    let mut have = proc_ids(pid, "Groups:");
    have.push(primary);
    have.sort_unstable();
    have.dedup();
    assert_eq!(have, want, "Groups of the launched program = id -G {name}");
    let _ = Command::new("kill").arg(pid.to_string()).status();
}

/// A root daemon samples a long-running program it launches for its caller.
/// This is root-only because the daemon's launch-as-caller path is the case
/// that previously only had coverage for credentials, not poll sampling.
#[test]
#[ignore = "needs root"]
fn root_daemon_samples_long_running_program() {
    let daemon = Daemon::start(As::Root);
    let (status, body) = daemon.http_as_caller(
        "POST",
        "/api/v1/sessions",
        r#"{"mode":"launch","argv":["sleep","20"]}"#,
    );
    assert_eq!(status, 201, "{body} / {}", daemon.log());
    let pid = body["root_pid"].as_u64().expect("root_pid");
    let sid = body["id"].as_str().expect("id");

    let started = Instant::now();
    let mut sampled = false;
    let mut last = Value::Null;
    while started.elapsed() < Duration::from_secs(10) {
        let (status, body) =
            daemon.http_as_caller("GET", &format!("/api/v1/sessions/{sid}/processes"), "");
        if status == 200 && process_tree_contains_pid(&body["processes"], pid) {
            sampled = true;
            break;
        }
        last = serde_json::json!({ "status": status, "body": body });
        sleep(Duration::from_millis(100));
    }
    let _ = Command::new("kill").arg(pid.to_string()).status();
    assert!(
        sampled,
        "root daemon did not store a sampled row for pid {pid}: {last}; log: {}",
        daemon.log()
    );
}

fn process_tree_contains_pid(nodes: &Value, pid: u64) -> bool {
    nodes.as_array().is_some_and(|nodes| {
        nodes
            .iter()
            .any(|node| node["pid"] == pid || process_tree_contains_pid(&node["children"], pid))
    })
}
