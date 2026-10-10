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
        Command::new(aw_bin())
            .envs(env_for(&self.root))
            .env_remove("AW_TOKEN")
            .args(args)
            .stdin(Stdio::null())
            .output()
            .expect("spawn aw")
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
    let out = daemon.aw(&["run", "-q", "--", "sh", "-c", "exit 7"]);
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
    daemon.wait_ended(&sid, Duration::from_secs(10));

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
    let ended = daemon.wait_ended(&sid, Duration::from_secs(15));
    let modes: Vec<&str> = ended["collectors"]
        .as_array()
        .map(|c| c.iter().filter_map(|c| c["mode"].as_str()).collect())
        .unwrap_or_default();
    assert!(
        modes.contains(&"poll"),
        "tracked by the poll sampler: {ended}"
    );
    if let Some(code) = ended.get("exit_code").filter(|c| !c.is_null()) {
        assert_eq!(code, 7, "{ended}");
    }
}

/// Root daemon (via `sudo -n`), this test's account as the caller: the
/// launched program's uid is the caller's and its group list is exactly the
/// caller's login groups (`id -G`), supplementary groups included. Needs
/// passwordless sudo and a caller in at least one supplementary group:
/// `cargo test -p aw-daemon --test e2e_cli -- --ignored root_daemon`.
#[test]
#[ignore = "needs passwordless sudo to start a root daemon"]
fn root_daemon_launch_carries_the_callers_login_groups() {
    let me = my_uid();
    assert_ne!(
        me, 0,
        "run as an ordinary account; the daemon is the root one"
    );
    let name = String::from_utf8(
        Command::new("id")
            .arg("-un")
            .output()
            .expect("id -un")
            .stdout,
    )
    .unwrap()
    .trim()
    .to_owned();
    let want = login_groups(&name);
    let primary = proc_ids(u64::from(std::process::id()), "Gid:")[0];
    assert!(
        want.iter().any(|g| *g != primary),
        "the caller must be in a supplementary group: {want:?}"
    );
    let daemon = Daemon::start(As::Root);
    let (status, body) = daemon.http(
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
