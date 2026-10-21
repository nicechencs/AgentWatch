//! Real-pseudoterminal coverage for `aw run` job control.
//!
//! The helper drives both `--no-daemon` and the daemon-backed route. The
//! latter uses this small protocol stub because terminal ownership belongs to
//! the CLI, not the collector implementation.
//!
//! The helper is waited with a deadline. `Command::output()` waits forever, and
//! a stuck helper (the macOS pty hang that has failed on `dev` since 34cf9b6)
//! held the whole CI job until the runner cancelled it. On timeout this test
//! kills the helper and every process it started — `pty.fork` puts `aw` in a
//! new session, so killing the helper alone leaves that session and anyone
//! still holding the helper's pipes — then panics with the helper's stdout and
//! stderr so the hung scenario is visible. The product terminal path is not
//! changed here.

#![cfg(unix)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// A stuck helper must fail the test, not the CI job. The scenarios themselves
/// finish in a few seconds when the terminal path works.
const HELPER_DEADLINE: Duration = Duration::from_secs(90);

struct DaemonStub {
    socket: PathBuf,
    running: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl DaemonStub {
    fn start(root: &Path) -> Self {
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
        || request.starts_with("POST /api/v1/sessions/s-pty/leftovers ")
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

/// Scratch under the crate `target/` tree. Not the system temp directory: a
/// runner's `/tmp` is shared, and the socket path has to stay short enough for
/// `sockaddr_un` when the manifest dir itself is not already huge.
fn scratch_root() -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(format!("aw-pty-{}-{nanos}", std::process::id()));
    // The pid separates parallel cargo invocations; the timestamp separates a
    // rerun that starts before the previous directory is removed.
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create pty test directory");
    dir
}

/// The helper (and the `aw` it launches) must not see the caller's policy,
/// socket, or home. A cleared `AW_POLICY` falls through to the user config, so
/// `HOME` / `XDG_CONFIG_HOME` / `APPDATA` point at the scratch directory.
fn isolate(cmd: &mut Command, home: &Path) {
    cmd.env_remove("AW_POLICY");
    cmd.env_remove("AW_INTERCEPT_AUDIT");
    cmd.env_remove("AW_TOKEN");
    cmd.env_remove("AW_HTTP");
    cmd.env_remove("AW_SYSTEM_SOCKET");
    cmd.env_remove("AW_SESSION");
    cmd.env_remove("TMPDIR");
    cmd.env("HOME", home);
    cmd.env("XDG_CONFIG_HOME", home);
    cmd.env("APPDATA", home);
}

/// Run the helper until it exits or [`HELPER_DEADLINE`] elapses.
///
/// Stdout and stderr are drained on their own threads. `Child::wait` with
/// piped output deadlocks once a pipe buffer fills, which is exactly the
/// failure mode a hung scenario would hit if the reads stayed on this thread.
///
/// Descendants are recorded from the start, not at the deadline. `aw` calls
/// `setpgid(0, 0)` and waits in its own session; when it exits, the programs
/// it started are reparented to init and a ppid walk from the helper no longer
/// finds them. Those processes can still hold the helper's pipe, so the walk
/// has to have seen them while their parent was alive.
fn run_helper(mut child: Child) -> std::process::Output {
    let stdout = child.stdout.take().expect("helper stdout piped");
    let stderr = child.stderr.take().expect("helper stderr piped");
    let out = Arc::new(Mutex::new(Vec::new()));
    let err = Arc::new(Mutex::new(Vec::new()));
    let out_buf = Arc::clone(&out);
    let err_buf = Arc::clone(&err);
    let out_thread = thread::spawn(move || drain(stdout, &out_buf));
    let err_thread = thread::spawn(move || drain(stderr, &err_buf));

    let helper_pid = child.id();
    let mut seen: Vec<u32> = vec![helper_pid];
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll pty helper") {
            break status;
        }
        remember_descendants(helper_pid, &mut seen);
        if started.elapsed() >= HELPER_DEADLINE {
            remember_descendants(helper_pid, &mut seen);
            // Kill recorded descendants before joining the readers. A survivor
            // in `aw`'s session, still holding a duplicated write end of the
            // helper's stdout pipe, would keep `drain` blocked after the
            // helper itself is gone — the same hang `Command::output()` had,
            // just one process further down.
            terminate_pids(&seen);
            let _ = child.kill();
            let _ = child.wait();
            let still_alive = wait_until_dead(&seen, Duration::from_secs(2));
            let stdout = join_drain(out_thread, &out);
            let stderr = join_drain(err_thread, &err);
            assert!(
                still_alive.is_empty(),
                "pty helper timed out and these processes survived SIGKILL: {still_alive:?}\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&stdout),
                String::from_utf8_lossy(&stderr)
            );
            panic!(
                "pty helper still running after {}s; killed helper pid {helper_pid} and {} other process(es) {seen:?}\nstdout:\n{}\nstderr:\n{}",
                HELPER_DEADLINE.as_secs(),
                seen.len().saturating_sub(1),
                String::from_utf8_lossy(&stdout),
                String::from_utf8_lossy(&stderr)
            );
        }
        thread::sleep(Duration::from_millis(50));
    };

    let stdout = join_drain(out_thread, &out);
    let stderr = join_drain(err_thread, &err);
    std::process::Output {
        status,
        stdout,
        stderr,
    }
}

fn drain(mut pipe: impl Read, into: &Mutex<Vec<u8>>) {
    let mut buf = [0_u8; 8192];
    loop {
        match pipe.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => into
                .lock()
                .expect("helper output lock")
                .extend_from_slice(&buf[..n]),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
}

fn join_drain(handle: JoinHandle<()>, buf: &Mutex<Vec<u8>>) -> Vec<u8> {
    handle.join().expect("join helper output reader");
    buf.lock().expect("helper output lock").clone()
}

/// Append every live process whose ancestry reaches `root` and is not yet in
/// `seen`.
///
/// Linux reads `/proc/<pid>/stat`. macOS has no `/proc`; `ps` prints the same
/// pid/ppid pairs there (and is the fallback wherever `/proc` is missing). The
/// walk is what stops the job from leaving `aw`'s session behind: `pty.fork`
/// calls `setsid`, so that session is not the helper's process group and
/// killing the helper does not signal it.
fn remember_descendants(root: u32, seen: &mut Vec<u32>) {
    let mut ppid_of = ppid_table();
    if ppid_of.is_empty() {
        ppid_of = ppid_table_from_ps();
    }
    let mut grew = true;
    while grew {
        grew = false;
        for &(pid, ppid) in &ppid_of {
            if (ppid == root || seen.contains(&ppid)) && !seen.contains(&pid) {
                seen.push(pid);
                grew = true;
            }
        }
    }
}

/// `(pid, ppid)` for every process that is not a zombie.
fn ppid_table() -> Vec<(u32, u32)> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut ppid_of = Vec::new();
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        // `comm` is wrapped in parentheses and may itself contain spaces and
        // parentheses. The state and ppid are the two fields after the last `)`.
        let Some(end) = stat.rfind(')') else {
            continue;
        };
        let mut fields = stat[end + 1..].split_whitespace();
        let Some(state) = fields.next() else {
            continue;
        };
        if state == "Z" {
            continue;
        }
        let Some(ppid) = fields.next().and_then(|field| field.parse::<u32>().ok()) else {
            continue;
        };
        ppid_of.push((pid, ppid));
    }
    ppid_of
}

/// macOS (and any host without `/proc`). `ps -ax -o pid=,ppid=` is POSIX and
/// prints one `pid ppid` pair per line, skipping the header because of `=`.
fn ppid_table_from_ps() -> Vec<(u32, u32)> {
    let Ok(output) = Command::new("ps")
        .args(["-ax", "-o", "pid=,ppid="])
        .output()
    else {
        return Vec::new();
    };
    let mut ppid_of = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let mut fields = line.split_whitespace();
        let Some(pid) = fields.next().and_then(|field| field.parse::<u32>().ok()) else {
            continue;
        };
        let Some(ppid) = fields.next().and_then(|field| field.parse::<u32>().ok()) else {
            continue;
        };
        ppid_of.push((pid, ppid));
    }
    ppid_of
}

fn pid_alive(pid: u32) -> bool {
    if std::path::Path::new("/proc").is_dir() {
        // `/proc/<pid>` exists for a zombie too. A zombie is not holding a pipe
        // and is reaped by its parent; treating it as alive would fail the
        // "nothing survived" check on a process that can no longer run.
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
            return false;
        };
        let Some(end) = stat.rfind(')') else {
            return false;
        };
        return stat[end + 1..].split_whitespace().next() != Some("Z");
    }
    // No `/proc`: ask `ps` for this one pid. Exit status is non-zero when the
    // process does not exist (`ps -p` on macOS and on Linux procps).
    Command::new("ps")
        .args(["-p", &pid.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Poll until every pid is gone or `budget` elapses. Returns whoever is left.
fn wait_until_dead(pids: &[u32], budget: Duration) -> Vec<u32> {
    let until = Instant::now() + budget;
    loop {
        let alive: Vec<u32> = pids.iter().copied().filter(|&pid| pid_alive(pid)).collect();
        if alive.is_empty() || Instant::now() >= until {
            return alive;
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn terminate_pids(pids: &[u32]) {
    // SIGKILL, not SIGTERM. A descendant blocked in a read of the helper's
    // pipe, or ignoring SIGTERM, must die before the drain threads are joined;
    // otherwise a leftover write end keeps `read` from returning and the
    // timeout path hangs the same way `Command::output()` did. The walk is by
    // ppid, so `aw`'s new session (it calls `setpgid(0, 0)` after `pty.fork`)
    // and that session's children are in `pids`.
    for &pid in pids {
        // `kill(1)` is not linked into this test crate (`nix` is a cfg(unix)
        // dependency of the library, and the crate denies `unsafe`). The
        // system `kill` resolves a pid the same way and needs no extra crate.
        let _ = Command::new("kill")
            .args(["-KILL", &pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

#[test]
fn pty_default_and_no_daemon_cover_input_signals_and_terminal_close() {
    if Command::new("python3").arg("--version").output().is_err() {
        panic!("python3 is required for the pty terminal regression");
    }
    let root = scratch_root();
    let daemon = DaemonStub::start(&root);
    let helper = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/terminal_pty.py");
    let mut cmd = Command::new("python3");
    cmd.arg(&helper)
        .arg(env!("CARGO_BIN_EXE_aw"))
        .env("AW_SOCKET", &daemon.socket)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    isolate(&mut cmd, &root);
    let child = cmd.spawn().expect("run pty terminal helper");
    let output = run_helper(child);
    assert!(
        output.status.success(),
        "pty helper failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    drop(daemon);
    let _ = std::fs::remove_dir_all(&root);
}
