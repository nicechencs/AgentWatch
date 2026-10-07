//! Cross-process checks for the daemon skeleton.
//!
//! These tests only create directories under the process temp dir. They never
//! touch `%ProgramData%\AgentWatch`, `/var/lib/agentwatch`, or the macOS
//! Application Support path.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_agentwatchd"))
}

fn scratch(label: &str) -> io::Result<PathBuf> {
    let nanos = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_nanos(),
        Err(_) => 0,
    };
    let dir = std::env::temp_dir().join(format!(
        "agentwatchd-{label}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn toml_basic(value: &str) -> String {
    let mut out = String::from("\"");
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

fn write_config(dir: &Path, data_dir: &Path, extra: &str) -> io::Result<PathBuf> {
    let path = dir.join("config.toml");
    let mut file = fs::File::create(&path)?;
    writeln!(
        file,
        "[storage]\ndata_dir = {}{extra}",
        toml_basic(&data_dir.display().to_string())
    )?;
    Ok(path)
}

fn minimal_body() -> io::Result<String> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/minimal.toml");
    fs::read_to_string(path)
}

fn spawn(args: &[&str]) -> io::Result<Child> {
    Command::new(bin())
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
}

fn output(args: &[&str]) -> io::Result<std::process::Output> {
    Command::new(bin())
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
}

fn wait_for_lock(lock: &Path, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if lock.is_file() {
            return true;
        }
        thread::sleep(Duration::from_millis(20));
    }
    false
}

fn kill(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn minimal_toml_parses_via_foreground_config() -> io::Result<()> {
    let root = scratch("minimal")?;
    let data = root.join("data");
    let body = minimal_body()?;
    let config = root.join("minimal.toml");
    {
        let mut file = fs::File::create(&config)?;
        writeln!(file, "[storage]")?;
        writeln!(
            file,
            "data_dir = {}",
            toml_basic(&data.display().to_string())
        )?;
        write!(file, "{body}")?;
    }
    let mut child = spawn(&["--foreground", "--config", &config.display().to_string()])?;
    let lock = data.join("agentwatchd.lock");
    let started = wait_for_lock(&lock, Duration::from_secs(5));
    fs::write(data.join("agentwatchd.stop"), b"stop\n")?;
    let finished = child.wait_timeout_ms(2_000).unwrap_or_default();
    if !finished {
        kill(&mut child);
    }
    let _ = fs::remove_dir_all(&root);
    if started && finished {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "minimal.toml foreground started={started} finished={finished}"
        )))
    }
}

#[test]
fn unknown_key_is_warned_and_illegal_value_refuses_startup() -> io::Result<()> {
    let root = scratch("keys")?;
    let data = root.join("data");
    let unknown = write_config(&root, &data, "\n[retention]\nnot_a_real_key = 1\n")?;
    // Unknown keys must not refuse startup. Stop immediately after the lock.
    let mut child = spawn(&["--foreground", "--config", &unknown.display().to_string()])?;
    let lock = data.join("agentwatchd.lock");
    let started = wait_for_lock(&lock, Duration::from_secs(5));
    fs::write(data.join("agentwatchd.stop"), b"stop\n")?;
    let finished = child.wait_timeout_ms(2_000).unwrap_or_default();
    if !finished {
        kill(&mut child);
    }
    let log = fs::read_to_string(data.join("agentwatchd.log")).unwrap_or_default();
    let warned = log.contains("unknown config key `retention.not_a_real_key` ignored");

    let illegal = root.join("illegal.toml");
    fs::write(
        &illegal,
        format!(
            "[storage]\ndata_dir = {}\n[proxy]\non_tls_reject = \"drop\"\n",
            toml_basic(&data.display().to_string())
        ),
    )?;
    let out = output(&["--foreground", "--config", &illegal.display().to_string()])?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    let refused = !out.status.success()
        && stderr.contains("invalid config value for key `proxy.on_tls_reject`");
    let _ = fs::remove_dir_all(&root);
    if started && finished && warned && refused {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "unknown/illegal started={started} finished={finished} warned={warned} refused={refused} stderr={stderr}"
        )))
    }
}

#[test]
fn schema_stdout_is_json() -> io::Result<()> {
    let out = output(&["config", "schema"])?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "schema exit {} stderr {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let trimmed = text.trim();
    let looks_like_object = trimmed.starts_with('{') && trimmed.ends_with('}');
    let titled = trimmed.contains("\"title\"") && trimmed.contains("\"DaemonConfig\"");
    if looks_like_object && titled {
        Ok(())
    } else {
        Err(io::Error::other(
            "schema stdout is not a JSON object titled DaemonConfig",
        ))
    }
}

#[test]
fn second_instance_exits_and_stop_is_ordered() -> io::Result<()> {
    let root = scratch("lock")?;
    let data = root.join("data");
    let config = write_config(&root, &data, "\n")?;
    let mut first = spawn(&["--foreground", "--config", &config.display().to_string()])?;
    let lock = data.join("agentwatchd.lock");
    if !wait_for_lock(&lock, Duration::from_secs(5)) {
        kill(&mut first);
        let _ = fs::remove_dir_all(&root);
        return Err(io::Error::other("first instance did not create the lock"));
    }

    let second = output(&["--foreground", "--config", &config.display().to_string()])?;
    let stderr = String::from_utf8_lossy(&second.stderr).to_string();
    let blocked = !second.status.success() && stderr.contains("already running");

    fs::write(data.join("agentwatchd.stop"), b"stop\n")?;
    let finished = first.wait_timeout_ms(2_000).unwrap_or_default();
    if !finished {
        kill(&mut first);
    }
    let log = fs::read_to_string(data.join("agentwatchd.log")).unwrap_or_default();
    let stop = log.find("shutdown: stop collectors");
    let batcher = log.find("batcher: received stop signal");
    let flush = log.find("shutdown: flush pipeline");
    let close = log.find("shutdown: close store");
    let ordered = match (stop, batcher, flush, close) {
        (Some(a), Some(b), Some(c), Some(d)) => a < b && b < c && c < d,
        _ => false,
    };
    let _ = fs::remove_dir_all(&root);
    if blocked && finished && ordered {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "blocked={blocked} finished={finished} ordered={ordered} stderr={stderr} log={log}"
        )))
    }
}

#[test]
fn log_probe_redacts_sensitive_fields() -> io::Result<()> {
    let root = scratch("probe")?;
    let data = root.join("data");
    let config = write_config(&root, &data, "\n")?;
    let out = output(&["--log-probe", "--config", &config.display().to_string()])?;
    let log = fs::read_to_string(data.join("agentwatchd.log")).unwrap_or_default();
    let stderr = String::from_utf8_lossy(&out.stderr);
    let leaked = log.contains("secret-argv-value")
        || log.contains("secret-env-value")
        || log.contains("secret-url-value")
        || log.contains("secret-header-value");
    let redacted = log.contains("<redacted len=");
    let _ = fs::remove_dir_all(&root);
    if out.status.success() && redacted && !leaked {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "probe success={} redacted={redacted} leaked={leaked} stderr={stderr} log={log}",
            out.status.success()
        )))
    }
}

trait WaitTimeout {
    fn wait_timeout_ms(&mut self, ms: u64) -> io::Result<bool>;
}

impl WaitTimeout for Child {
    fn wait_timeout_ms(&mut self, ms: u64) -> io::Result<bool> {
        let start = Instant::now();
        let limit = Duration::from_millis(ms);
        loop {
            if self.try_wait()?.is_some() {
                return Ok(true);
            }
            if start.elapsed() >= limit {
                return Ok(false);
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
}
