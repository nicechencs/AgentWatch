//! Execute a parsed scenario and append one truth line per finished action.
//!
//! Nested `spawn` steps re-exec this binary (`sim spawn`) so each level is a
//! real OS process with its own pid. The child appends to the same truth file.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::http_step;
use crate::paths::{self, bait_bytes};
use crate::scenario::{Scenario, SetupFile, Step};
use crate::truth::TruthLine;

#[derive(Debug, Serialize, Deserialize)]
struct SpawnPayload {
    steps: Vec<Step>,
    sim_root: PathBuf,
    depth: u32,
    #[serde(default)]
    id: Option<String>,
    /// Addresses of the local test server this run started. Children inherit
    /// them so a nested step can reach HTTP, UDP, and the DNS stub.
    #[serde(default)]
    endpoints: Endpoints,
    /// Milliseconds the operator asked this run to last. `None` keeps every
    /// `duration_ms` / `hold_ms` at the value written in the scenario.
    #[serde(default)]
    duration_override_ms: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Endpoints {
    http_port: Option<u16>,
    https_port: Option<u16>,
    udp_port: Option<u16>,
    dns_port: Option<u16>,
    cert_pem: Option<PathBuf>,
    /// `false` when the scenario asked for a DNS stub and this process could
    /// not bind one. DNS steps then record `skip` instead of failing the run.
    #[serde(default = "default_true")]
    dns_available: bool,
}

fn default_true() -> bool {
    true
}

struct RunCtx<'a> {
    root: &'a Path,
    depth: u32,
    ppid: Option<u32>,
    truth: &'a Path,
    endpoints: &'a Endpoints,
    duration_override_ms: Option<u64>,
}

struct LocalServer {
    child: Child,
    // Keep the banner pipe open while the server finishes writing it.
    _stdout: std::process::ChildStdout,
    endpoints: Endpoints,
    /// Directory that holds the cert and the server's own byte log.
    scratch: PathBuf,
}

impl Drop for LocalServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.scratch);
    }
}

pub struct RunOpts {
    pub truth: PathBuf,
    /// Override the temp root. Tests pass this so they can assert cleanup.
    pub sim_root: Option<PathBuf>,
    /// Shorten `duration_ms` and `hold_ms`. `None` uses the scenario values.
    pub duration_override_ms: Option<u64>,
}

pub fn run_scenario(scenario: &Scenario, opts: &RunOpts) -> Result<(), String> {
    let root = match &opts.sim_root {
        Some(path) => {
            fs::create_dir_all(path).map_err(|err| format!("create sim root: {err}"))?;
            path.clone()
        }
        None => {
            let dir = std::env::temp_dir().join(format!(
                "agentwatch-sim-{}-{}",
                sanitize(&scenario.name),
                std::process::id()
            ));
            fs::create_dir_all(&dir).map_err(|err| format!("create sim root: {err}"))?;
            dir
        }
    };

    // Truncate once, before any child exists. Later lines (including the
    // children's) append so they cannot wipe each other.
    crate::truth::TruthLog::create(&opts.truth).map_err(|err| format!("open truth log: {err}"))?;

    let pid = std::process::id();
    let mut header = TruthLine::now("run", pid, None, true);
    header.scenario = Some(scenario.name.clone());
    header.sim_root = Some(root.display().to_string());
    header.depth = Some(0);
    append(&opts.truth, &header)?;

    let server = match start_local_server(&scenario.setup.server, &root) {
        Ok(server) => server,
        Err(err) => {
            let mut line = TruthLine::now("server", pid, None, false);
            line.error = Some(err.clone());
            append(&opts.truth, &line)?;
            return Err(err);
        }
    };
    let endpoints = server
        .as_ref()
        .map(|item| item.endpoints.clone())
        .unwrap_or_default();
    if let Some(server) = &server {
        let mut line = TruthLine::now("server", pid, None, true);
        line.depth = Some(0);
        if let Some(port) = endpoints.http_port {
            line.extra
                .insert("http_port".to_string(), serde_json::json!(port));
        }
        if let Some(port) = endpoints.https_port {
            line.extra
                .insert("https_port".to_string(), serde_json::json!(port));
        }
        if let Some(port) = endpoints.udp_port {
            line.extra
                .insert("udp_port".to_string(), serde_json::json!(port));
        }
        if let Some(port) = endpoints.dns_port {
            line.extra
                .insert("dns_port".to_string(), serde_json::json!(port));
        }
        line.extra.insert(
            "dns_available".to_string(),
            serde_json::json!(endpoints.dns_available),
        );
        let _ = server;
        append(&opts.truth, &line)?;
    }

    let setup_result = setup_files(&root, &scenario.setup.files, pid, None, &opts.truth);
    let steps_result = setup_result.and_then(|_| {
        run_steps(
            &scenario.step,
            &root,
            0,
            None,
            &opts.truth,
            &endpoints,
            opts.duration_override_ms,
        )
    });

    // The server's own byte log lives under the temp root, which is about to go.
    // Copy it beside the client truth log first so the two counts can be compared.
    if let Some(server) = &server {
        let src = server.scratch.join("server.jsonl");
        if let Some(parent) = opts.truth.parent() {
            let dest = parent.join("server.jsonl");
            if dest != src {
                let _ = fs::copy(&src, dest);
            }
        }
    }
    drop(server);

    let removed = fs::remove_dir_all(&root);
    let mut done = TruthLine::now("cleanup", pid, None, removed.is_ok());
    done.sim_root = Some(root.display().to_string());
    done.depth = Some(0);
    if let Err(err) = &removed {
        done.error = Some(format!("remove sim root: {err}"));
    }
    append(&opts.truth, &done)?;

    steps_result
}

/// Child entry: run a JSON step list inside an existing temp root and append
/// truth lines. Does not delete the temp root (the root process owns cleanup).
pub fn run_spawn_child(payload_path: &Path, truth: &Path, ppid: u32) -> Result<(), String> {
    let text =
        fs::read_to_string(payload_path).map_err(|err| format!("read spawn payload: {err}"))?;
    let payload: SpawnPayload =
        serde_json::from_str(&text).map_err(|err| format!("parse spawn payload: {err}"))?;
    note_spawn_enter(payload.depth, payload.id.as_deref(), Some(ppid), truth)?;
    if payload.steps.len() == 1 {
        if let Some(ms) = payload.steps[0]
            .lifetime_ms
            .filter(|_| payload.steps[0].action == "short_lived")
        {
            // The short-lived process exists only to exit. Its lifetime is the wait.
            thread::sleep(Duration::from_millis(ms));
            let mut line = base("short_lived", payload.depth, Some(ppid), true);
            line.extra
                .insert("lifetime_ms".to_string(), serde_json::json!(ms));
            append(truth, &line)?;
            return Ok(());
        }
    }
    run_steps(
        &payload.steps,
        &payload.sim_root,
        payload.depth,
        Some(ppid),
        truth,
        &payload.endpoints,
        payload.duration_override_ms,
    )
}

fn setup_files(
    root: &Path,
    files: &[SetupFile],
    pid: u32,
    ppid: Option<u32>,
    truth: &Path,
) -> Result<(), String> {
    for file in files {
        let dest = paths::under_root(root, &file.path).map_err(|err| err.to_string())?;
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).map_err(|err| format!("create bait dir: {err}"))?;
        }
        let bytes = match file.content.as_str() {
            "random" => bait_bytes(file.size),
            other => {
                let mut body = other.as_bytes().to_vec();
                if body.len() as u64 != file.size && file.size > 0 && body.is_empty() {
                    body = bait_bytes(file.size);
                }
                body
            }
        };
        let write = fs::write(&dest, &bytes);
        let mut line = TruthLine::now("setup_file", pid, ppid, write.is_ok());
        line.path = Some(dest.display().to_string());
        line.bytes = Some(bytes.len() as u64);
        if let Err(err) = &write {
            line.error = Some(err.to_string());
        }
        append(truth, &line)?;
        write.map_err(|err| format!("write bait {}: {err}", file.path))?;
    }
    Ok(())
}

fn run_steps(
    steps: &[Step],
    root: &Path,
    depth: u32,
    ppid: Option<u32>,
    truth: &Path,
    endpoints: &Endpoints,
    duration_override_ms: Option<u64>,
) -> Result<(), String> {
    let ctx = RunCtx {
        root,
        depth,
        ppid,
        truth,
        endpoints,
        duration_override_ms,
    };
    for step in steps {
        run_step(step, &ctx)?;
    }
    Ok(())
}

fn run_step(step: &Step, ctx: &RunCtx<'_>) -> Result<(), String> {
    match step.action.as_str() {
        "spawn" => spawn_child(step, ctx),
        "exec" => exec_step(step, ctx),
        "read_file" => read_file(step, ctx),
        "write_file" | "create" => write_file(step, ctx),
        "delete" => delete_path(step, ctx),
        "rename" => rename_path(step, ctx),
        "http_upload" => http_upload(step, ctx),
        "http_download" => http_download(step, ctx),
        "dns_lookup" => dns_lookup(step, ctx),
        "udp_send" => udp_send(step, ctx),
        "long_conn" => long_conn(step, ctx),
        "repeat" => repeat_step(step, ctx),
        "sleep" => sleep_step(step, ctx),
        other => {
            let mut line = base(other, ctx.depth, ctx.ppid, false);
            line.error = Some(format!("action `{other}` is not implemented"));
            append(ctx.truth, &line)?;
            Err(format!(
                "unsupported action `{other}` (implemented: spawn, exec, read_file, write_file, create, delete, rename, http_upload, http_download, dns_lookup, udp_send, long_conn, repeat, sleep)"
            ))
        }
    }
}

fn spawn_child(step: &Step, ctx: &RunCtx<'_>) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|err| format!("current_exe: {err}"))?;
    let payload = SpawnPayload {
        steps: step.steps.clone(),
        sim_root: ctx.root.to_path_buf(),
        depth: ctx.depth + 1,
        id: step.id.clone(),
        endpoints: ctx.endpoints.clone(),
        duration_override_ms: ctx.duration_override_ms,
    };
    let payload_path = ctx.root.join(format!(
        ".spawn-{}-{}-{}.json",
        ctx.depth,
        std::process::id(),
        step.id.as_deref().unwrap_or("anon")
    ));
    let json = serde_json::to_vec(&payload).map_err(|err| format!("encode spawn: {err}"))?;
    fs::write(&payload_path, json).map_err(|err| format!("write spawn payload: {err}"))?;

    let child = Command::new(&exe)
        .arg("spawn")
        .arg("--payload")
        .arg(&payload_path)
        .arg("--truth")
        .arg(ctx.truth)
        .arg("--ppid")
        .arg(std::process::id().to_string())
        .status();

    let (ok, error) = match child {
        Ok(status) if status.success() => (true, None),
        Ok(status) => (false, Some(format!("spawn child exit {status}"))),
        Err(err) => (false, Some(err.to_string())),
    };

    // The child's own lines already carry its pid. Read the newest spawn
    // marker the child wrote so the parent row can name that pid.
    let spawned = read_spawned_pid(ctx.truth, ctx.depth + 1, step.id.as_deref());

    let mut line = base("spawn", ctx.depth, ctx.ppid, ok);
    line.id = step.id.clone();
    line.spawned_pid = spawned;
    line.error = error;
    if let Some(ms) = step.lifetime_ms {
        line.extra
            .insert("lifetime_ms".to_string(), serde_json::json!(ms));
    }
    append(ctx.truth, &line)?;

    let _ = fs::remove_file(&payload_path);
    if ok {
        Ok(())
    } else {
        Err(line
            .error
            .clone()
            .unwrap_or_else(|| "spawn failed".to_string()))
    }
}

fn read_spawned_pid(truth: &Path, depth: u32, id: Option<&str>) -> Option<u32> {
    let text = fs::read_to_string(truth).ok()?;
    let mut found = None;
    for raw in text.lines() {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) else {
            continue;
        };
        if value.get("action").and_then(|v| v.as_str()) != Some("spawn_enter") {
            continue;
        }
        if value.get("depth").and_then(|v| v.as_u64()) != Some(u64::from(depth)) {
            continue;
        }
        if let Some(want) = id {
            if value.get("id").and_then(|v| v.as_str()) != Some(want) {
                continue;
            }
        }
        found = value.get("pid").and_then(|v| v.as_u64()).map(|n| n as u32);
    }
    found
}

/// Called at the start of a spawn child so the parent can learn this pid even
/// when the payload's first step fails.
pub fn note_spawn_enter(
    depth: u32,
    id: Option<&str>,
    ppid: Option<u32>,
    truth: &Path,
) -> Result<(), String> {
    let mut line = base("spawn_enter", depth, ppid, true);
    line.id = id.map(str::to_string);
    append(truth, &line)
}

fn read_file(step: &Step, ctx: &RunCtx<'_>) -> Result<(), String> {
    let rel = required_path(step)?;
    let path = match paths::under_root(ctx.root, rel) {
        Ok(path) => path,
        Err(err) => {
            let mut line = base("read_file", ctx.depth, ctx.ppid, false);
            line.path = Some(rel.to_string());
            line.error = Some(err.to_string());
            append(ctx.truth, &line)?;
            return Err(err.to_string());
        }
    };
    let mode = step.mode.as_deref().unwrap_or("read");
    let read = fs::read(&path);
    let mut line = base("read_file", ctx.depth, ctx.ppid, read.is_ok());
    line.path = Some(path.display().to_string());
    line.extra.insert(
        "mode".to_string(),
        serde_json::Value::String(mode.to_string()),
    );
    match read {
        Ok(buf) => {
            line.bytes = Some(buf.len() as u64);
            append(ctx.truth, &line)
        }
        Err(err) => {
            line.error = Some(err.to_string());
            append(ctx.truth, &line)?;
            Err(format!("read_file {rel}: {err}"))
        }
    }
}

fn write_file(step: &Step, ctx: &RunCtx<'_>) -> Result<(), String> {
    let rel = required_path(step)?;
    let path = match paths::under_root(ctx.root, rel) {
        Ok(path) => path,
        Err(err) => {
            let mut line = base(&step.action, ctx.depth, ctx.ppid, false);
            line.path = Some(rel.to_string());
            line.error = Some(err.to_string());
            append(ctx.truth, &line)?;
            return Err(err.to_string());
        }
    };
    if let Some(parent) = path.parent() {
        if let Err(err) = fs::create_dir_all(parent) {
            let mut line = base(&step.action, ctx.depth, ctx.ppid, false);
            line.path = Some(path.display().to_string());
            line.error = Some(err.to_string());
            append(ctx.truth, &line)?;
            return Err(format!("create parent: {err}"));
        }
    }
    let nbytes = step.bytes.unwrap_or(0);
    let body = bait_bytes(nbytes);
    let write = fs::write(&path, &body);
    let mut line = base(&step.action, ctx.depth, ctx.ppid, write.is_ok());
    line.path = Some(path.display().to_string());
    line.bytes = Some(body.len() as u64);
    match write {
        Ok(()) => append(ctx.truth, &line),
        Err(err) => {
            line.error = Some(err.to_string());
            append(ctx.truth, &line)?;
            Err(format!("{} {rel}: {err}", step.action))
        }
    }
}

fn delete_path(step: &Step, ctx: &RunCtx<'_>) -> Result<(), String> {
    let rel = required_path(step)?;
    let path = match paths::under_root(ctx.root, rel) {
        Ok(path) => path,
        Err(err) => {
            let mut line = base("delete", ctx.depth, ctx.ppid, false);
            line.path = Some(rel.to_string());
            line.error = Some(err.to_string());
            append(ctx.truth, &line)?;
            return Err(err.to_string());
        }
    };
    let result = if path.is_dir() {
        fs::remove_dir_all(&path)
    } else {
        fs::remove_file(&path)
    };
    let mut line = base("delete", ctx.depth, ctx.ppid, result.is_ok());
    line.path = Some(path.display().to_string());
    match result {
        Ok(()) => append(ctx.truth, &line),
        Err(err) => {
            line.error = Some(err.to_string());
            append(ctx.truth, &line)?;
            Err(format!("delete {rel}: {err}"))
        }
    }
}

fn rename_path(step: &Step, ctx: &RunCtx<'_>) -> Result<(), String> {
    let from_rel = step
        .from
        .as_deref()
        .ok_or_else(|| "rename requires `from`".to_string())?;
    let to_rel = step
        .to
        .as_deref()
        .ok_or_else(|| "rename requires `to`".to_string())?;
    let from = paths::under_root(ctx.root, from_rel).map_err(|err| err.to_string())?;
    let to = paths::under_root(ctx.root, to_rel).map_err(|err| err.to_string())?;
    if let Some(parent) = to.parent() {
        fs::create_dir_all(parent).map_err(|err| format!("create rename parent: {err}"))?;
    }
    let result = fs::rename(&from, &to);
    let mut line = base("rename", ctx.depth, ctx.ppid, result.is_ok());
    line.from = Some(from.display().to_string());
    line.to = Some(to.display().to_string());
    match result {
        Ok(()) => append(ctx.truth, &line),
        Err(err) => {
            line.error = Some(err.to_string());
            append(ctx.truth, &line)?;
            Err(format!("rename {from_rel} -> {to_rel}: {err}"))
        }
    }
}

fn http_upload(step: &Step, ctx: &RunCtx<'_>) -> Result<(), String> {
    let url = step
        .url
        .clone()
        .ok_or_else(|| "http_upload requires `url`".to_string())?;
    let url = substitute_ports(&url, ctx.endpoints);
    let bytes = step.bytes.unwrap_or(0);
    let outcome = http_step::upload(&url, bytes, ctx.endpoints.cert_pem.as_deref());
    let mut line = base("http_upload", ctx.depth, ctx.ppid, outcome.ok);
    line.url = Some(redact_url(&url));
    line.local = outcome.local;
    line.remote = outcome.remote;
    line.app_bytes = Some(if outcome.ok { outcome.app_bytes } else { bytes });
    line.bytes = Some(if outcome.ok { outcome.app_bytes } else { bytes });
    line.error = outcome.error;
    // A refused connection is recorded, not fatal: smoke still runs with no server.
    append(ctx.truth, &line)
}

fn http_download(step: &Step, ctx: &RunCtx<'_>) -> Result<(), String> {
    let url = step
        .url
        .clone()
        .ok_or_else(|| "http_download requires `url`".to_string())?;
    let url = substitute_ports(&url, ctx.endpoints);
    let outcome = http_step::download(&url, ctx.endpoints.cert_pem.as_deref());
    let mut line = base("http_download", ctx.depth, ctx.ppid, outcome.ok);
    line.url = Some(redact_url(&url));
    line.local = outcome.local;
    line.remote = outcome.remote;
    line.app_bytes = Some(outcome.app_bytes);
    line.bytes = Some(outcome.app_bytes);
    line.error = outcome.error;
    append(ctx.truth, &line)
}

fn dns_lookup(step: &Step, ctx: &RunCtx<'_>) -> Result<(), String> {
    let name = step
        .name
        .clone()
        .ok_or_else(|| "dns_lookup requires `name`".to_string())?;
    if !name_is_test_zone(&name) {
        let mut line = base("dns_lookup", ctx.depth, ctx.ppid, false);
        line.name = Some(name);
        line.error = Some("dns names must be under agentwatch.test".to_string());
        append(ctx.truth, &line)?;
        return Err("dns_lookup refused a name outside agentwatch.test".to_string());
    }
    if !ctx.endpoints.dns_available {
        let mut line = base("dns_lookup", ctx.depth, ctx.ppid, true);
        line.name = Some(name);
        line.extra
            .insert("skip".to_string(), serde_json::json!(true));
        line.extra.insert(
            "reason".to_string(),
            serde_json::json!("dns stub unavailable"),
        );
        return append(ctx.truth, &line);
    }
    let looked = match ctx.endpoints.dns_port {
        Some(port) => query_stub(&name, port).map(|n| (n, "stub")),
        None => {
            let query = if name.contains(':') {
                name.clone()
            } else {
                format!("{name}:0")
            };
            query
                .to_socket_addrs()
                .map(|iter| (iter.count(), "system"))
                .map_err(|err| err.to_string())
        }
    };
    let mut line = base("dns_lookup", ctx.depth, ctx.ppid, looked.is_ok());
    line.name = Some(name);
    match looked {
        Ok((n, via)) => {
            line.extra
                .insert("answers".to_string(), serde_json::json!(n));
            line.extra.insert("via".to_string(), serde_json::json!(via));
            // NXDOMAIN (zero answers) is a completed lookup, not a failed step.
            line.ok = true;
            append(ctx.truth, &line)
        }
        Err(err) => {
            line.ok = false;
            line.error = Some(err.to_string());
            append(ctx.truth, &line)
        }
    }
}

fn udp_send(step: &Step, ctx: &RunCtx<'_>) -> Result<(), String> {
    let dest = step
        .dest
        .clone()
        .or_else(|| {
            ctx.endpoints
                .udp_port
                .map(|port| format!("127.0.0.1:{port}"))
        })
        .ok_or_else(|| "udp_send requires `dest` or a local udp listener".to_string())?;
    let dest = substitute_ports(&dest, ctx.endpoints);
    let addr: SocketAddr = dest
        .parse()
        .map_err(|_| format!("udp_send dest is not 127.0.0.1:<port>: {dest}"))?;
    if !addr.ip().is_loopback() {
        let mut line = base("udp_send", ctx.depth, ctx.ppid, false);
        line.error = Some("udp_send only sends to 127.0.0.1".to_string());
        append(ctx.truth, &line)?;
        return Err("udp_send refused a non-loopback destination".to_string());
    }
    let nbytes = step.bytes.unwrap_or(32).min(1400);
    let body = bait_bytes(nbytes);
    let socket = UdpSocket::bind("127.0.0.1:0").map_err(|err| format!("bind udp: {err}"))?;
    let sent = socket.send_to(&body, addr);
    let mut line = base("udp_send", ctx.depth, ctx.ppid, sent.is_ok());
    line.local = socket.local_addr().ok().map(|a| a.to_string());
    line.remote = Some(addr.to_string());
    line.bytes = Some(nbytes);
    line.app_bytes = Some(nbytes);
    match sent {
        Ok(n) => {
            line.bytes = Some(n as u64);
            line.app_bytes = Some(n as u64);
            if ctx
                .endpoints
                .udp_port
                .is_some_and(|port| addr == SocketAddr::from(([127, 0, 0, 1], port)))
            {
                // The local server writes its truth line before echoing. Wait
                // for that echo so cleanup cannot copy the log too early.
                let echoed = (|| {
                    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
                    let mut echo = [0u8; 2048];
                    let (len, peer) = socket.recv_from(&mut echo)?;
                    if peer != addr || echo[..len] != body[..n] {
                        return Err(std::io::Error::other("unexpected local UDP echo"));
                    }
                    Ok(())
                })();
                if let Err(err) = echoed {
                    line.ok = false;
                    line.error = Some(err.to_string());
                    append(ctx.truth, &line)?;
                    return Err(format!("udp_send echo: {err}"));
                }
            }
            append(ctx.truth, &line)
        }
        Err(err) => {
            line.error = Some(err.to_string());
            append(ctx.truth, &line)?;
            Err(format!("udp_send: {err}"))
        }
    }
}

fn long_conn(step: &Step, ctx: &RunCtx<'_>) -> Result<(), String> {
    let url = step
        .url
        .clone()
        .ok_or_else(|| "long_conn requires `url`".to_string())?;
    let url = substitute_ports(&url, ctx.endpoints);
    let hold = scale_ms(
        step.hold_ms.unwrap_or(30_000),
        ctx.duration_override_ms,
        30_000,
    );
    let addr = http_addr(&url)?;
    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5));
    let mut line = base("long_conn", ctx.depth, ctx.ppid, stream.is_ok());
    line.url = Some(redact_url(&url));
    line.remote = Some(addr.to_string());
    match stream {
        Ok(stream) => {
            line.local = stream.local_addr().ok().map(|a| a.to_string());
            // Hold the TCP connection open. No request is written, so no body exists.
            // A zero-length probe keeps the socket from being treated as idle by the
            // local listener's read timeout; nothing is sent.
            let started = Instant::now();
            let probe = hold_open(&stream, hold);
            if let Err(err) = probe {
                line.ok = false;
                line.error = Some(err.clone());
            }
            let elapsed = started.elapsed().as_millis() as u64;
            line.extra
                .insert("hold_ms".to_string(), serde_json::json!(hold));
            line.extra
                .insert("elapsed_ms".to_string(), serde_json::json!(elapsed));
            append(ctx.truth, &line)
        }
        Err(err) => {
            line.error = Some(err.to_string());
            append(ctx.truth, &line)?;
            Err(format!("long_conn: {err}"))
        }
    }
}

fn repeat_step(step: &Step, ctx: &RunCtx<'_>) -> Result<(), String> {
    let times = scaled_times(step, ctx.duration_override_ms);
    let mut line = base("repeat", ctx.depth, ctx.ppid, true);
    line.extra
        .insert("times".to_string(), serde_json::json!(times));
    if let Some(ms) = step.duration_ms {
        line.extra
            .insert("duration_ms".to_string(), serde_json::json!(ms));
    }
    append(ctx.truth, &line)?;
    for _ in 0..times {
        for child in &step.steps {
            run_step(child, ctx)?;
        }
    }
    Ok(())
}

fn exec_step(step: &Step, ctx: &RunCtx<'_>) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|err| format!("current_exe: {err}"))?;
    let mut argv = step.argv.clone();
    if argv.is_empty() {
        argv.push("--version".to_string());
    }
    // Re-exec this binary. `sim argv-echo` exits immediately after printing
    // nothing: the point is the OS-visible argument vector, which the truth
    // line records. No shell is involved, so spaces and non-ASCII stay one argv.
    let child = Command::new(&exe)
        .arg("argv-echo")
        .args(&argv)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let (ok, error) = match child {
        Ok(status) if status.success() => (true, None),
        Ok(status) => (false, Some(format!("exec exit {status}"))),
        Err(err) => (false, Some(err.to_string())),
    };
    let mut line = base("exec", ctx.depth, ctx.ppid, ok);
    line.id = step.id.clone();
    line.extra.insert(
        "argv".to_string(),
        serde_json::Value::Array(
            argv.iter()
                .cloned()
                .map(serde_json::Value::String)
                .collect(),
        ),
    );
    line.error = error.clone();
    append(ctx.truth, &line)?;
    if ok {
        Ok(())
    } else {
        Err(error.unwrap_or_else(|| "exec failed".to_string()))
    }
}

fn sleep_step(step: &Step, ctx: &RunCtx<'_>) -> Result<(), String> {
    let ms = step.ms.unwrap_or(0);
    thread::sleep(Duration::from_millis(ms));
    let mut line = base("sleep", ctx.depth, ctx.ppid, true);
    line.extra.insert("ms".to_string(), serde_json::json!(ms));
    append(ctx.truth, &line)
}

/// `SIM_DURATION_MS` / `--duration` scales a block written for `duration_ms`.
/// A step with no `duration_ms` keeps `times` (the count is the load, not a clock).
fn scaled_times(step: &Step, override_ms: Option<u64>) -> u64 {
    let times = step.times.unwrap_or(1);
    let Some(nominal) = step.duration_ms else {
        return times;
    };
    let Some(want) = override_ms else {
        return times;
    };
    if nominal == 0 || want >= nominal {
        return times;
    }
    // Keep at least one iteration so the shape of the load is still observable.
    ((times.saturating_mul(want)) / nominal).max(1)
}

fn scale_ms(nominal: u64, override_ms: Option<u64>, full: u64) -> u64 {
    let Some(want) = override_ms else {
        return nominal;
    };
    if full == 0 || want >= full {
        return nominal;
    }
    (nominal.saturating_mul(want) / full).max(1)
}

fn substitute_ports(text: &str, endpoints: &Endpoints) -> String {
    let mut out = text.to_string();
    if let Some(port) = endpoints.http_port {
        out = out.replace("{http_port}", &port.to_string());
    }
    if let Some(port) = endpoints.https_port {
        out = out.replace("{https_port}", &port.to_string());
    }
    if let Some(port) = endpoints.udp_port {
        out = out.replace("{udp_port}", &port.to_string());
    }
    if let Some(port) = endpoints.dns_port {
        out = out.replace("{dns_port}", &port.to_string());
    }
    out
}

/// Drop a query string before the URL is written. Byte counts live in `bytes`.
fn redact_url(url: &str) -> String {
    match url.split_once('?') {
        Some((path, _)) => path.to_string(),
        None => url.to_string(),
    }
}

fn name_is_test_zone(name: &str) -> bool {
    let host = name.split(':').next().unwrap_or(name);
    let host = host.trim_end_matches('.');
    host.eq_ignore_ascii_case("agentwatch.test")
        || host.to_ascii_lowercase().ends_with(".agentwatch.test")
}

/// Stay connected for `hold` ms. Every few seconds, read with a short timeout.
/// `WouldBlock` means the peer is still there and sent nothing, which is what
/// this step wants. A real close or error ends the hold early.
fn hold_open(stream: &TcpStream, hold: u64) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_millis(hold);
    let mut buf = [0u8; 8];
    while Instant::now() < deadline {
        let slice = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_secs(2));
        stream
            .set_read_timeout(Some(slice))
            .map_err(|err| format!("timeout: {err}"))?;
        match stream.peek(&mut buf) {
            Ok(0) => return Err("peer closed the long connection".to_string()),
            Ok(_) => return Err("peer sent bytes on the long connection".to_string()),
            Err(err)
                if err.kind() == std::io::ErrorKind::WouldBlock
                    || err.kind() == std::io::ErrorKind::TimedOut => {}
            Err(err) => return Err(err.to_string()),
        }
    }
    Ok(())
}

fn http_addr(url: &str) -> Result<SocketAddr, String> {
    let rest = url
        .split_once("://")
        .map(|(_, rest)| rest)
        .ok_or_else(|| format!("not a url: {url}"))?;
    let host = rest.split('/').next().unwrap_or(rest);
    host.parse::<SocketAddr>()
        .map_err(|_| format!("long_conn url has no ip:port: {url}"))
}

/// One question, one answer count. NXDOMAIN is `Ok(0)`.
fn query_stub(name: &str, port: u16) -> Result<usize, String> {
    let packet = dns_query(name)?;
    let socket = UdpSocket::bind("127.0.0.1:0").map_err(|err| format!("bind dns: {err}"))?;
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|err| format!("dns timeout: {err}"))?;
    socket
        .send_to(&packet, SocketAddr::from(([127, 0, 0, 1], port)))
        .map_err(|err| format!("send dns: {err}"))?;
    let mut buf = [0u8; 512];
    let (n, _) = socket
        .recv_from(&mut buf)
        .map_err(|err| format!("recv dns: {err}"))?;
    if n < 12 {
        return Err("short dns response".to_string());
    }
    let rcode = buf[3] & 0x0f;
    if rcode == 3 {
        return Ok(0);
    }
    if rcode != 0 {
        return Err(format!("dns rcode {rcode}"));
    }
    Ok(u16::from_be_bytes([buf[6], buf[7]]) as usize)
}

fn dns_query(name: &str) -> Result<Vec<u8>, String> {
    let mut out = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    let host = name.trim_end_matches('.').split(':').next().unwrap_or(name);
    for label in host.split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes.len() > 63 {
            return Err(format!("dns label rejected: {label}"));
        }
        out.push(bytes.len() as u8);
        out.extend_from_slice(bytes);
    }
    out.push(0);
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    Ok(out)
}

fn required_path(step: &Step) -> Result<&str, String> {
    step.path
        .as_deref()
        .ok_or_else(|| format!("{} requires `path`", step.action))
}

fn base(action: &str, depth: u32, ppid: Option<u32>, ok: bool) -> TruthLine {
    let mut line = TruthLine::now(action, std::process::id(), ppid, ok);
    line.depth = Some(depth);
    line
}

fn append(truth: &Path, line: &TruthLine) -> Result<(), String> {
    // Spawn children share this file with the parent. Open-append per line so
    // writers do not truncate each other. Lines are small and written whole.
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(truth)
        .map_err(|err| format!("open truth log: {err}"))?;
    let mut buf = serde_json::to_vec(line).map_err(|err| format!("encode truth: {err}"))?;
    buf.push(b'\n');
    file.write_all(&buf)
        .map_err(|err| format!("write truth: {err}"))?;
    file.flush().map_err(|err| format!("flush truth: {err}"))
}

/// Start `sim serve` when the scenario declares `[setup].server`.
///
/// The child binds `127.0.0.1` only. Its certificate stays under the sim temp
/// root and is deleted with that root; nothing is installed into a trust store.
fn start_local_server(
    hint: &Option<crate::scenario::ServerHint>,
    root: &Path,
) -> Result<Option<LocalServer>, String> {
    let Some(hint) = hint else {
        return Ok(None);
    };
    if !hint.http && !hint.https {
        return Ok(None);
    }
    let scratch = root.join(".server");
    fs::create_dir_all(&scratch).map_err(|err| format!("server dir: {err}"))?;
    let truth = scratch.join("server.jsonl");
    let cert_out = scratch.join("cert");
    let exe = std::env::current_exe().map_err(|err| format!("current_exe: {err}"))?;
    let http = format!("127.0.0.1:{}", hint.http_port.unwrap_or(0));
    let https = format!("127.0.0.1:{}", hint.https_port.unwrap_or(0));
    let mut cmd = Command::new(exe);
    cmd.arg("serve")
        .arg("--http")
        .arg(&http)
        .arg("--https")
        .arg(&https)
        .arg("--truth")
        .arg(&truth)
        .arg("--cert-out")
        .arg(&cert_out)
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if hint.udp {
        cmd.arg("--udp").arg("127.0.0.1:0");
    }
    if hint.dns {
        cmd.arg("--dns").arg("127.0.0.1:0");
    }
    let mut child = cmd
        .spawn()
        .map_err(|err| format!("spawn sim serve: {err}"))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| "serve stdout".to_string())?;
    let banner = read_banner(&mut stdout, hint.udp, hint.dns);
    let endpoints = match banner {
        Ok(found) => found,
        Err(err) => {
            let _ = child.kill();
            let _ = child.wait();
            if hint.dns && !hint.http {
                return Ok(None);
            }
            return Err(err);
        }
    };
    // DNS is optional. If the banner omitted it, later lookups are `skip`.
    let mut endpoints = endpoints;
    if hint.dns && endpoints.dns_port.is_none() {
        endpoints.dns_available = false;
    }
    endpoints.cert_pem = Some(cert_out.join("cert.pem"));
    Ok(Some(LocalServer {
        child,
        _stdout: stdout,
        endpoints,
        scratch,
    }))
}

fn read_banner(
    stdout: impl std::io::Read,
    want_udp: bool,
    want_dns: bool,
) -> Result<Endpoints, String> {
    let mut reader = std::io::BufReader::new(stdout);
    let mut endpoints = Endpoints {
        dns_available: true,
        ..Endpoints::default()
    };
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        let mut line = String::new();
        let n = std::io::BufRead::read_line(&mut reader, &mut line)
            .map_err(|err| format!("serve banner: {err}"))?;
        if n == 0 {
            break;
        }
        let line = line.trim();
        if let Some(port) = line.strip_prefix("http://127.0.0.1:") {
            endpoints.http_port = port.parse().ok();
        } else if let Some(port) = line.strip_prefix("https://127.0.0.1:") {
            endpoints.https_port = port.parse().ok();
        } else if let Some(port) = line.strip_prefix("udp://127.0.0.1:") {
            endpoints.udp_port = port.parse().ok();
        } else if let Some(port) = line.strip_prefix("dns://127.0.0.1:") {
            endpoints.dns_port = port.parse().ok();
        }
        let http_ready = endpoints.http_port.is_some() && endpoints.https_port.is_some();
        let udp_ready = !want_udp || endpoints.udp_port.is_some();
        let dns_ready = !want_dns || endpoints.dns_port.is_some();
        if http_ready && udp_ready && dns_ready {
            return Ok(endpoints);
        }
    }
    if endpoints.http_port.is_some() && want_dns && endpoints.dns_port.is_none() {
        endpoints.dns_available = false;
        return Ok(endpoints);
    }
    Err("sim serve did not print its listen addresses".to_string())
}

fn sanitize(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        out.push_str("scenario");
    }
    out
}
