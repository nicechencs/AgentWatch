//! Execute a parsed scenario and append one truth line per finished action.
//!
//! Nested `spawn` steps re-exec this binary (`sim spawn`) so each level is a
//! real OS process with its own pid. The child appends to the same truth file.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::ToSocketAddrs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

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
}

pub struct RunOpts {
    pub truth: PathBuf,
    /// Override the temp root. Tests pass this so they can assert cleanup.
    pub sim_root: Option<PathBuf>,
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

    let setup_result = setup_files(&root, &scenario.setup.files, pid, None, &opts.truth);
    let steps_result =
        setup_result.and_then(|_| run_steps(&scenario.step, &root, 0, None, &opts.truth));

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
    run_steps(
        &payload.steps,
        &payload.sim_root,
        payload.depth,
        Some(ppid),
        truth,
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
) -> Result<(), String> {
    for step in steps {
        run_step(step, root, depth, ppid, truth)?;
    }
    Ok(())
}

fn run_step(
    step: &Step,
    root: &Path,
    depth: u32,
    ppid: Option<u32>,
    truth: &Path,
) -> Result<(), String> {
    match step.action.as_str() {
        "spawn" => spawn_child(step, root, depth, ppid, truth),
        "read_file" => read_file(step, root, depth, ppid, truth),
        "write_file" | "create" => write_file(step, root, depth, ppid, truth),
        "delete" => delete_path(step, root, depth, ppid, truth),
        "rename" => rename_path(step, root, depth, ppid, truth),
        "http_upload" => http_upload(step, depth, ppid, truth),
        "http_download" => http_download(step, depth, ppid, truth),
        "dns_lookup" => dns_lookup(step, depth, ppid, truth),
        "sleep" => sleep_step(step, depth, ppid, truth),
        other => {
            let mut line = base(other, depth, ppid, false);
            line.error = Some(format!("action `{other}` is not implemented in P0-SIM-02"));
            append(truth, &line)?;
            Err(format!(
                "unsupported action `{other}` (P0-SIM-02 implements spawn, read_file, write_file, create, delete, rename, http_upload, http_download, dns_lookup, sleep)"
            ))
        }
    }
}

fn spawn_child(
    step: &Step,
    root: &Path,
    depth: u32,
    ppid: Option<u32>,
    truth: &Path,
) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|err| format!("current_exe: {err}"))?;
    let payload = SpawnPayload {
        steps: step.steps.clone(),
        sim_root: root.to_path_buf(),
        depth: depth + 1,
        id: step.id.clone(),
    };
    let payload_path = root.join(format!(
        ".spawn-{}-{}-{}.json",
        depth,
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
        .arg(truth)
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
    let spawned = read_spawned_pid(truth, depth + 1, step.id.as_deref());

    let mut line = base("spawn", depth, ppid, ok);
    line.id = step.id.clone();
    line.spawned_pid = spawned;
    line.error = error;
    append(truth, &line)?;

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

fn read_file(
    step: &Step,
    root: &Path,
    depth: u32,
    ppid: Option<u32>,
    truth: &Path,
) -> Result<(), String> {
    let rel = required_path(step)?;
    let path = match paths::under_root(root, rel) {
        Ok(path) => path,
        Err(err) => {
            let mut line = base("read_file", depth, ppid, false);
            line.path = Some(rel.to_string());
            line.error = Some(err.to_string());
            append(truth, &line)?;
            return Err(err.to_string());
        }
    };
    let mode = step.mode.as_deref().unwrap_or("read");
    let read = fs::read(&path);
    let mut line = base("read_file", depth, ppid, read.is_ok());
    line.path = Some(path.display().to_string());
    line.extra.insert(
        "mode".to_string(),
        serde_json::Value::String(mode.to_string()),
    );
    match read {
        Ok(buf) => {
            line.bytes = Some(buf.len() as u64);
            append(truth, &line)
        }
        Err(err) => {
            line.error = Some(err.to_string());
            append(truth, &line)?;
            Err(format!("read_file {rel}: {err}"))
        }
    }
}

fn write_file(
    step: &Step,
    root: &Path,
    depth: u32,
    ppid: Option<u32>,
    truth: &Path,
) -> Result<(), String> {
    let rel = required_path(step)?;
    let path = match paths::under_root(root, rel) {
        Ok(path) => path,
        Err(err) => {
            let mut line = base(&step.action, depth, ppid, false);
            line.path = Some(rel.to_string());
            line.error = Some(err.to_string());
            append(truth, &line)?;
            return Err(err.to_string());
        }
    };
    if let Some(parent) = path.parent() {
        if let Err(err) = fs::create_dir_all(parent) {
            let mut line = base(&step.action, depth, ppid, false);
            line.path = Some(path.display().to_string());
            line.error = Some(err.to_string());
            append(truth, &line)?;
            return Err(format!("create parent: {err}"));
        }
    }
    let nbytes = step.bytes.unwrap_or(0);
    let body = bait_bytes(nbytes);
    let write = fs::write(&path, &body);
    let mut line = base(&step.action, depth, ppid, write.is_ok());
    line.path = Some(path.display().to_string());
    line.bytes = Some(body.len() as u64);
    match write {
        Ok(()) => append(truth, &line),
        Err(err) => {
            line.error = Some(err.to_string());
            append(truth, &line)?;
            Err(format!("{} {rel}: {err}", step.action))
        }
    }
}

fn delete_path(
    step: &Step,
    root: &Path,
    depth: u32,
    ppid: Option<u32>,
    truth: &Path,
) -> Result<(), String> {
    let rel = required_path(step)?;
    let path = match paths::under_root(root, rel) {
        Ok(path) => path,
        Err(err) => {
            let mut line = base("delete", depth, ppid, false);
            line.path = Some(rel.to_string());
            line.error = Some(err.to_string());
            append(truth, &line)?;
            return Err(err.to_string());
        }
    };
    let result = if path.is_dir() {
        fs::remove_dir_all(&path)
    } else {
        fs::remove_file(&path)
    };
    let mut line = base("delete", depth, ppid, result.is_ok());
    line.path = Some(path.display().to_string());
    match result {
        Ok(()) => append(truth, &line),
        Err(err) => {
            line.error = Some(err.to_string());
            append(truth, &line)?;
            Err(format!("delete {rel}: {err}"))
        }
    }
}

fn rename_path(
    step: &Step,
    root: &Path,
    depth: u32,
    ppid: Option<u32>,
    truth: &Path,
) -> Result<(), String> {
    let from_rel = step
        .from
        .as_deref()
        .ok_or_else(|| "rename requires `from`".to_string())?;
    let to_rel = step
        .to
        .as_deref()
        .ok_or_else(|| "rename requires `to`".to_string())?;
    let from = paths::under_root(root, from_rel).map_err(|err| err.to_string())?;
    let to = paths::under_root(root, to_rel).map_err(|err| err.to_string())?;
    if let Some(parent) = to.parent() {
        fs::create_dir_all(parent).map_err(|err| format!("create rename parent: {err}"))?;
    }
    let result = fs::rename(&from, &to);
    let mut line = base("rename", depth, ppid, result.is_ok());
    line.from = Some(from.display().to_string());
    line.to = Some(to.display().to_string());
    match result {
        Ok(()) => append(truth, &line),
        Err(err) => {
            line.error = Some(err.to_string());
            append(truth, &line)?;
            Err(format!("rename {from_rel} -> {to_rel}: {err}"))
        }
    }
}

fn http_upload(step: &Step, depth: u32, ppid: Option<u32>, truth: &Path) -> Result<(), String> {
    let url = step
        .url
        .clone()
        .ok_or_else(|| "http_upload requires `url`".to_string())?;
    let bytes = step.bytes.unwrap_or(0);
    let outcome = http_step::upload(&url, bytes);
    let mut line = base("http_upload", depth, ppid, outcome.ok);
    line.url = Some(url);
    line.app_bytes = Some(if outcome.ok { outcome.app_bytes } else { bytes });
    line.bytes = Some(if outcome.ok { outcome.app_bytes } else { bytes });
    line.error = outcome.error;
    // Connection refused is expected until P0-SIM-03's server is up.
    append(truth, &line)
}

fn http_download(step: &Step, depth: u32, ppid: Option<u32>, truth: &Path) -> Result<(), String> {
    let url = step
        .url
        .clone()
        .ok_or_else(|| "http_download requires `url`".to_string())?;
    let outcome = http_step::download(&url);
    let mut line = base("http_download", depth, ppid, outcome.ok);
    line.url = Some(url);
    line.app_bytes = Some(outcome.app_bytes);
    line.bytes = Some(outcome.app_bytes);
    line.error = outcome.error;
    append(truth, &line)
}

fn dns_lookup(step: &Step, depth: u32, ppid: Option<u32>, truth: &Path) -> Result<(), String> {
    let name = step
        .name
        .clone()
        .ok_or_else(|| "dns_lookup requires `name`".to_string())?;
    let query = if name.contains(':') {
        name.clone()
    } else {
        format!("{name}:0")
    };
    let looked = query.to_socket_addrs().map(|iter| iter.count());
    let mut line = base("dns_lookup", depth, ppid, looked.is_ok());
    line.name = Some(name);
    match looked {
        Ok(n) => {
            line.extra
                .insert("answers".to_string(), serde_json::json!(n));
            append(truth, &line)
        }
        Err(err) => {
            // NXDOMAIN for the documented bait name is still a completed lookup.
            line.ok = false;
            line.error = Some(err.to_string());
            append(truth, &line)
        }
    }
}

fn sleep_step(step: &Step, depth: u32, ppid: Option<u32>, truth: &Path) -> Result<(), String> {
    let ms = step.ms.unwrap_or(0);
    thread::sleep(Duration::from_millis(ms));
    let mut line = base("sleep", depth, ppid, true);
    line.extra.insert("ms".to_string(), serde_json::json!(ms));
    append(truth, &line)
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
