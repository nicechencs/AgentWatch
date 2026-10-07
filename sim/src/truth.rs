//! Ground-truth JSONL. One line per finished action.
//!
//! Shape follows testing.md §4.3. Extra fields (`id`, `ppid` on every line,
//! `spawned_pid`, `ok`, `error`) are additive so a 3-level tree is visible
//! without a second file.

use std::fs::OpenOptions;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Serialize)]
pub struct TruthLine {
    pub t_wall_ns: u128,
    pub pid: u32,
    /// Parent in the sim process tree. Absent on the root process: this crate
    /// does not query the OS parent (that needs unsafe FFI on Windows).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ppid: Option<u32>,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_bytes: Option<u64>,
    /// Child pid created by a `spawn` step, so the parent row names its child.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spawned_pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub depth: Option<u32>,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Present on the root `run` line only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scenario: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sim_root: Option<String>,
    #[serde(flatten)]
    pub extra: std::collections::BTreeMap<String, Value>,
}

impl TruthLine {
    pub fn now(action: impl Into<String>, pid: u32, ppid: Option<u32>, ok: bool) -> Self {
        Self {
            t_wall_ns: wall_ns(),
            pid,
            ppid,
            action: action.into(),
            id: None,
            path: None,
            from: None,
            to: None,
            bytes: None,
            url: None,
            name: None,
            local: None,
            remote: None,
            app_bytes: None,
            spawned_pid: None,
            depth: None,
            ok,
            error: None,
            scenario: None,
            sim_root: None,
            extra: std::collections::BTreeMap::new(),
        }
    }
}

pub struct TruthLog;

impl TruthLog {
    /// Create or truncate the truth file before any child process appends to it.
    pub fn create(path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;
        Ok(())
    }
}

fn wall_ns() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}
