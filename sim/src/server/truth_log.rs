//! Server truth log: one JSON object per exchange, byte counts only.
//!
//! `tls_bytes` is omitted from the Rust value when it was not measured and
//! serializes as JSON `null`. Callers must not pass `Some(0)` to mean unknown.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

use serde::Serialize;

#[derive(Clone, Copy)]
pub enum Direction {
    Upload,
    Download,
    Udp,
    Dns,
}

impl Direction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Upload => "upload",
            Self::Download => "download",
            Self::Udp => "udp",
            Self::Dns => "dns",
        }
    }
}

impl Serialize for Direction {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

pub struct TruthRecord {
    pub connection_id: u64,
    pub direction: Direction,
    pub app_bytes: u64,
    /// `None` becomes JSON `null`. Never use `Some(0)` for "not measured".
    pub tls_bytes: Option<u64>,
    pub ok: bool,
    pub error: Option<String>,
}

#[derive(Serialize)]
struct TruthLine<'a> {
    connection_id: u64,
    direction: Direction,
    app_bytes: u64,
    tls_bytes: Option<u64>,
    ok: bool,
    error: Option<&'a str>,
}

pub struct TruthLog {
    file: Mutex<File>,
}

impl TruthLog {
    pub fn create(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|err| format!("{}: {err}", parent.display()))?;
            }
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|err| format!("{}: {err}", path.display()))?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }

    /// Flush and sync the line before the caller finishes the HTTP response.
    pub fn append(&self, record: &TruthRecord) -> Result<(), String> {
        let line = TruthLine {
            connection_id: record.connection_id,
            direction: record.direction,
            app_bytes: record.app_bytes,
            tls_bytes: record.tls_bytes,
            ok: record.ok,
            error: record.error.as_deref(),
        };
        let mut encoded =
            serde_json::to_vec(&line).map_err(|err| format!("encode truth: {err}"))?;
        encoded.push(b'\n');
        let mut file = self
            .file
            .lock()
            .map_err(|_| "truth log lock poisoned".to_string())?;
        file.write_all(&encoded)
            .and_then(|_| file.flush())
            .and_then(|_| file.sync_all())
            .map_err(|err| format!("write truth: {err}"))
    }
}
