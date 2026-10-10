//! What the collectors are doing right now, for `GET /api/v1/doctor` and the
//! Settings page.
//!
//! The foreground loop ([`crate::runtime`]) owns the samplers. After it starts
//! them and after every sample tick it writes a [`CollectorRuntime`] onto
//! [`crate::api::ApiState`]. The doctor answer reads that, not the config:
//! the config's `[collectors.linux]` table holds switches for collectors this
//! build does not attach (`tls_uprobe`, `ipc_payload_peek`), and Settings used
//! to print it as 「linux 未启用」 while process sampling was running.

use serde_json::{json, Value};

/// Runtime state of the collectors, as last reported by the foreground loop.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CollectorRuntime {
    /// False until the foreground loop has reported once (also in unit tests
    /// that build an [`crate::api::ApiState`] without a loop): state unknown.
    pub reported: bool,
    /// The daemon-wide sample (`daemon-sample` session) is sampling.
    pub daemon_sample: bool,
    /// Roots watched for API-started sessions (`crate::watch`).
    pub watched_roots: usize,
    /// Wall time of the last successful sample, Unix nanoseconds.
    pub last_sample_ns: Option<i64>,
}

impl CollectorRuntime {
    /// Whether the poll collector is sampling anything.
    #[must_use]
    pub fn poll_running(&self) -> bool {
        self.daemon_sample || self.watched_roots > 0
    }
}

/// Kernel-level collector this platform would use; not attached in this build.
fn kernel_collector() -> Option<&'static str> {
    if cfg!(target_os = "linux") {
        Some("ebpf")
    } else if cfg!(windows) {
        Some("etw")
    } else if cfg!(target_os = "macos") {
        Some("eslogger")
    } else {
        None
    }
}

/// `collectors` for the doctor answer. `poll_capabilities` is the same list
/// the session answers carry, so the new-session page and the overview agree.
#[must_use]
pub fn doctor_collectors(runtime: &CollectorRuntime, poll_capabilities: &Value) -> Value {
    let status = if !runtime.reported {
        "unknown"
    } else if runtime.poll_running() {
        "running"
    } else {
        "stopped"
    };
    let mut list = vec![json!({
        "name": "poll",
        "status": status,
        "running": if runtime.reported { json!(runtime.poll_running()) } else { Value::Null },
        "daemon_sample": runtime.daemon_sample,
        "watched_roots": runtime.watched_roots,
        "last_sample_ns": runtime.last_sample_ns,
        "capabilities": poll_capabilities,
    })];
    if let Some(name) = kernel_collector() {
        list.push(json!({
            "name": name,
            "status": "not_built",
            "running": false,
            "capabilities": [],
        }));
    }
    Value::Array(list)
}

/// Doctor `capabilities`: the poll list with `available` spelled out.
#[must_use]
pub fn doctor_capabilities(poll_capabilities: &Value) -> Value {
    let list = poll_capabilities
        .as_array()
        .map(|caps| {
            caps.iter()
                .map(|cap| {
                    let mut cap = cap.clone();
                    let available = cap["evidence"].as_str().is_some_and(|e| e != "NA");
                    cap["available"] = json!(available);
                    cap
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Value::Array(list)
}

#[cfg(test)]
mod tests {
    use super::{doctor_capabilities, doctor_collectors, CollectorRuntime};
    use serde_json::json;

    /// UI re-review #144 new-3: Settings said 「linux 未启用」 while process
    /// sampling ran. The answer must follow the loop's runtime state.
    #[test]
    fn poll_status_follows_the_runtime_state() {
        let caps = json!([{ "kind": "proc", "evidence": "S" }]);
        let unknown = doctor_collectors(&CollectorRuntime::default(), &caps);
        assert_eq!(unknown[0]["name"], "poll");
        assert_eq!(unknown[0]["status"], "unknown");
        assert!(unknown[0]["running"].is_null());

        let running = CollectorRuntime {
            reported: true,
            daemon_sample: true,
            watched_roots: 0,
            last_sample_ns: Some(5),
        };
        let list = doctor_collectors(&running, &caps);
        assert_eq!(list[0]["status"], "running");
        assert_eq!(list[0]["running"], true);
        assert_eq!(list[0]["last_sample_ns"], 5);
        assert_eq!(list[0]["capabilities"], caps);

        let watching = CollectorRuntime {
            reported: true,
            daemon_sample: false,
            watched_roots: 2,
            last_sample_ns: None,
        };
        assert_eq!(doctor_collectors(&watching, &caps)[0]["status"], "running");

        let stopped = CollectorRuntime {
            reported: true,
            ..CollectorRuntime::default()
        };
        assert_eq!(doctor_collectors(&stopped, &caps)[0]["status"], "stopped");
        // A kernel collector is never reported as running in this build.
        for entry in list.as_array().into_iter().flatten().skip(1) {
            assert_eq!(entry["status"], "not_built");
        }
    }

    #[test]
    fn capabilities_spell_out_availability() {
        let caps = json!([
            { "kind": "proc", "evidence": "S" },
            { "kind": "file", "evidence": "NA", "na_reason": "collector_unavailable" }
        ]);
        let out = doctor_capabilities(&caps);
        assert_eq!(out[0]["available"], true);
        assert_eq!(out[1]["available"], false);
        assert_eq!(out[1]["na_reason"], "collector_unavailable");
    }
}
