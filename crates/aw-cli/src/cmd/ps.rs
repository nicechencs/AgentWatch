//! `aw ps` (P1-CLI-02).
//!
//! Lists processes the caller could attach to, as a tree. Rows come from a
//! [`ProcessTable`]. The production table is [`DaemonTable`]: it asks the
//! daemon (`GET /api/v1/processes`) over the internal channel, so this CLI
//! does not read the operating system's process list itself. The daemon
//! decides scope: an administrator sees every process, anyone else their own.
//! A daemon that cannot read a table answers `available: false`, which is
//! printed as 「没采」 (not collected), never as an empty list. Tests inject rows.
//!
//! `--agents-only` keeps rows whose executable base name is on
//! [`AGENT_NAMES`]. That list is a name match only. Full agent recognition is
//! P5; a hit here is not evidence that the process is an agent.

use std::io;

use serde_json::{json, Value};

use aw_core::Evidence;

use crate::client::{ApiRequest, Client, ClientError, Transport};
use crate::endpoint::Endpoint;
use crate::exit;
use crate::output::{evidence_badge, evidence_code, OutputMode, Row, Table};

use super::render;
use super::Outcome;

/// Name stems treated as agents for `--agents-only`.
///
/// Comparison is on the executable base name, without a directory and without
/// `.exe`, case-insensitive. This is not agent detection: P5 owns that.
pub(crate) const AGENT_NAMES: [&str; 8] = [
    "claude", "codex", "cursor", "aider", "continue", "windsurf", "gemini", "copilot",
];

/// One process the table is willing to show. No command line: argv is not a
/// field here, so it cannot be printed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcessRow {
    /// Process id.
    pub pid: u32,
    /// Parent process id. `None` when the table does not know it (not `0`).
    pub parent: Option<u32>,
    /// Executable base name. Not a path.
    pub name: String,
    /// Owner id (uid or SID) as the daemon reported it. `None` when unknown.
    pub user: Option<String>,
    /// How this row was observed.
    pub evidence: Evidence,
}

/// Why the table produced no rows.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum PsError {
    /// The daemon did not answer.
    Unreachable { detail: String },
    /// The channel rejected this caller before a process table was returned.
    Permission { detail: String, code: &'static str },
    /// The daemon answered but has no process table on this platform.
    NotCollected { detail: String },
    /// The exchange or the answer was broken.
    Unavailable { detail: String },
    /// `--filter` was rejected.
    BadFilter { detail: String },
}

impl std::fmt::Display for PsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreachable { detail }
            | Self::Permission { detail, .. }
            | Self::NotCollected { detail }
            | Self::Unavailable { detail }
            | Self::BadFilter { detail } => write!(f, "{detail}"),
        }
    }
}

/// Process list. Production is [`DaemonTable`].
pub(crate) trait ProcessTable {
    /// Processes visible to the caller.
    ///
    /// # Errors
    ///
    /// [`PsError::Unavailable`] when no source is wired, or [`PsError::BadFilter`].
    fn list(&mut self) -> Result<Vec<ProcessRow>, PsError>;
}

/// Production table: the daemon's `GET /api/v1/processes`.
pub(crate) struct DaemonTable {
    endpoint: Endpoint,
    transport: Option<Box<dyn Transport>>,
}

impl DaemonTable {
    /// Bind to `endpoint` over `transport`. Does not connect.
    pub(crate) fn new(endpoint: Endpoint, transport: Box<dyn Transport>) -> Self {
        Self {
            endpoint,
            transport: Some(transport),
        }
    }
}

impl ProcessTable for DaemonTable {
    fn list(&mut self) -> Result<Vec<ProcessRow>, PsError> {
        let Some(transport) = self.transport.take() else {
            return Err(PsError::Unavailable {
                detail: "进程表已读取".to_owned(),
            });
        };
        let mut client = Client::new(self.endpoint.clone(), transport);
        let reply =
            client
                .call(&ApiRequest::get("/api/v1/processes"))
                .map_err(|err| match err {
                    ClientError::Unreachable { .. } => PsError::Unreachable {
                        detail: err.to_string(),
                    },
                    ClientError::Forbidden { .. } => PsError::Permission {
                        detail: err.to_string(),
                        code: "forbidden",
                    },
                    ClientError::UntrustedServer { .. } => PsError::Permission {
                        detail: err.to_string(),
                        code: "daemon_untrusted_server",
                    },
                    ClientError::Status {
                        status: 401 | 403,
                        ref code,
                        ..
                    } => PsError::Permission {
                        detail: err.to_string(),
                        code: if code.as_deref() == Some("unidentified_peer") {
                            "unidentified_peer"
                        } else {
                            "forbidden"
                        },
                    },
                    other => PsError::Unavailable {
                        detail: format!("请求进程表失败：{other}"),
                    },
                })?;
        let body = reply.json().ok_or_else(|| PsError::Unavailable {
            detail: "后台返回的进程表不是 JSON".to_owned(),
        })?;
        rows_from_json(&body)
    }
}

/// Parse a `GET /processes` answer. `available: false` (or a missing flag) is
/// [`PsError::NotCollected`]; a row without a pid or name is rejected rather
/// than shown with a guessed value.
fn rows_from_json(body: &Value) -> Result<Vec<ProcessRow>, PsError> {
    if body.get("available").and_then(Value::as_bool) != Some(true) {
        return Err(PsError::NotCollected {
            detail: not_collected_detail(body.get("reason").and_then(Value::as_str)),
        });
    }
    let Some(list) = body.get("processes").and_then(Value::as_array) else {
        return Err(PsError::Unavailable {
            detail: "后台进程表没有 `processes` 列表".to_owned(),
        });
    };
    list.iter()
        .map(|row| {
            let pid = row
                .get("pid")
                .and_then(Value::as_u64)
                .and_then(|pid| u32::try_from(pid).ok());
            let name = row.get("name").and_then(Value::as_str);
            match (pid, name) {
                (Some(pid), Some(name)) => Ok(ProcessRow {
                    pid,
                    parent: row
                        .get("ppid")
                        .and_then(Value::as_u64)
                        .and_then(|ppid| u32::try_from(ppid).ok()),
                    name: name.to_owned(),
                    user: row
                        .get("user_id")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    evidence: Evidence::S,
                }),
                _ => Err(PsError::Unavailable {
                    detail: "后台进程行没有 pid 或 name".to_owned(),
                }),
            }
        })
        .collect()
}

/// 「没采」 line for a table the daemon could not read.
///
/// The JSON error code stays `not_collected`. `reason` is a machine code; the
/// sentence is the same wording the UI shows (`new.procReason.*`).
fn not_collected_detail(reason: Option<&str>) -> String {
    let sentence = match reason.map(str::trim).filter(|text| !text.is_empty()) {
        Some("no_process_table") => "这个平台上后台没有可读的进程表".to_owned(),
        Some(code) => format!("原因码 {code}，这个版本还不认识"),
        None => "后台没说原因".to_owned(),
    };
    format!("没采：进程表（{sentence}）")
}

/// Run `aw ps`.
pub(crate) fn run(
    agents_only: bool,
    filter: Option<&str>,
    json: bool,
    table: &mut dyn ProcessTable,
) -> Outcome {
    if let Some(text) = filter {
        if text.trim().is_empty() {
            return super::error_outcome(exit::USAGE, "usage", "--filter 为空", json);
        }
    }
    let rows = match table.list() {
        Ok(rows) => rows,
        Err(PsError::Unreachable { detail }) => {
            return super::error_outcome(exit::UNREACHABLE, "unreachable", &detail, json);
        }
        Err(PsError::Permission { detail, code }) => {
            return super::error_outcome(exit::PERMISSION, code, &detail, json);
        }
        Err(PsError::NotCollected { detail }) => {
            return super::error_outcome(exit::GENERAL, "not_collected", &detail, json);
        }
        Err(PsError::Unavailable { detail }) => {
            return super::error_outcome(exit::GENERAL, "unavailable", &detail, json);
        }
        Err(PsError::BadFilter { detail }) => {
            return super::error_outcome(exit::USAGE, "usage", &detail, json);
        }
    };
    let filtered = select(&rows, agents_only, filter);
    let mode = OutputMode::from_json_flag(json);
    match write_ps(mode, &filtered, agents_only) {
        Ok(stdout) => Outcome {
            code: exit::OK,
            stdout,
            stderr: Vec::new(),
        },
        Err(err) => super::error_outcome(exit::GENERAL, "ps", &err.to_string(), json),
    }
}

/// Keep rows the flags ask for.
///
/// `--agents-only` matches [`AGENT_NAMES`] against the base name. `--filter` is
/// a case-insensitive substring of that same base name. Neither inspects argv.
fn select(rows: &[ProcessRow], agents_only: bool, filter: Option<&str>) -> Vec<ProcessRow> {
    let needle = filter.map(str::to_ascii_lowercase);
    rows.iter()
        .filter(|row| {
            if agents_only && !is_agent_name(&row.name) {
                return false;
            }
            if let Some(needle) = &needle {
                if !row.name.to_ascii_lowercase().contains(needle) {
                    return false;
                }
            }
            true
        })
        .cloned()
        .collect()
}

/// `true` when `name` is on [`AGENT_NAMES`].
///
/// Strips one trailing `.exe` and ignores ASCII case. A path is reduced to its
/// last segment so a caller that passed a full path still matches the base
/// name. The match is the whole base name, not a substring, so `claude-helper`
/// is not `claude`.
pub(crate) fn is_agent_name(name: &str) -> bool {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let base = base
        .strip_suffix(".exe")
        .or_else(|| base.strip_suffix(".EXE"))
        .unwrap_or(base);
    let folded = base.to_ascii_lowercase();
    AGENT_NAMES.iter().any(|agent| folded == *agent)
}

fn write_ps(mode: OutputMode, rows: &[ProcessRow], agents_only: bool) -> io::Result<Vec<u8>> {
    let ordered = tree_order(rows);
    let rendered = Table {
        headers: vec![
            "tree".to_owned(),
            "pid".to_owned(),
            "name".to_owned(),
            "user".to_owned(),
        ],
        rows: ordered
            .iter()
            .map(|(depth, row)| Row {
                cells: vec![
                    tree_cell(*depth, &row.name),
                    row.pid.to_string(),
                    row.name.clone(),
                    row.user.clone().unwrap_or_else(|| "—".to_owned()),
                ],
                evidence: row.evidence.clone(),
            })
            .collect(),
    };
    let doc = ps_json(&ordered, agents_only);
    let mut buf = Vec::new();
    render::write_out(&mut buf, mode, &rendered, &doc)?;
    Ok(buf)
}

fn tree_cell(depth: usize, name: &str) -> String {
    let mut cell = String::new();
    for _ in 0..depth {
        cell.push_str("  ");
    }
    if depth > 0 {
        cell.push_str("└ ");
    }
    cell.push_str(name);
    cell
}

/// Parents before children. A row whose parent is not in `rows` is a root.
/// Depth is the number of selected ancestors, so a filtered list does not
/// pretend a missing parent is pid 0.
fn tree_order(rows: &[ProcessRow]) -> Vec<(usize, ProcessRow)> {
    let mut remaining: Vec<ProcessRow> = rows.to_vec();
    let mut ordered: Vec<(usize, ProcessRow)> = Vec::with_capacity(rows.len());
    let mut guard = rows.len().saturating_add(1);
    while !remaining.is_empty() && guard > 0 {
        guard -= 1;
        let before = remaining.len();
        let mut index = 0;
        while index < remaining.len() {
            let parent = remaining[index].parent;
            let depth = match parent {
                Some(pid) => ordered
                    .iter()
                    .find(|(_, row)| row.pid == pid)
                    .map(|(depth, _)| depth + 1),
                None => Some(0),
            };
            let ready = depth.is_some() || !remaining.iter().any(|row| Some(row.pid) == parent);
            if ready {
                let row = remaining.remove(index);
                let depth = depth.unwrap_or(0);
                ordered.push((depth, row));
            } else {
                index += 1;
            }
        }
        if remaining.len() == before {
            // A cycle, or parents that only point at each other. Emit the rest
            // as roots rather than dropping them.
            for row in remaining.drain(..) {
                ordered.push((0, row));
            }
        }
    }
    ordered
}

fn ps_json(rows: &[(usize, ProcessRow)], agents_only: bool) -> Value {
    json!({
        "agents_only": agents_only,
        "agent_match": "name list; full recognition is P5",
        "rows": rows.iter().map(|(depth, row)| json!({
            "depth": depth,
            "pid": row.pid,
            "parent": row.parent,
            "name": row.name,
            "user_id": row.user,
            "evidence": evidence_code(&row.evidence),
            "badge": evidence_badge(&row.evidence),
        })).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{is_agent_name, run, DaemonTable, ProcessRow, ProcessTable, PsError, AGENT_NAMES};
    use crate::client::MemoryTransport;
    use crate::endpoint::Endpoint;
    use crate::exit;
    use aw_core::Evidence;

    struct Fixed(Vec<ProcessRow>);

    impl ProcessTable for Fixed {
        fn list(&mut self) -> Result<Vec<ProcessRow>, PsError> {
            Ok(self.0.clone())
        }
    }

    fn row(pid: u32, parent: Option<u32>, name: &str) -> ProcessRow {
        ProcessRow {
            pid,
            parent,
            name: name.to_owned(),
            user: None,
            evidence: Evidence::S,
        }
    }

    #[test]
    fn agents_only_keeps_name_matches() {
        let mut table = Fixed(vec![
            row(1, None, "claude"),
            row(2, Some(1), "node"),
            row(3, None, "codex.exe"),
            row(4, None, "Cursor"),
            row(5, None, "claude-helper"),
        ]);
        let outcome = run(true, None, false, &mut table);
        assert_eq!(outcome.code, exit::OK);
        let text = String::from_utf8(outcome.stdout).expect("utf8");
        assert!(text.contains("claude"), "{text}");
        assert!(text.contains("codex.exe"), "{text}");
        assert!(text.contains("Cursor"), "{text}");
        assert!(!text.contains("node"), "{text}");
        assert!(!text.contains("claude-helper"), "{text}");
        assert!(text.contains("S 采样"), "{text}");
        for name in AGENT_NAMES {
            assert!(is_agent_name(name));
        }
    }

    fn socket() -> Endpoint {
        Endpoint::Unix {
            path: std::path::PathBuf::from("/nonexistent/aw-test.sock"),
        }
    }

    fn daemon(status: u16, body: &str) -> DaemonTable {
        DaemonTable::new(
            socket(),
            Box::new(MemoryTransport::replying(status, body.as_bytes().to_vec())),
        )
    }

    /// Real-window #144 blocker 3: `aw ps` reads the daemon's table and
    /// prints the running `sleep` with its owner.
    #[test]
    fn daemon_rows_are_printed_with_user() {
        let body = r#"{"available":true,"scope":"own","processes":[
            {"pid":10,"ppid":1,"name":"bash","user_id":"1000"},
            {"pid":11,"ppid":10,"name":"sleep","user_id":"1000","argv":["sleep","900"]}
        ]}"#;
        let outcome = run(false, Some("sleep"), false, &mut daemon(200, body));
        assert_eq!(outcome.code, exit::OK);
        let text = String::from_utf8(outcome.stdout).expect("utf8");
        assert!(text.contains("sleep") && text.contains("11"), "{text}");
        assert!(text.contains("1000"), "{text}");
        assert!(!text.contains("bash"), "{text}");
        let json = run(false, None, true, &mut daemon(200, body));
        let doc: serde_json::Value = serde_json::from_slice(&json.stdout).expect("json");
        assert_eq!(doc["rows"][1]["pid"], 11);
        assert_eq!(doc["rows"][1]["depth"], 1);
        assert_eq!(doc["rows"][1]["user_id"], "1000");
    }

    #[test]
    fn not_collected_is_not_an_empty_list() {
        let body = r#"{"available":false,"reason":"no_process_table","detail":"this platform has no process table for the daemon to read (not collected)","scope":"own","roots":[],"processes":[]}"#;
        let outcome = run(false, None, false, &mut daemon(200, body));
        assert_eq!(outcome.code, exit::GENERAL);
        let text = String::from_utf8(outcome.stderr).expect("utf8");
        assert!(
            text.contains("没采：进程表（这个平台上后台没有可读的进程表）"),
            "{text}"
        );
        assert!(!text.contains("no_process_table"), "{text}");
        assert!(outcome.stdout.is_empty());
        let json = run(false, None, true, &mut daemon(200, body));
        let doc: serde_json::Value = serde_json::from_slice(&json.stderr).expect("json");
        assert_eq!(doc["error"]["code"], "not_collected");
    }

    #[test]
    fn not_collected_reason_unknown_keeps_the_code() {
        let body = r#"{"available":false,"reason":"disk_asleep","roots":[],"processes":[]}"#;
        let outcome = run(false, None, false, &mut daemon(200, body));
        let text = String::from_utf8(outcome.stderr).expect("utf8");
        assert!(
            text.contains("没采：进程表（原因码 disk_asleep，这个版本还不认识）"),
            "{text}"
        );
    }

    #[test]
    fn not_collected_without_a_reason_says_so() {
        let body = r#"{"available":false,"roots":[],"processes":[]}"#;
        let outcome = run(false, None, false, &mut daemon(200, body));
        let text = String::from_utf8(outcome.stderr).expect("utf8");
        assert!(text.contains("没采：进程表（后台没说原因）"), "{text}");
        assert!(!text.contains("（后台没说原因（"), "{text}");
    }

    #[test]
    fn unreachable_daemon_is_exit_3() {
        let mut table = DaemonTable::new(socket(), Box::new(MemoryTransport::failing("refused")));
        let outcome = run(false, None, false, &mut table);
        assert_eq!(outcome.code, exit::UNREACHABLE);
        assert!(matches!(
            DaemonTable::new(socket(), Box::new(MemoryTransport::failing("x"))).list(),
            Err(PsError::Unreachable { .. })
        ));
    }

    #[test]
    fn tree_indents_a_child() {
        let mut table = Fixed(vec![row(2, Some(1), "aider"), row(1, None, "claude")]);
        let outcome = run(false, None, false, &mut table);
        let text = String::from_utf8(outcome.stdout).expect("utf8");
        let claude = text
            .lines()
            .find(|line| line.contains("claude"))
            .expect("root");
        let aider = text
            .lines()
            .find(|line| line.contains("aider"))
            .expect("child");
        assert!(
            aider.find('a') > claude.find('c'),
            "child should be indented:\n{text}"
        );
    }
}
