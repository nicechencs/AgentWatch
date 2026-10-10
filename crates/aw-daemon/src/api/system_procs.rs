//! `GET /api/v1/processes`: the live host process table for the attach picker
//! and `aw ps`.
//!
//! Rows come from [`aw_collector_poll::host_process_table`] (the same `sysinfo`
//! source as the poll collector), so every row is evidence S. The table is
//! read when the request arrives; nothing is cached or stored.
//!
//! Who sees what:
//! - An administrator (root / Administrators) sees every process.
//! - Everyone else sees only processes whose owner id equals their own peer
//!   id (uid or SID). A process whose owner could not be read is not shown to
//!   them: it may belong to someone else.
//!
//! Argv is redacted with the built-in rules before it leaves the daemon, and
//! only for rows the caller may see. The working directory is not read.
//!
//! When the platform has no process table, the answer is `available: false`
//! with a reason. That is "not collected", never an empty table.

use std::collections::{HashMap, HashSet};

use serde_json::{json, Value};

use aw_agent_adapters::{identify, ProcInfo};
use aw_collector_poll::HostProcess;

use super::auth::Caller;
use super::routes::ApiResponse;

/// Reads the host table. Tests swap in a fixed table.
pub(crate) type TableReader = fn() -> Option<Vec<HostProcess>>;

/// Production reader.
pub(crate) fn live_table() -> Option<Vec<HostProcess>> {
    aw_collector_poll::host_process_table()
}

/// Query parameters this route reads.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct ProcQuery {
    agents_only: bool,
    /// Lower-cased substring of the name, or a pid.
    needle: Option<String>,
}

fn parse_query(raw: &str) -> ProcQuery {
    let mut out = ProcQuery::default();
    for pair in raw.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let value = decode(value);
        match key {
            "agents_only" => out.agents_only = matches!(value.as_str(), "1" | "true" | ""),
            "q" => {
                let trimmed = value.trim().to_lowercase();
                out.needle = (!trimmed.is_empty()).then_some(trimmed);
            }
            _ => {}
        }
    }
    out
}

/// Minimal `application/x-www-form-urlencoded` decode. Invalid escapes stay literal.
fn decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).ok();
                match hex.and_then(|hex| u8::from_str_radix(hex, 16).ok()) {
                    Some(byte) => {
                        out.push(byte);
                        index += 3;
                    }
                    None => {
                        out.push(b'%');
                        index += 1;
                    }
                }
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Handle `GET /api/v1/processes`.
pub(crate) fn system_processes(read: TableReader, caller: &Caller, raw_query: &str) -> ApiResponse {
    let query = parse_query(raw_query);
    let scope = if caller.admin { "all" } else { "own" };
    let Some(table) = read() else {
        return ApiResponse::json(
            200,
            &json!({
                "available": false,
                // A code the UI words in the user's language; English only in `detail`.
                "reason": "no_process_table",
                "detail": "this platform has no process table for the daemon to read (not collected)",
                "scope": scope,
                "roots": [],
                "processes": [],
            }),
        );
    };
    let rows = build_rows(table, caller, &query);
    let roots = tree(&rows);
    ApiResponse::json(
        200,
        &json!({
            "available": true,
            "reason": Value::Null,
            "scope": scope,
            "source": "poll",
            "evidence": "S",
            "count": rows.len(),
            "roots": roots,
            "processes": rows.iter().map(Row::flat_json).collect::<Vec<_>>(),
        }),
    )
}

/// One visible row, already redacted.
struct Row {
    pid: u32,
    ppid: Option<u32>,
    name: String,
    exe: Option<String>,
    argv: Option<Vec<String>>,
    user_id: Option<String>,
    agent: Option<String>,
}

impl Row {
    fn flat_json(&self) -> Value {
        json!({
            "pid": self.pid,
            "ppid": self.ppid,
            "name": self.name,
            "exe": self.exe,
            "argv": self.argv,
            "user_id": self.user_id,
            "agent": self.agent,
            "evidence": "S",
        })
    }
}

fn base_name(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

fn build_rows(table: Vec<HostProcess>, caller: &Caller, query: &ProcQuery) -> Vec<Row> {
    // Parents of visible rows are looked up for agent matching (`parent_exe`)
    // only; a parent the caller may not see is not returned.
    let by_pid: HashMap<u32, (String, Vec<String>)> = table
        .iter()
        .map(|proc| {
            (
                proc.row.pid,
                (
                    display_name(proc),
                    proc.row.argv.clone().unwrap_or_default(),
                ),
            )
        })
        .collect();
    let redactor = aw_pipeline::Redactor::new(&aw_pipeline::config::RedactionConfig::default());
    let mut rows: Vec<Row> = table
        .into_iter()
        .filter(|proc| caller.admin || proc.row.user_id.as_deref() == Some(caller.user_id.as_str()))
        .map(|proc| {
            let name = display_name(&proc);
            let info = ProcInfo {
                pid: proc.row.pid,
                exe_name: name.clone(),
                argv: proc.row.argv.clone().unwrap_or_default(),
                env_keys: Vec::new(),
            };
            let parent: Vec<ProcInfo> = proc
                .row
                .ppid
                .and_then(|ppid| by_pid.get(&ppid).map(|entry| (ppid, entry)))
                .map(|(ppid, (pname, pargv))| ProcInfo {
                    pid: ppid,
                    exe_name: pname.clone(),
                    argv: pargv.clone(),
                    env_keys: Vec::new(),
                })
                .into_iter()
                .collect();
            let agent = identify(&info, &parent).map(|hit| hit.profile_id);
            Row {
                pid: proc.row.pid,
                ppid: proc.row.ppid,
                name,
                exe: proc.row.exe,
                argv: proc.row.argv.map(|argv| redactor.redact_args(&argv)),
                user_id: proc.row.user_id,
                agent,
            }
        })
        .filter(|row| !query.agents_only || row.agent.is_some())
        .filter(|row| match &query.needle {
            None => true,
            Some(needle) => {
                row.name.to_lowercase().contains(needle.as_str())
                    || row.pid.to_string() == *needle
                    || row
                        .agent
                        .as_deref()
                        .is_some_and(|agent| agent.contains(needle.as_str()))
            }
        })
        .collect();
    rows.sort_by_key(|row| row.pid);
    rows
}

/// Name for display: the OS name, else the executable's base name, else argv[0].
fn display_name(proc: &HostProcess) -> String {
    if let Some(name) = &proc.name {
        return name.clone();
    }
    if let Some(exe) = &proc.row.exe {
        return base_name(exe).to_owned();
    }
    proc.row
        .argv
        .as_ref()
        .and_then(|argv| argv.first())
        .map_or_else(
            || format!("pid {}", proc.row.pid),
            |arg0| base_name(arg0).to_owned(),
        )
}

/// Nest rows under their parent when the parent is also visible; otherwise a
/// row is a root. A cycle cannot hang this: each pid is placed once.
fn tree(rows: &[Row]) -> Vec<Value> {
    let pids: HashSet<u32> = rows.iter().map(|row| row.pid).collect();
    let mut children: HashMap<u32, Vec<usize>> = HashMap::new();
    let mut roots: Vec<usize> = Vec::new();
    for (index, row) in rows.iter().enumerate() {
        match row.ppid {
            Some(ppid) if ppid != row.pid && pids.contains(&ppid) => {
                children.entry(ppid).or_default().push(index);
            }
            _ => roots.push(index),
        }
    }
    let mut placed: HashSet<u32> = HashSet::new();
    let mut out: Vec<Value> = roots
        .iter()
        .map(|&index| node(rows, index, &children, &mut placed))
        .collect();
    // Rows only reachable through a parent cycle become roots.
    for (index, row) in rows.iter().enumerate() {
        if !placed.contains(&row.pid) {
            out.push(node(rows, index, &children, &mut placed));
        }
    }
    out
}

fn node(
    rows: &[Row],
    index: usize,
    children: &HashMap<u32, Vec<usize>>,
    placed: &mut HashSet<u32>,
) -> Value {
    let row = &rows[index];
    placed.insert(row.pid);
    let kids: Vec<Value> = children
        .get(&row.pid)
        .map(|list| {
            list.iter()
                .filter(|&&child| !placed.contains(&rows[child].pid))
                .copied()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
        .into_iter()
        .map(|child| node(rows, child, children, placed))
        .collect();
    let mut value = row.flat_json();
    if let Some(map) = value.as_object_mut() {
        map.insert("children".to_owned(), Value::Array(kids));
    }
    value
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{decode, live_table, system_processes, HostProcess};
    use crate::api::auth::Caller;
    use aw_collector_poll::{ProcessRow, ProcessStartTime};
    use serde_json::Value;

    fn body(reply: &super::ApiResponse) -> Value {
        serde_json::from_slice(&reply.body).expect("json body")
    }

    fn pids(doc: &Value) -> Vec<u64> {
        doc["processes"]
            .as_array()
            .expect("processes")
            .iter()
            .filter_map(|row| row["pid"].as_u64())
            .collect()
    }

    /// Owner id the host table reports for this test process.
    fn my_user_id() -> String {
        let me = std::process::id();
        live_table()
            .expect("table")
            .into_iter()
            .find(|proc| proc.row.pid == me)
            .and_then(|proc| proc.row.user_id)
            .expect("own row has a user id")
    }

    /// Spawn this test binary on the ignored sleeper so a real child is alive.
    fn spawn_sleeper() -> std::process::Child {
        let exe = std::env::current_exe().expect("current_exe");
        std::process::Command::new(exe)
            .args([
                "--exact",
                "api::system_procs::tests::sleeper",
                "--ignored",
                "--test-threads=1",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn the sleeper")
    }

    fn wait_for(caller: &Caller, pid: u32) -> Value {
        let mut last = Value::Null;
        for _ in 0..40 {
            last = body(&system_processes(live_table, caller, ""));
            if pids(&last).contains(&u64::from(pid)) {
                return last;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        last
    }

    /// Real-window bug: the picker showed 「没有记录」 while a process ran.
    /// A non-admin caller must see a live child they own, as a child of this
    /// process in the tree; another account must not see it.
    #[test]
    fn live_child_is_listed_for_its_owner_only() {
        let mut child = spawn_sleeper();
        let pid = child.id();
        let owner = Caller {
            user_id: my_user_id(),
            admin: false,
        };
        let doc = wait_for(&owner, pid);
        let stranger = body(&system_processes(
            live_table,
            &Caller {
                user_id: "no-such-account".to_owned(),
                admin: false,
            },
            "",
        ));
        let admin = wait_for(
            &Caller {
                user_id: "0".to_owned(),
                admin: true,
            },
            pid,
        );
        let _ = child.kill();
        let _ = child.wait();

        assert_eq!(doc["available"], true);
        assert_eq!(doc["scope"], "own");
        assert_eq!(doc["evidence"], "S");
        assert!(
            pids(&doc).contains(&u64::from(pid)),
            "owner sees the child: {doc}"
        );
        let row = doc["processes"]
            .as_array()
            .expect("rows")
            .iter()
            .find(|row| row["pid"] == pid)
            .expect("row");
        assert_eq!(row["ppid"], std::process::id());
        assert_eq!(row["user_id"], owner.user_id.as_str());
        assert!(row["name"].as_str().is_some_and(|name| !name.is_empty()));
        // Nested under this process in the tree.
        let me = std::process::id();
        let nested = doc["roots"].as_array().expect("roots").iter().any(|root| {
            fn has(node: &Value, parent: u32, pid: u32) -> bool {
                if node["pid"] == parent {
                    return node["children"]
                        .as_array()
                        .is_some_and(|kids| kids.iter().any(|kid| kid["pid"] == pid));
                }
                node["children"]
                    .as_array()
                    .is_some_and(|kids| kids.iter().any(|kid| has(kid, parent, pid)))
            }
            has(root, me, pid)
        });
        assert!(nested, "child nests under its parent");

        assert_eq!(stranger["available"], true);
        assert!(stranger["processes"].as_array().expect("rows").is_empty());
        assert_eq!(admin["scope"], "all");
        assert!(pids(&admin).contains(&u64::from(pid)));
    }

    #[test]
    fn missing_table_is_not_collected_not_empty() {
        let doc = body(&system_processes(
            || None,
            &Caller {
                user_id: "1000".to_owned(),
                admin: false,
            },
            "q=sleep",
        ));
        assert_eq!(doc["available"], false);
        assert_eq!(doc["reason"], "no_process_table");
        assert!(doc["detail"]
            .as_str()
            .is_some_and(|d| d.contains("not collected")));
        assert!(doc["roots"].as_array().is_some_and(Vec::is_empty));
    }

    fn fixed() -> Option<Vec<HostProcess>> {
        let row = |pid: u32, ppid: Option<u32>, user: &str, argv: &[&str]| HostProcess {
            row: ProcessRow {
                pid,
                ppid,
                start: ProcessStartTime::Unavailable,
                exe: Some(format!("/usr/bin/{}", argv[0])),
                argv: Some(argv.iter().map(|a| (*a).to_owned()).collect()),
                cwd: None,
                user_id: Some(user.to_owned()),
            },
            name: Some(argv[0].to_owned()),
        };
        Some(vec![
            row(10, Some(1), "1000", &["bash"]),
            row(11, Some(10), "1000", &["sleep", "300", "--token=hunter2"]),
            row(12, Some(10), "1000", &["claude"]),
            row(20, Some(1), "1001", &["sleep", "900"]),
        ])
    }

    #[test]
    fn filters_redaction_and_agents_only() {
        let caller = Caller {
            user_id: "1000".to_owned(),
            admin: false,
        };
        let doc = body(&system_processes(fixed, &caller, "q=SLEEP"));
        assert_eq!(pids(&doc), vec![11], "own sleep only: {doc}");
        let text = doc.to_string();
        assert!(!text.contains("hunter2"), "argv is redacted: {text}");
        // The filtered child has no visible parent, so it is a root.
        assert_eq!(doc["roots"][0]["pid"], 11);

        let agents = body(&system_processes(fixed, &caller, "agents_only=1"));
        assert_eq!(pids(&agents), vec![12], "{agents}");
        assert_eq!(agents["processes"][0]["agent"], "claude-code");

        let all = body(&system_processes(fixed, &caller, ""));
        assert_eq!(pids(&all), vec![10, 11, 12]);
        assert_eq!(all["roots"].as_array().map(Vec::len), Some(1));
        assert_eq!(decode("a%20b+c%zz"), "a b c%zz");
    }

    #[test]
    #[ignore = "helper process for live_child_is_listed_for_its_owner_only"]
    fn sleeper() {
        std::thread::sleep(std::time::Duration::from_secs(10));
    }
}
