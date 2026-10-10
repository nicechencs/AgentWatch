//! Per-row detail for `GET /sessions/{sid}/timeline` and `/around`.
//!
//! The `timeline` view (storage §3.1) carries only `session_id, ts_ns, cat, id,
//! proc_uid, evidence`. Each page row is looked up in the table its `cat`
//! names and gets three more keys:
//!
//! - `summary`: one line built from that row's stored columns, the same
//!   columns event-schema / storage name. Nothing is inferred; a column that is
//!   NULL is left out of the line, not printed as `0` or a guess.
//! - `fields`: the columns the summary was built from, as stored. Paths, argv
//!   and URLs were redacted at write time and are not re-expanded here.
//! - `proc`: `{pid, exe_name}` of the row's process (api-and-cli §3), or null.
//!
//! A row whose source table or row is missing keeps `summary: ""` and
//! `fields: {}`; the page shows the category and time only.

use rusqlite::{Connection, OptionalExtension};
use serde_json::{json, Map, Value};

/// Nullable text and integer columns.
type Txt = Option<String>;
type Num = Option<i64>;
type FileCols = (Txt, Txt, Txt, Num, Num, Txt);
type NetCols = (Txt, Txt, Txt, Num, Num, Num);
type AgentCols = (String, Txt, Txt, Txt, Txt, Txt);

/// The extra keys for one timeline row.
pub(crate) struct RowDetail {
    pub summary: String,
    pub fields: Map<String, Value>,
    pub proc: Value,
}

impl RowDetail {
    fn empty() -> Self {
        Self {
            summary: String::new(),
            fields: Map::new(),
            proc: Value::Null,
        }
    }
}

/// Detail for one row. Any SQLite error (a table this database does not have
/// yet, for instance) gives an empty detail rather than failing the page.
pub(crate) fn row_detail(
    conn: &Connection,
    session_id: i64,
    cat: &str,
    id: i64,
    proc_uid: Option<i64>,
) -> RowDetail {
    let mut detail = match cat {
        "proc" => proc_row(conn, session_id, id),
        "file" => file_row(conn, id),
        "net" => net_row(conn, id),
        "dns" => dns_row(conn, id),
        "http" => http_row(conn, id),
        "gap" => gap_row(conn, id),
        "finding" => finding_row(conn, id),
        "agent" => agent_row(conn, id),
        _ => None,
    }
    .unwrap_or_else(RowDetail::empty);
    if let Some(uid) = proc_uid {
        detail.proc = proc_summary(conn, session_id, uid).unwrap_or(Value::Null);
    }
    detail
}

/// `exe` is a full path; the summary uses its last segment.
fn exe_name(exe: &str) -> &str {
    exe.rsplit(['/', '\\']).next().unwrap_or(exe)
}

fn latest_image(
    conn: &Connection,
    session_id: i64,
    proc_uid: i64,
) -> Option<(Option<String>, Option<String>)> {
    conn.query_row(
        "SELECT exe, argv FROM process_images WHERE session_id = ?1 AND proc_uid = ?2 \
         ORDER BY ts_ns DESC, id DESC LIMIT 1",
        rusqlite::params![session_id, proc_uid],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .optional()
    .ok()
    .flatten()
}

fn proc_summary(conn: &Connection, session_id: i64, proc_uid: i64) -> Option<Value> {
    let pid: i64 = conn
        .query_row(
            "SELECT pid FROM processes WHERE session_id = ?1 AND proc_uid = ?2",
            rusqlite::params![session_id, proc_uid],
            |row| row.get(0),
        )
        .optional()
        .ok()
        .flatten()?;
    let exe = latest_image(conn, session_id, proc_uid).and_then(|(exe, _)| exe);
    Some(json!({ "pid": pid, "exe_name": exe.as_deref().map(exe_name) }))
}

/// `argv` is stored as a JSON array of strings.
fn argv_line(argv: Option<&str>) -> Option<String> {
    let parsed: Vec<String> = serde_json::from_str(argv?).ok()?;
    if parsed.is_empty() {
        None
    } else {
        Some(parsed.join(" "))
    }
}

fn put(fields: &mut Map<String, Value>, key: &str, value: Value) {
    if !value.is_null() {
        fields.insert(key.to_owned(), value);
    }
}

fn join(parts: &[Option<String>]) -> String {
    parts
        .iter()
        .flatten()
        .filter(|part| !part.is_empty())
        .cloned()
        .collect::<Vec<_>>()
        .join(" ")
}

fn proc_row(conn: &Connection, session_id: i64, proc_uid: i64) -> Option<RowDetail> {
    let (pid, ppid, how, exit_code, exit_signal): (
        i64,
        Option<i64>,
        Option<String>,
        Option<i64>,
        Option<i64>,
    ) = conn
        .query_row(
            "SELECT pid, ppid, how, exit_code, exit_signal FROM processes \
             WHERE session_id = ?1 AND proc_uid = ?2",
            rusqlite::params![session_id, proc_uid],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()
        .ok()
        .flatten()?;
    let (exe, argv) = latest_image(conn, session_id, proc_uid).unwrap_or((None, None));
    let mut fields = Map::new();
    put(&mut fields, "pid", json!(pid));
    put(&mut fields, "ppid", json!(ppid));
    put(&mut fields, "how", json!(how));
    put(&mut fields, "exe", json!(exe));
    put(&mut fields, "exit_code", json!(exit_code));
    put(&mut fields, "exit_signal", json!(exit_signal));
    let name = exe.as_deref().map(exe_name).map(str::to_owned);
    let who = Some(match &name {
        Some(name) => format!("{name}({pid})"),
        None => format!("pid {pid}"),
    });
    let exit = match (exit_code, exit_signal) {
        (Some(code), _) => Some(format!("exit {code}")),
        (None, Some(signal)) => Some(format!("signal {signal}")),
        _ => None,
    };
    let summary = join(&[who, argv_line(argv.as_deref()), exit]);
    Some(RowDetail {
        summary,
        fields,
        proc: Value::Null,
    })
}

fn file_row(conn: &Connection, id: i64) -> Option<RowDetail> {
    let (op, path, path_to, bytes_read, bytes_written, sensitive): FileCols = conn
        .query_row(
            "SELECT op, path, path_to, bytes_read, bytes_written, sensitive_rule \
             FROM file_access WHERE id = ?1",
            [id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()
        .ok()
        .flatten()?;
    let mut fields = Map::new();
    put(&mut fields, "op", json!(op));
    put(&mut fields, "path", json!(path));
    put(&mut fields, "path_to", json!(path_to));
    put(&mut fields, "bytes_read", json!(bytes_read));
    put(&mut fields, "bytes_written", json!(bytes_written));
    put(&mut fields, "sensitive_rule", json!(sensitive));
    let summary = join(&[
        op,
        path,
        path_to.map(|to| format!("→ {to}")),
        sensitive.map(|rule| format!("[{rule}]")),
    ]);
    Some(RowDetail {
        summary,
        fields,
        proc: Value::Null,
    })
}

fn net_row(conn: &Connection, id: i64) -> Option<RowDetail> {
    let (proto, domain, ip, port, up, down): NetCols = conn
        .query_row(
            "SELECT proto, domain, remote_ip, remote_port, bytes_up, bytes_down \
             FROM net_flows WHERE id = ?1",
            [id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()
        .ok()
        .flatten()?;
    let mut fields = Map::new();
    put(&mut fields, "proto", json!(proto));
    put(&mut fields, "domain", json!(domain));
    put(&mut fields, "remote_ip", json!(ip));
    put(&mut fields, "remote_port", json!(port));
    put(&mut fields, "bytes_up", json!(up));
    put(&mut fields, "bytes_down", json!(down));
    let host = domain.or(ip);
    let target = match (host, port) {
        (Some(host), Some(port)) => Some(format!("→ {host}:{port}")),
        (Some(host), None) => Some(format!("→ {host}")),
        _ => None,
    };
    let summary = join(&[
        proto,
        target,
        up.map(|n| format!("↑{n} B")),
        down.map(|n| format!("↓{n} B")),
    ]);
    Some(RowDetail {
        summary,
        fields,
        proc: Value::Null,
    })
}

fn dns_row(conn: &Connection, id: i64) -> Option<RowDetail> {
    let (qname, qtype, rcode, answers): (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    ) = conn
        .query_row(
            "SELECT qname, qtype, CAST(rcode AS TEXT), answers FROM dns WHERE id = ?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .ok()
        .flatten()?;
    let mut fields = Map::new();
    put(&mut fields, "qname", json!(qname));
    put(&mut fields, "qtype", json!(qtype));
    put(&mut fields, "rcode", json!(rcode));
    put(&mut fields, "answers", json!(answers));
    let answer_list: Option<String> = answers
        .as_deref()
        .and_then(|text| serde_json::from_str::<Vec<String>>(text).ok())
        .filter(|list| !list.is_empty())
        .map(|list| format!("→ {}", list.join(", ")));
    let summary = join(&[qname, qtype, answer_list]);
    Some(RowDetail {
        summary,
        fields,
        proc: Value::Null,
    })
}

fn http_row(conn: &Connection, id: i64) -> Option<RowDetail> {
    let (method, url, status): (Option<String>, Option<String>, Option<i64>) = conn
        .query_row(
            "SELECT method, url, status FROM http WHERE id = ?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .ok()
        .flatten()?;
    let mut fields = Map::new();
    put(&mut fields, "method", json!(method));
    put(&mut fields, "url", json!(url));
    put(&mut fields, "status", json!(status));
    let summary = join(&[method, url, status.map(|s| s.to_string())]);
    Some(RowDetail {
        summary,
        fields,
        proc: Value::Null,
    })
}

fn gap_row(conn: &Connection, id: i64) -> Option<RowDetail> {
    let (collector, kind, count, detail): (String, String, Option<i64>, Option<String>) = conn
        .query_row(
            "SELECT collector, kind, count, detail FROM gaps WHERE id = ?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .ok()
        .flatten()?;
    let mut fields = Map::new();
    put(&mut fields, "collector", json!(collector));
    put(&mut fields, "kind", json!(kind));
    put(&mut fields, "count", json!(count));
    put(&mut fields, "detail", json!(detail));
    let summary = join(&[
        Some(collector),
        Some(kind),
        detail,
        count.map(|n| format!("×{n}")),
    ]);
    Some(RowDetail {
        summary,
        fields,
        proc: Value::Null,
    })
}

fn finding_row(conn: &Connection, id: i64) -> Option<RowDetail> {
    let (rule_id, kind, severity): (String, Option<String>, Option<String>) = conn
        .query_row(
            "SELECT rule_id, kind, severity FROM findings WHERE id = ?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .ok()
        .flatten()?;
    let mut fields = Map::new();
    put(&mut fields, "rule_id", json!(rule_id));
    put(&mut fields, "kind", json!(kind));
    put(&mut fields, "severity", json!(severity));
    // The finding's sentence comes from `wording::render` on the findings
    // route; the timeline line names the rule only.
    let summary = join(&[severity, Some(rule_id)]);
    Some(RowDetail {
        summary,
        fields,
        proc: Value::Null,
    })
}

fn agent_row(conn: &Connection, id: i64) -> Option<RowDetail> {
    let (agent, tool, phase, command, path, url): AgentCols = conn
        .query_row(
            "SELECT agent, tool, phase, command, path, url FROM agent_events WHERE id = ?1",
            [id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()
        .ok()
        .flatten()?;
    let mut fields = Map::new();
    put(&mut fields, "agent", json!(agent));
    put(&mut fields, "tool", json!(tool));
    put(&mut fields, "phase", json!(phase));
    put(&mut fields, "command", json!(command));
    put(&mut fields, "path", json!(path));
    put(&mut fields, "url", json!(url));
    let summary = join(&[Some(agent), tool, phase, command.or(path).or(url)]);
    Some(RowDetail {
        summary,
        fields,
        proc: Value::Null,
    })
}
