//! `aw http <SESSION> [--filter] [--json]` (P3-CLI-01).
//!
//! Rows come from a [`QuerySource`]. The live route is
//! `GET /api/v1/sessions/{sid}/http`. [`super::query::http_request`] builds that
//! call. This command does not open the database and does not dial the daemon.
//!
//! A session that did not enable the proxy is not an empty success: the source
//! returns `reason: no_proxy` and this command prints why URLs are unavailable.
//! Missing byte and duration columns render as `不可得`, never `0`. The URL cell
//! is the already-redacted value the source stored. This module does not print
//! a row with `Debug`.

use std::io;

use serde_json::{json, Value};

use crate::exit;
use crate::output::{OutputMode, Row, Table};

use super::query::{self, HttpItem, HttpPage, HttpQuery, QuerySource};
use super::render::{self, evidence_or_na};
use super::sessions::{query_outcome, write_ok};
use super::Outcome;

/// Parsed `aw http` arguments.
pub(crate) struct HttpArgs<'a> {
    /// `<SESSION>`: public id, name, or `@last`.
    pub session: &'a str,
    /// `--filter`. Forwarded; not compiled in the CLI.
    pub filter: Option<&'a str>,
    /// `--json`.
    pub json: bool,
}

/// Render HTTP rows for one session.
///
/// # Errors
///
/// A failure to format the outcome. The process code is [`Outcome::code`].
pub(crate) fn run(args: HttpArgs<'_>, source: &dyn QuerySource) -> io::Result<Outcome> {
    if args.session.trim().is_empty() {
        return Ok(super::error_outcome(
            exit::USAGE,
            "usage",
            "会话不能为空",
            args.json,
        ));
    }
    let query = HttpQuery {
        filter: args.filter.map(str::to_owned),
    };
    // Built so a wired client sends the documented query. The source looks up.
    let _request = query::http_request(args.session, &query);
    let mode = OutputMode::from_json_flag(args.json);
    match source.http(args.session, &query) {
        Ok(page) => {
            let table = http_table(&page);
            let doc = http_json(&page);
            let mut outcome = write_ok(mode, &table, &doc)?;
            if page.reason.as_deref() == Some("no_proxy") && mode == OutputMode::Table {
                let note = "aw: 此会话未启用代理，URL 不可得（no_proxy）\n";
                outcome.stderr.extend(note.as_bytes());
            }
            Ok(outcome)
        }
        Err(err) => Ok(query_outcome(err, args.json)),
    }
}

fn http_table(page: &HttpPage) -> Table {
    Table {
        headers: vec![
            "time".to_owned(),
            "proc".to_owned(),
            "method".to_owned(),
            "url".to_owned(),
            "status".to_owned(),
            "req_bytes".to_owned(),
            "resp_bytes".to_owned(),
            "duration_ms".to_owned(),
        ],
        rows: page
            .rows
            .iter()
            .map(|row| Row {
                cells: vec![
                    row.ts_ns.to_string(),
                    proc_cell(row),
                    row.method.clone(),
                    row.url.clone(),
                    query::opt_i64(row.status),
                    query::opt_i64(row.req_body_bytes),
                    query::opt_i64(row.resp_body_bytes),
                    query::opt_i64(row.duration_ms),
                ],
                evidence: evidence_or_na(row.evidence.as_ref()),
            })
            .collect(),
    }
}

/// `exe` when the API sent one, otherwise the process id, otherwise `不可得`.
fn proc_cell(row: &HttpItem) -> String {
    if let Some(exe) = row.proc_exe.as_deref() {
        if !exe.is_empty() {
            return exe.to_owned();
        }
    }
    if let Some(pid) = row.proc_pid {
        return pid.to_string();
    }
    query::opt_i64(row.proc_uid)
}

fn http_json(page: &HttpPage) -> Value {
    json!({
        "reason": page.reason,
        "http": page.rows.iter().map(|row| json!({
            "id": row.id,
            "ts_ns": row.ts_ns,
            "proc_uid": row.proc_uid,
            "proc": {
                "pid": row.proc_pid,
                "exe_name": row.proc_exe,
            },
            "method": row.method,
            "url": row.url,
            "status": row.status,
            "req_body_bytes": row.req_body_bytes,
            "resp_body_bytes": row.resp_body_bytes,
            "duration_ms": row.duration_ms,
            "evidence": row.evidence.as_ref().map(render::evidence_json),
        })).collect::<Vec<_>>(),
    })
}
