//! `agent_events` rows: one bounded E3 self-report (P5-AGENT-02).
//!
//! The summary columns are the structured fields an adapter may keep: command,
//! path, url, query, tool. A prompt, a file body, an HTTP body, and the values
//! of Authorization or Cookie are not parameters of this insert. `summary_json`
//! is stored as the caller handed it over; this module does not re-expand it
//! and does not log it.
//!
//! A missing field is `None`, which SQLite stores as NULL. An empty string is
//! not written: that would claim the field was observed and empty.

use rusqlite::{OptionalExtension, params, Connection};

use crate::error::StoreError;
use crate::migrate::{apply_agent_schema, Store};

/// One `agent_events` row. Not `Debug`: `command`, `path`, `url`, and `query`
/// are the same shape as argv and request targets.
#[derive(Clone)]
pub struct AgentEventInsert {
    /// Session row id, looked up by the caller. `None` when the public id did
    /// not resolve. Not `Some(0)`.
    pub session_id: Option<i64>,
    /// Unix nanoseconds. Required by the DDL.
    pub ts_ns: i64,
    /// Agent id. Required. Not a display name.
    pub agent: String,
    /// Tool name, or unknown.
    pub tool: Option<String>,
    /// `pre` / `post` / `unknown`, or unknown when the payload had no phase.
    pub phase: Option<String>,
    /// Adapter call id, or unknown.
    pub call_id: Option<String>,
    /// Structured command summary, or unknown.
    pub command: Option<String>,
    /// Structured path summary, or unknown.
    pub path: Option<String>,
    /// Structured URL summary, already redacted by the caller, or unknown.
    pub url: Option<String>,
    /// Structured query summary, or unknown.
    pub query: Option<String>,
    /// Bounded summary object. `None` inserts NULL. Not logged.
    pub summary_json: Option<String>,
    /// `E3` for a self-report. The caller sets it; this module does not upgrade it.
    pub evidence: String,
    /// `agent.<id>/hook` or `agent.<id>/otel`.
    pub source: String,
    /// JSON field evidence. `None` inserts NULL, not `""`.
    pub field_evidence: Option<String>,
    /// Why the row is `NA`, when `evidence` is `NA`. `None` inserts NULL.
    pub na_reason: Option<String>,
}

/// Integer id for `public_id`, with no user filter.
///
/// A hook names a session by the id `aw run` injected. It has no caller user,
/// so the user-scoped lookup would miss a real session. `Ok(None)` is "not in
/// this database", not a guessed id, and the caller stores NULL.
///
/// # Errors
///
/// [`StoreError::Sqlite`] when the `sessions` table cannot be read.
pub fn session_id_by_public(conn: &Connection, public_id: &str) -> Result<Option<i64>, StoreError> {
    conn.query_row(
        "SELECT id FROM sessions WHERE public_id = ?1",
        params![public_id],
        |row| row.get(0),
    )
    .optional()
    .map_err(|err| StoreError::sqlite("session_id_by_public", err))
}

/// Record that one self-report was discarded.
///
/// `detail` is a reason code (`timeout`, `send_failed`), not a payload. The
/// session is NULL when it did not resolve. This is a gap, not a tool-call row.
///
/// # Errors
///
/// [`StoreError::Sqlite`] when the `gaps` table cannot be written.
pub fn insert_self_report_gap(
    conn: &Connection,
    session_id: Option<i64>,
    ts_ns: i64,
    detail: &str,
) -> Result<(), StoreError> {
    let detail = if detail.is_empty() {
        None
    } else {
        Some(detail)
    };
    conn.execute(
        "INSERT INTO gaps (
            session_id, collector, kind, affects, from_ns, to_ns, count, detail
         ) VALUES (?1, 'agent.self_report', 'self_report_dropped', '[\"agent\"]', ?2, ?2, 1, ?3)",
        params![session_id, ts_ns, detail],
    )
    .map_err(|err| StoreError::sqlite("insert_self_report_gap", err))?;
    Ok(())
}

/// Ensure `agent_events` exists, then insert one self-report.
///
/// A database that has never stored a self-report is migrated here, not at
/// [`Store::open`]. When the table cannot be created, or the insert fails, the
/// error is returned and nothing is reported as stored.
///
/// # Errors
///
/// [`StoreError::ReadOnly`] when the database was opened read-only.
/// [`StoreError::Sqlite`] when migration or the insert fails.
pub fn store_agent_event(store: &mut Store, row: &AgentEventInsert) -> Result<(), StoreError> {
    apply_agent_schema(store)?;
    insert_agent_event(store.connection(), row)
}

/// Insert one self-report.
///
/// Empty strings are stored as NULL. An empty `agent`, `evidence`, or `source`
/// is refused: those columns are `NOT NULL`, and `""` would mean "observed and
/// blank" rather than missing.
///
/// # Errors
///
/// [`StoreError::Sqlite`] when a required field is empty or SQLite refuses the row.
pub fn insert_agent_event(conn: &Connection, row: &AgentEventInsert) -> Result<(), StoreError> {
    if row.agent.is_empty() || row.evidence.is_empty() || row.source.is_empty() {
        return Err(StoreError::sqlite(
            "insert_agent_event",
            rusqlite::Error::InvalidParameterName(
                "agent, evidence, and source are required; an unknown value is not stored as \"\""
                    .into(),
            ),
        ));
    }
    conn.execute(
        "INSERT INTO agent_events (
            session_id, ts_ns, agent, tool, phase, call_id,
            command, path, url, query, summary_json,
            evidence, source, field_evidence, na_reason
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6,
            ?7, ?8, ?9, ?10, ?11,
            ?12, ?13, ?14, ?15
         )",
        params![
            row.session_id,
            row.ts_ns,
            row.agent,
            empty_as_null(row.tool.as_deref()),
            empty_as_null(row.phase.as_deref()),
            empty_as_null(row.call_id.as_deref()),
            empty_as_null(row.command.as_deref()),
            empty_as_null(row.path.as_deref()),
            empty_as_null(row.url.as_deref()),
            empty_as_null(row.query.as_deref()),
            empty_as_null(row.summary_json.as_deref()),
            row.evidence,
            row.source,
            empty_as_null(row.field_evidence.as_deref()),
            empty_as_null(row.na_reason.as_deref()),
        ],
    )
    .map_err(|err| StoreError::sqlite("insert_agent_event", err))?;
    Ok(())
}

/// `""` is not a value. Callers that pass it get NULL, the same as `None`.
fn empty_as_null(value: Option<&str>) -> Option<&str> {
    value.filter(|text| !text.is_empty())
}
