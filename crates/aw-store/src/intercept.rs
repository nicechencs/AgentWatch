//! `intercept_events` rows: one deny, rewrite, ask, or downgrade (P5-SEC-01).
//!
//! Summaries are already redacted and truncated by the caller. This module
//! does not re-expand them and does not log them. A missing field is `None`,
//! which SQLite stores as NULL. An empty string is not written.

use rusqlite::{params, Connection};

use crate::error::StoreError;
use crate::migrate::{apply_intercept_schema, Store};

/// One `intercept_events` row. Not `Debug`: summaries are still derived from
/// commands and URLs.
#[derive(Clone)]
pub struct InterceptEventInsert {
    /// Session row id. `None` when the public id did not resolve.
    pub session_id: Option<i64>,
    /// Unix nanoseconds.
    pub ts_ns: i64,
    /// Agent id, or unknown.
    pub agent: Option<String>,
    /// `hook` / `mcp` / `proxy`. Required.
    pub layer: String,
    /// Hook event name, or unknown.
    pub event: Option<String>,
    /// Winning rule, or unknown.
    pub rule_id: Option<String>,
    /// Rule action. Required.
    pub action: String,
    /// Action actually taken. Required.
    pub effective_action: String,
    /// Tool name, or unknown.
    pub tool: Option<String>,
    /// Host, or unknown.
    pub host: Option<String>,
    /// MCP method, or unknown.
    pub mcp_method: Option<String>,
    /// Redacted original summary. Required; an empty string is refused.
    pub before_summary: String,
    /// Hex SHA-256 of the original. Required.
    pub before_hash: String,
    /// Redacted replacement, only for a rewrite.
    pub after_summary: Option<String>,
    /// Hash of the replacement, only for a rewrite.
    pub after_hash: Option<String>,
    /// Sentence shown to the agent. Not a secret.
    pub reason: Option<String>,
    /// `E3` or `S`. Required.
    pub evidence: String,
    /// `intercept.<agent>/hook`, `intercept.mcp-tap`, or `intercept.proxy`.
    pub source: String,
    /// `daemon` / `local_backup` / `dropped`.
    pub delivered: String,
    /// `true` when `effective_action` is not `action`.
    pub downgraded: bool,
}

/// Ensure `intercept_events` exists, then insert one row.
///
/// # Errors
///
/// [`StoreError::ReadOnly`] when the database was opened read-only.
/// [`StoreError::Sqlite`] when migration or the insert fails.
pub fn store_intercept_event(
    store: &mut Store,
    row: &InterceptEventInsert,
) -> Result<(), StoreError> {
    apply_intercept_schema(store)?;
    insert_intercept_event(store.connection(), row)
}

/// Insert one intercept row. The table must already exist.
///
/// # Errors
///
/// [`StoreError::Sqlite`] when a required field is empty or SQLite refuses the row.
pub fn insert_intercept_event(
    conn: &Connection,
    row: &InterceptEventInsert,
) -> Result<(), StoreError> {
    if row.layer.is_empty()
        || row.action.is_empty()
        || row.effective_action.is_empty()
        || row.before_summary.is_empty()
        || row.before_hash.is_empty()
        || row.evidence.is_empty()
        || row.source.is_empty()
        || row.delivered.is_empty()
    {
        return Err(StoreError::sqlite(
            "insert_intercept_event",
            rusqlite::Error::InvalidParameterName(
                "layer, action, effective_action, before_summary, before_hash, evidence, source, and delivered are required"
                    .into(),
            ),
        ));
    }
    conn.execute(
        "INSERT INTO intercept_events (
            session_id, ts_ns, agent, layer, event, rule_id,
            action, effective_action, tool, host, mcp_method,
            before_summary, before_hash, after_summary, after_hash,
            reason, evidence, source, delivered, downgraded
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6,
            ?7, ?8, ?9, ?10, ?11,
            ?12, ?13, ?14, ?15,
            ?16, ?17, ?18, ?19, ?20
         )",
        params![
            row.session_id,
            row.ts_ns,
            empty_as_null(row.agent.as_deref()),
            row.layer,
            empty_as_null(row.event.as_deref()),
            empty_as_null(row.rule_id.as_deref()),
            row.action,
            row.effective_action,
            empty_as_null(row.tool.as_deref()),
            empty_as_null(row.host.as_deref()),
            empty_as_null(row.mcp_method.as_deref()),
            row.before_summary,
            row.before_hash,
            empty_as_null(row.after_summary.as_deref()),
            empty_as_null(row.after_hash.as_deref()),
            empty_as_null(row.reason.as_deref()),
            row.evidence,
            row.source,
            row.delivered,
            i64::from(row.downgraded),
        ],
    )
    .map_err(|err| StoreError::sqlite("insert_intercept_event", err))?;
    Ok(())
}

/// Record that one intercept audit could not be stored.
///
/// `detail` is a reason code, not a payload. This is a gap, not an intercept row.
///
/// # Errors
///
/// [`StoreError::Sqlite`] when the `gaps` table cannot be written.
pub fn insert_intercept_gap(
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
         ) VALUES (?1, 'intercept', 'intercept_audit_dropped', '[\"agent\"]', ?2, ?2, 1, ?3)",
        params![session_id, ts_ns, detail],
    )
    .map_err(|err| StoreError::sqlite("insert_intercept_gap", err))?;
    Ok(())
}

fn empty_as_null(value: Option<&str>) -> Option<&str> {
    value.filter(|text| !text.is_empty())
}
