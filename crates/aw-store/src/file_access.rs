//! `file_access` rows and the partial-record UPSERT.
//!
//! storage.md §4: a `partial = 1` snapshot is updated in place when the same
//! `id` is written again. The final row (`partial = 0`) replaces the snapshot's
//! counters rather than adding to them, because the aggregator owns the totals
//! and a second add would double-count. Two partials do add: each one is a
//! delta the aggregator has not folded into a running total yet.
//!
//! NULL is "not observed". A later NULL does not wipe a known count, and a
//! known count is never stored as `0` to mean unknown. `opens` is `NOT NULL`
//! in the DDL, so it is not part of that rule.
//!
//! The indexed FTS text is `path`, plus `path_to` when the op is a rename.
//! Both are whatever the caller stored. This module does not redact them.

use rusqlite::{params, Connection};

use crate::error::StoreError;
use crate::fts::{self, FtsMode, FtsSource};

/// One `file_access` row. Not `Debug`: `path` may be a sensitive filesystem path.
#[derive(Clone)]
pub struct FileAccessRow {
    /// UPSERT key. The caller assigns it; SQLite does not, because a partial
    /// snapshot and its final row must share the id.
    pub id: i64,
    /// Owning session.
    pub session_id: i64,
    /// `ProcUid` bit-cast to `i64`. Not a foreign key.
    pub proc_uid: i64,
    /// `access` / `create` / `delete` / `rename` / `exec`.
    pub op: String,
    /// Path, already redacted by the pipeline. Required.
    pub path: String,
    /// Rename target, or unknown.
    pub path_to: Option<String>,
    /// `read` / `write` / `read_write` / `exec` / `unknown`, or unknown itself.
    pub access: Option<String>,
    /// First observation, Unix nanoseconds.
    pub first_ns: i64,
    /// Last observation, Unix nanoseconds.
    pub last_ns: i64,
    /// Open count. DDL default is 1; pass the real count, not a sentinel.
    pub opens: i64,
    /// Read count. `None` stays NULL.
    pub reads: Option<i64>,
    /// Bytes read. `None` stays NULL.
    pub bytes_read: Option<i64>,
    /// Write count. `None` stays NULL.
    pub writes: Option<i64>,
    /// Bytes written. `None` stays NULL.
    pub bytes_written: Option<i64>,
    /// `1` when the open created the file. `None` when that was not observed.
    pub created: Option<i64>,
    /// `1` when the open truncated the file. `None` when not observed.
    pub truncated: Option<i64>,
    /// `1` when the file was modified. `None` when not observed.
    pub modified: Option<i64>,
    /// Open result. `None` when not observed. `Some(0)` is a real success.
    pub result: Option<i64>,
    /// `1` for an intermediate snapshot, `0` for the final row.
    pub partial: i64,
    /// Sensitive-path rule id, or none.
    pub sensitive_rule: Option<String>,
    /// `E1|E2|E3|S|I|NA`.
    pub evidence: String,
    /// Why the record is `NA`, or NULL.
    pub na_reason: Option<String>,
    /// JSON field evidence, or NULL when empty.
    pub field_evidence: Option<String>,
    /// Collector source string.
    pub source: String,
}

/// Insert or merge `rows`, then refresh each row's FTS entry.
///
/// `fts` is the caller's `storage.fts` flag. [`FtsMode::Off`] still deletes a
/// stale FTS row for the id (a previous open may have indexed it) and does not
/// insert a new one.
pub fn write_rows(
    conn: &Connection,
    rows: &[FileAccessRow],
    fts: FtsMode,
) -> Result<(), StoreError> {
    if rows.is_empty() {
        return Ok(());
    }
    let mut stmt = conn
        .prepare_cached(&upsert_sql())
        .map_err(|err| StoreError::sqlite("prepare_file_access", err))?;
    for row in rows {
        stmt.execute(params![
            row.id,
            row.session_id,
            row.proc_uid,
            row.op,
            row.path,
            row.path_to,
            row.access,
            row.first_ns,
            row.last_ns,
            row.opens,
            row.reads,
            row.bytes_read,
            row.writes,
            row.bytes_written,
            row.created,
            row.truncated,
            row.modified,
            row.result,
            row.partial,
            row.sensitive_rule,
            row.evidence,
            row.na_reason,
            row.field_evidence,
            row.source,
        ])
        .map_err(|err| StoreError::sqlite("upsert_file_access", err))?;
        fts::upsert(
            conn,
            fts,
            FtsSource::FileAccess,
            row.id,
            Some(&indexed_text(row)),
        )?;
    }
    Ok(())
}

/// Text stored in `fts_text.body` for this row.
///
/// A rename indexes `path` and `path_to` joined by a newline, so a substring
/// query hits either side. The newline is not a path separator the user
/// searches for; trigram still matches inside each side.
fn indexed_text(row: &FileAccessRow) -> String {
    match &row.path_to {
        Some(to) if !to.is_empty() => format!("{}\n{to}", row.path),
        _ => row.path.clone(),
    }
}

/// `ON CONFLICT(id)`:
///
/// - `first_ns` keeps the earlier instant.
/// - `last_ns` keeps the later instant.
/// - A final row (`excluded.partial = 0`) replaces counters and flags.
/// - A partial row adds counters. NULL on either side stays NULL unless the
///   other side is known, in which case the known side is kept (not treated
///   as zero, and not dropped).
/// - `partial` becomes 0 once any write says the row is final.
/// - `path`, `op`, and `proc_uid` stay as first written. A partial and its
///   final row are the same access; a changed path is a different id.
fn upsert_sql() -> String {
    format!(
        "INSERT INTO file_access (
            id, session_id, proc_uid, op, path, path_to, access,
            first_ns, last_ns, opens, reads, bytes_read, writes, bytes_written,
            created, truncated, modified, result, partial, sensitive_rule,
            evidence, na_reason, field_evidence, source
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7,
            ?8, ?9, ?10, ?11, ?12, ?13, ?14,
            ?15, ?16, ?17, ?18, ?19, ?20,
            ?21, ?22, ?23, ?24
         )
         ON CONFLICT(id) DO UPDATE SET
            last_ns = CASE
                WHEN excluded.last_ns > file_access.last_ns THEN excluded.last_ns
                ELSE file_access.last_ns END,
            first_ns = CASE
                WHEN excluded.first_ns < file_access.first_ns THEN excluded.first_ns
                ELSE file_access.first_ns END,
            path_to = COALESCE(file_access.path_to, excluded.path_to),
            access = COALESCE(excluded.access, file_access.access),
            opens = CASE
                WHEN excluded.partial = 0 THEN excluded.opens
                ELSE file_access.opens + excluded.opens END,
            reads = {reads},
            bytes_read = {bytes_read},
            writes = {writes},
            bytes_written = {bytes_written},
            created = COALESCE(excluded.created, file_access.created),
            truncated = COALESCE(excluded.truncated, file_access.truncated),
            modified = COALESCE(excluded.modified, file_access.modified),
            result = COALESCE(excluded.result, file_access.result),
            partial = CASE
                WHEN file_access.partial = 0 OR excluded.partial = 0 THEN 0
                ELSE 1 END,
            sensitive_rule = COALESCE(file_access.sensitive_rule, excluded.sensitive_rule),
            evidence = excluded.evidence,
            na_reason = COALESCE(excluded.na_reason, file_access.na_reason),
            field_evidence = COALESCE(excluded.field_evidence, file_access.field_evidence),
            source = excluded.source",
        reads = merge_nullable("reads"),
        bytes_read = merge_nullable("bytes_read"),
        writes = merge_nullable("writes"),
        bytes_written = merge_nullable("bytes_written"),
    )
}

/// Final row replaces. Partial row: NULL + NULL = NULL; one known side wins;
/// two known sides add.
fn merge_nullable(col: &str) -> String {
    format!(
        "CASE
            WHEN excluded.partial = 0 THEN COALESCE(excluded.{col}, file_access.{col})
            WHEN excluded.{col} IS NULL THEN file_access.{col}
            WHEN file_access.{col} IS NULL THEN excluded.{col}
            ELSE file_access.{col} + excluded.{col} END"
    )
}
