//! Session export to JSONL and CSV zip (P1-STORE-03).
//!
//! Callers pass a [`std::io::Write`]. This module does not open files and does
//! not write into a user directory. The daemon should stream the bytes out of
//! its API; the CLI is what writes them to disk.
//!
//! # What storage.md §7 fixes, and what it does not
//!
//! Fixed by [storage §7](https://github.com/):
//!
//! - JSONL starts with one header object: `type`, `export_version`, `session`,
//!   `collectors`, `gaps_summary`.
//! - Each later line is one record: `type` plus the table columns, time order.
//! - Every record carries `evidence`.
//! - CSV is a zip of one file per record kind plus `README.txt`.
//!
//! Not fixed there, so this module chooses and documents the choice:
//!
//! - `export_version` is the integer `1`.
//! - `session` contains `id`, `public_id`, `name`, `mode`, `agent`,
//!   `started_ns`, `ended_ns`, `platform`, `user_id`. It does not contain
//!   `argv`, `cwd`, or `stats` (those are sensitive or undocumented here).
//! - `collectors` is the `sessions.collectors` JSON value embedded as JSON.
//!   A column that is not a JSON value is [`ExportError::BadStoredJson`].
//! - `gaps_summary` is the whole session, **not** narrowed by `--filter`:
//!   `rows` (gap row count), `unknown_count` (rows whose `count` is NULL),
//!   `lost` (SQLite `SUM(count)`; `null` when every `count` is NULL or there
//!   are no rows — never `0` standing in for unknown), `by_collector`
//!   (same three numbers per `collector`, ordered by collector name).
//! - Record `type` is the table name: `processes`, `net_flows`, `dns`, `gaps`.
//! - Time order is `(time, type, id)`. The time column is `processes.start_ns`,
//!   `net_flows.start_ns`, `dns.ts_ns`, or `gaps.from_ns`. `type` is the table
//!   name, so ties sort as `dns`, `gaps`, `net_flows`, `processes`. For
//!   processes, `id` is `proc_uid` (the table has no surrogate id). This is
//!   stricter than `ORDER BY ts_ns, id` on the timeline view, which can tie
//!   across tables.
//! - `field_evidence`, `answers`, `domain_alts`, and `affects` are embedded as
//!   JSON when the stored text is one JSON value, otherwise the export fails.
//!   SQL NULL is JSON `null`, not `{}` and not `""`.
//! - `gaps` has no `evidence` or `field_evidence` column. The timeline view
//!   stores the literal `E1` (storage.md §3.1). JSONL repeats that: `"evidence":"E1"`
//!   and `"field_evidence":null`. CSV adds an `evidence` column and does not
//!   invent a `field_evidence` column.
//! - P1 CSV files are only `processes.csv`, `net_flows.csv`, `dns.csv`,
//!   `gaps.csv`, and `README.txt`. `process_images` is not a P1 CSV file, so
//!   exe / argv are absent even though the table exists.
//! - `--filter` reuses [`crate::query::parse_filter`] and the query layer's
//!   SQL compiler (`Target::Timeline`). It is not a second parser.
//! - `--redact-paths` / `--redact-hosts` are the substitutions in [`redact`].
//!   They are not the P2 redaction module. The header is not redacted.
//! - Zip entry timestamps are zero. Compression method is store (0).
//! - A failure after the first byte leaves whatever was already written.
//!   The caller discards that buffer. Nothing is retried silently, and a
//!   missing row is [`ExportError::MissingRow`], not a skipped record.
//!
//! Byte columns (`bytes_up`, `bytes_down`, and the platform totals) stay null
//! when the database has NULL. Null is "not observed", not zero octets.

mod csvzip;
mod jsonl;
mod jsontext;
mod records;
mod redact;
mod source;

pub use csvzip::write_csv_zip;
pub use jsonl::{write_jsonl, write_jsonl_pages};
pub use records::{ExportRecord, GapRecord, GapsSummary, Page, PageSource, SessionHeader};
pub use redact::{redact_host_field, redact_host_text, redact_user_paths};
pub use source::Redact;

use std::fmt;
use std::io;

use crate::query::QueryError;

/// Why an export stopped.
///
/// Display text names the column or the table. It does not include stored
/// paths, argv, domains, or the filter text.
#[derive(Debug)]
pub enum ExportError {
    /// The session is missing, or it belongs to another user.
    NotFound {
        /// `sessions.id` the caller asked for.
        session_id: i64,
    },
    /// The filter or a query failed.
    Query(QueryError),
    /// A stored JSON column is not one JSON value.
    BadStoredJson {
        /// Column name.
        column: &'static str,
    },
    /// A timeline row disappeared before the detail read.
    MissingRow {
        /// Table name.
        table: &'static str,
        /// Primary id, or `proc_uid` for processes.
        id: i64,
    },
    /// A zip size does not fit in the classic 32-bit field.
    TooLarge {
        /// Which entry.
        name: &'static str,
    },
    /// `page_size` was outside `1..=1000`.
    BadPageSize,
    /// The caller’s writer failed.
    Io {
        /// What was being written.
        op: &'static str,
        /// OS error.
        source: io::Error,
    },
}

impl fmt::Display for ExportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound { session_id } => {
                write!(f, "session {session_id} is not visible")
            }
            Self::Query(err) => write!(f, "{err}"),
            Self::BadStoredJson { column } => {
                write!(f, "stored {column} is not a JSON value")
            }
            Self::MissingRow { table, id } => {
                write!(f, "missing {table} row {id} during export")
            }
            Self::TooLarge { name } => write!(f, "{name} is larger than a zip32 entry"),
            Self::BadPageSize => write!(f, "page_size must be 1..=1000"),
            Self::Io { op, source } => write!(f, "{op}: {source}"),
        }
    }
}

impl std::error::Error for ExportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Query(err) => Some(err),
            Self::Io { source, .. } => Some(source),
            Self::NotFound { .. }
            | Self::BadStoredJson { .. }
            | Self::MissingRow { .. }
            | Self::TooLarge { .. }
            | Self::BadPageSize => None,
        }
    }
}

impl From<QueryError> for ExportError {
    fn from(err: QueryError) -> Self {
        Self::Query(err)
    }
}

pub(crate) fn io_err(op: &'static str, source: io::Error) -> ExportError {
    ExportError::Io { op, source }
}

/// Options for one export. The caller owns the session identity check inputs.
pub struct ExportOptions<'a> {
    /// `sessions.user_id`. Rows for any other user are not visible.
    pub user_id: &'a str,
    /// `sessions.id`.
    pub session_id: i64,
    /// Filter expression. `None` or `""` exports every P1 record in the session.
    /// Parsed by [`crate::query::parse_filter`].
    pub filter: Option<&'a str>,
    /// Clock for `time:-…`. `None` leaves a relative “ago” filter as an error
    /// instead of substituting zero.
    pub now_ns: Option<i64>,
    /// Replace `/Users/<name>`, `/home/<name>`, and `X:\Users\<name>` segments.
    pub redact_paths: bool,
    /// Replace hostname-shaped domain labels. See [`redact`].
    pub redact_hosts: bool,
    /// Rows fetched per page. `None` is 1000, the query layer's maximum page.
    pub page_size: Option<i64>,
}
