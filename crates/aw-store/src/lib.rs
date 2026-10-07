//! SQLite storage: schema migrations and the batch writer.
//!
//! [`RecordSink`] is the trait P1-PIPE-05 should use. Do not declare another
//! one in `aw-pipeline`. That crate cannot depend on `rusqlite`; the SQL stays
//! in this crate. Queries live in [`query`]. Retention lives in the `retention` module.
//! Session export lives in [`export`].
//!
//! Windows file ACLs are not set. See [`migrate`] for why.

#![forbid(unsafe_code)]

mod error;
mod export;
mod migrate;
mod query;
mod retention;
mod sink;

pub use retention::{
    ApplyReport, DiskCheck, OldestSession, PurgeReason, PurgeReport, PurgeScope, Retention,
    RetentionConfig, Stats, TableCount, WriteMode,
};

pub use error::StoreError;
pub use export::{
    redact_host_field, redact_host_text, redact_user_paths, write_csv_zip, write_jsonl,
    write_jsonl_pages, ExportError, ExportOptions, ExportRecord, GapRecord, GapsSummary, Page,
    PageSource, Redact, SessionHeader,
};
pub use migrate::{OpenStatus, Store, SCHEMA_VERSION};
pub use query::{
    ensure_timeline, flows, gaps, list_sessions, parse_filter, process_tree, session_summary,
    timeline, Cursor, FilterExpr, FlowGroupBy, FlowQuery, FlowRow, FlowSort, GapItem, ProcessNode,
    QueryError, SessionFilter, SessionListItem, SessionSummary, TimelinePage, TimelineQuery,
    TimelineRow,
};
pub use sink::{
    DnsRow, GapRow, NetFlowBucketRow, NetFlowRow, ProcessImageRow, ProcessRow, RecordSink,
    SessionRow, SqliteSink, WriteBatch,
};

/// Empty marker so the daemon can name this crate before it constructs a [`Store`].
pub struct Placeholder;
