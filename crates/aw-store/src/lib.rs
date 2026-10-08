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
mod file_access;
mod fts;
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
pub use file_access::FileAccessRow;
pub use fts::{read_mode as read_fts_mode, set_mode as set_fts_mode, FtsMode, FtsSource};
pub use migrate::FILE_SCHEMA_VERSION;
pub use migrate::{OpenStatus, Store, SCHEMA_VERSION};
pub use query::{
    around, around_sql, compile_predicate, compile_store_expr, delete_session, dns_events,
    ensure_timeline, files, flow_buckets, flows, gaps, keyset_suffix, list_sessions, parse_filter,
    patch_session, process_detail, process_tree, search, search_sql, search_sql_instr,
    session_by_public_id, session_summary, stop_session, timeline, timeline_histogram, traffic,
    AroundRow, CompileCtx, Compiled, Cursor, DnsEvent, DnsPage, FileGroupBy, FilePage, FileQuery,
    FileRow, FilterExpr, FlowBucket, FlowGroupBy, FlowQuery, FlowRow, FlowSort, GapItem,
    HistBucket, ProcessDetail, ProcessImage, ProcessNode, QueryError, SearchHit, SessionFilter,
    SessionListItem, SessionSummary, StoreExpr, StoreField, StoreOp, StoreParam, StoreTarget,
    StoreTerm, StoreValue, TimelinePage, TimelineQuery, TimelineRow, TrafficBucket,
};
pub use sink::{
    apply_file_schema, DnsRow, GapRow, NetFlowBucketRow, NetFlowRow, ProcessImageRow, ProcessRow,
    RecordSink, SessionRow, SqliteSink, WriteBatch,
};

/// Empty marker so the daemon can name this crate before it constructs a [`Store`].
pub struct Placeholder;
