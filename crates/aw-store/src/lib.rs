//! SQLite storage: schema migrations and the batch writer.
//!
//! [`RecordSink`] is the trait P1-PIPE-05 should use. Do not declare another
//! one in `aw-pipeline`. That crate cannot depend on `rusqlite`; the SQL stays
//! in this crate. Queries live in [`query`]. Retention lives in the `retention` module.
//! Session export lives in [`export`].
//!
//! Windows file ACLs are not set. See [`migrate`] for why.

#![forbid(unsafe_code)]

mod agent_events;
mod connection;
mod error;
mod export;
mod file_access;
mod findings;
mod fts;
mod http;
mod inter_agent;
mod merge;
mod migrate;
mod query;
mod retention;
mod sink;

pub use retention::{
    ApplyReport, DiskCheck, OldestSession, PurgeReason, PurgeReport, PurgeScope, Retention,
    RetentionConfig, Stats, TableCount, WriteMode,
};

pub use agent_events::{
    insert_agent_event, insert_self_report_gap, session_id_by_public, store_agent_event,
    AgentEventInsert,
};
pub use connection::{
    configure_connection, open_connection, open_connection_with_flags, open_in_memory_connection,
    BUSY_TIMEOUT,
};
pub use error::StoreError;
pub use export::{
    redact_host_field, redact_host_text, redact_user_paths, write_csv_zip, write_jsonl,
    write_jsonl_pages, ExportError, ExportOptions, ExportRecord, GapRecord, GapsSummary, Page,
    PageSource, Redact, SessionHeader,
};
pub use file_access::FileAccessRow;
pub use findings::{upsert_finding, FindingRef, FindingRow, MAX_REFS};
pub use fts::{read_mode as read_fts_mode, set_mode as set_fts_mode, FtsMode, FtsSource};
pub use http::{insert_http, HttpRow};
pub use inter_agent::{
    insert_agent_instance, insert_agent_link, insert_agent_rpc, insert_ipc_channel,
    insert_watch_group, store_agent_instance, store_agent_link, store_agent_rpc, store_ipc_channel,
    store_watch_group, AgentInstanceInsert, AgentLinkInsert, AgentRpcInsert, IpcChannelInsert,
    WatchGroupInsert,
};
pub use merge::{merge_exports, ClockSkew, MergeError, MergeReport, MergeRequest};
pub use migrate::FILE_SCHEMA_VERSION;
pub use migrate::{
    apply_agent_schema, apply_http_schema, apply_inter_agent_schema, apply_proxy_schema,
    OpenStatus, Store, AGENT_SCHEMA_VERSION, HTTP_SCHEMA_VERSION, INTER_AGENT_SCHEMA_VERSION,
    PROXY_SCHEMA_VERSION, SCHEMA_VERSION,
};
pub use query::{
    around, around_sql, compile_predicate, compile_store_expr, delete_session, dns_events,
    ensure_timeline, files, flow_buckets, flows, gaps, keyset_suffix, list_all_sessions,
    list_sessions, newest_session_for_user, parse_filter, patch_session, process_detail,
    process_tree, process_tree_filtered, public_id_by_session_id, search, search_sql,
    search_sql_instr, session_by_public_id, session_counts, session_summary, stop_session,
    timeline, timeline_histogram, traffic, AroundRow, CompileCtx, Compiled, Cursor, DnsEvent,
    DnsPage, FileGroupBy, FilePage, FileQuery, FileRow, FilterExpr, FlowBucket, FlowGroupBy,
    FlowQuery, FlowRow, FlowSort, GapItem, HistBucket, ProcessDetail, ProcessImage, ProcessNode,
    QueryError, SearchHit, SessionCounts, SessionFilter, SessionListItem, SessionSummary,
    StoreExpr, StoreField, StoreOp, StoreParam, StoreTarget, StoreTerm, StoreValue, TimelinePage,
    TimelineQuery, TimelineRow, TrafficBucket,
};
pub use sink::{
    apply_file_schema, DnsRow, GapRow, NetFlowBucketRow, NetFlowRow, ProcessImageRow, ProcessRow,
    RecordSink, SessionRow, SqliteSink, WriteBatch, MAX_ROWS_PER_TRANSACTION,
};

/// Empty marker so the daemon can name this crate before it constructs a [`Store`].
pub struct Placeholder;
