//! SQLite storage: schema migrations and the batch writer.
//!
//! [`RecordSink`] is the trait P1-PIPE-05 should use. Do not declare another
//! one in `aw-pipeline`. That crate cannot depend on `rusqlite`; the SQL stays
//! in this crate. Query and retention are later tasks and are not implemented here.
//!
//! Windows file ACLs are not set. See [`migrate`] for why.

#![forbid(unsafe_code)]

mod error;
mod migrate;
mod sink;

pub use error::StoreError;
pub use migrate::{OpenStatus, Store, SCHEMA_VERSION};
pub use sink::{
    DnsRow, GapRow, NetFlowBucketRow, NetFlowRow, ProcessImageRow, ProcessRow, RecordSink,
    SessionRow, SqliteSink, WriteBatch,
};

/// Empty marker so the daemon can name this crate before it constructs a [`Store`].
pub struct Placeholder;
