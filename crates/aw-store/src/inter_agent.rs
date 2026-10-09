//! Inter-agent rows (P6-STORE-01).
//!
//! Five inserts, one per table created by migration 0010. Nothing here reads
//! IPC. A collector that has not observed a field passes `None`, and SQLite
//! stores NULL. Byte counts are not filled in with 0: 0 would mean the probe
//! measured nothing, which is a different claim from "not observed".
//!
//! `agent_rpc` keeps a method name and the evidence for it. Arguments, results,
//! and message bodies are not fields of [`AgentRpcInsert`].

use rusqlite::{params, Connection};

use crate::error::StoreError;
use crate::migrate::{apply_inter_agent_schema, Store};

/// One `watch_groups` row.
#[derive(Clone)]
pub struct WatchGroupInsert {
    /// Public id used by the CLI. Not a hostname.
    pub public_id: String,
    /// OS user id of the person who created the group.
    pub user_id: String,
    /// User-given name.
    pub name: String,
    /// Wall-clock creation, Unix nanoseconds.
    pub created_ns: i64,
}

/// One `agent_instances` row.
#[derive(Clone)]
pub struct AgentInstanceInsert {
    /// Owning session.
    pub session_id: i64,
    /// `ProcUid` bit-cast to `i64`. Not a foreign key.
    pub proc_uid: i64,
    /// Agent profile id, or unknown.
    pub profile_id: Option<String>,
    /// `primary` / `sub_agent` / `mcp_server` / `tool` / `unknown`, or unknown.
    pub role: Option<String>,
    /// Parent instance in the same session, or none.
    pub parent_instance_id: Option<i64>,
    /// `E1|E2|E3|S|I|NA`.
    pub evidence: String,
    /// Collector source string.
    pub source: String,
}

/// One `ipc_channels` row. Byte columns stay NULL when the count was not observed.
#[derive(Clone)]
pub struct IpcChannelInsert {
    /// Owning session.
    pub session_id: i64,
    /// `pipe` / `unix_stream` / `unix_dgram` / `named_pipe` / `loopback_tcp` /
    /// `loopback_udp`.
    pub kind: String,
    /// Local endpoint description, already redacted, or unknown.
    pub endpoint_a: Option<String>,
    /// Peer endpoint description, already redacted, or unknown.
    pub endpoint_b: Option<String>,
    /// Bytes from A toward B. `None` is unobserved, not zero.
    pub bytes_a_to_b: Option<i64>,
    /// Bytes from B toward A. `None` is unobserved, not zero.
    pub bytes_b_to_a: Option<i64>,
    /// `E1|E2|E3|S|I|NA`.
    pub evidence: String,
    /// Collector source string.
    pub source: String,
}

/// One `agent_rpc` row. No argument or result body.
#[derive(Clone)]
pub struct AgentRpcInsert {
    /// Owning session.
    pub session_id: i64,
    /// Channel this call was observed on, or unknown.
    pub channel_id: Option<i64>,
    /// Method name (`tools/call`, …), or unknown.
    pub method: Option<String>,
    /// `E1|E2|E3|S|I|NA`.
    pub evidence: String,
    /// Collector source string.
    pub source: String,
}

/// One `agent_links` row.
#[derive(Clone)]
pub struct AgentLinkInsert {
    /// Session the link was recorded under. Not a foreign key: a link can name
    /// a session that is not the only one it spans.
    pub session_id: i64,
    /// Instance the link starts from.
    pub from_instance: i64,
    /// Instance the link ends at, or unknown.
    pub to_instance: Option<i64>,
    /// Channel the link was derived from, or unknown.
    pub channel_id: Option<i64>,
    /// `E1|E2|E3|S|I|NA`.
    pub evidence: String,
    /// Collector source string.
    pub source: String,
}

/// Ensure the inter-agent tables exist, then insert one watch group.
///
/// Returns the row id SQLite assigned.
///
/// # Errors
///
/// [`StoreError::ReadOnly`] when the database was opened read-only.
/// [`StoreError::Sqlite`] when migration fails or a required field is empty.
pub fn store_watch_group(store: &mut Store, row: &WatchGroupInsert) -> Result<i64, StoreError> {
    apply_inter_agent_schema(store)?;
    insert_watch_group(store.connection(), row)
}

/// Insert one watch group. The tables must already exist.
///
/// # Errors
///
/// [`StoreError::Sqlite`] when a required field is empty or SQLite refuses the row.
pub fn insert_watch_group(conn: &Connection, row: &WatchGroupInsert) -> Result<i64, StoreError> {
    if row.public_id.is_empty() || row.user_id.is_empty() || row.name.is_empty() {
        return Err(required("insert_watch_group"));
    }
    conn.execute(
        "INSERT INTO watch_groups (public_id, user_id, name, created_ns)
         VALUES (?1, ?2, ?3, ?4)",
        params![row.public_id, row.user_id, row.name, row.created_ns],
    )
    .map_err(|err| StoreError::sqlite("insert_watch_group", err))?;
    Ok(conn.last_insert_rowid())
}

/// Ensure the inter-agent tables exist, then insert one agent instance.
///
/// Returns the row id SQLite assigned.
///
/// # Errors
///
/// [`StoreError::ReadOnly`] when the database was opened read-only.
/// [`StoreError::Sqlite`] when migration fails or a required field is empty.
pub fn store_agent_instance(
    store: &mut Store,
    row: &AgentInstanceInsert,
) -> Result<i64, StoreError> {
    apply_inter_agent_schema(store)?;
    insert_agent_instance(store.connection(), row)
}

/// Insert one agent instance. The tables must already exist.
///
/// # Errors
///
/// [`StoreError::Sqlite`] when a required field is empty or SQLite refuses the row.
pub fn insert_agent_instance(
    conn: &Connection,
    row: &AgentInstanceInsert,
) -> Result<i64, StoreError> {
    if row.evidence.is_empty() || row.source.is_empty() {
        return Err(required("insert_agent_instance"));
    }
    conn.execute(
        "INSERT INTO agent_instances (
            session_id, proc_uid, profile_id, role, parent_instance_id, evidence, source
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            row.session_id,
            row.proc_uid,
            empty_as_null(row.profile_id.as_deref()),
            empty_as_null(row.role.as_deref()),
            row.parent_instance_id,
            row.evidence,
            row.source,
        ],
    )
    .map_err(|err| StoreError::sqlite("insert_agent_instance", err))?;
    Ok(conn.last_insert_rowid())
}

/// Ensure the inter-agent tables exist, then insert one IPC channel.
///
/// Returns the row id SQLite assigned.
///
/// # Errors
///
/// [`StoreError::ReadOnly`] when the database was opened read-only.
/// [`StoreError::Sqlite`] when migration fails or a required field is empty.
pub fn store_ipc_channel(store: &mut Store, row: &IpcChannelInsert) -> Result<i64, StoreError> {
    apply_inter_agent_schema(store)?;
    insert_ipc_channel(store.connection(), row)
}

/// Insert one IPC channel. The tables must already exist.
///
/// # Errors
///
/// [`StoreError::Sqlite`] when a required field is empty or SQLite refuses the row.
pub fn insert_ipc_channel(conn: &Connection, row: &IpcChannelInsert) -> Result<i64, StoreError> {
    if row.kind.is_empty() || row.evidence.is_empty() || row.source.is_empty() {
        return Err(required("insert_ipc_channel"));
    }
    conn.execute(
        "INSERT INTO ipc_channels (
            session_id, kind, endpoint_a, endpoint_b, bytes_a_to_b, bytes_b_to_a, evidence, source
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            row.session_id,
            row.kind,
            empty_as_null(row.endpoint_a.as_deref()),
            empty_as_null(row.endpoint_b.as_deref()),
            row.bytes_a_to_b,
            row.bytes_b_to_a,
            row.evidence,
            row.source,
        ],
    )
    .map_err(|err| StoreError::sqlite("insert_ipc_channel", err))?;
    Ok(conn.last_insert_rowid())
}

/// Ensure the inter-agent tables exist, then insert one RPC observation.
///
/// Returns the row id SQLite assigned.
///
/// # Errors
///
/// [`StoreError::ReadOnly`] when the database was opened read-only.
/// [`StoreError::Sqlite`] when migration fails or a required field is empty.
pub fn store_agent_rpc(store: &mut Store, row: &AgentRpcInsert) -> Result<i64, StoreError> {
    apply_inter_agent_schema(store)?;
    insert_agent_rpc(store.connection(), row)
}

/// Insert one RPC observation. The tables must already exist.
///
/// # Errors
///
/// [`StoreError::Sqlite`] when a required field is empty or SQLite refuses the row.
pub fn insert_agent_rpc(conn: &Connection, row: &AgentRpcInsert) -> Result<i64, StoreError> {
    if row.evidence.is_empty() || row.source.is_empty() {
        return Err(required("insert_agent_rpc"));
    }
    conn.execute(
        "INSERT INTO agent_rpc (session_id, channel_id, method, evidence, source)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            row.session_id,
            row.channel_id,
            empty_as_null(row.method.as_deref()),
            row.evidence,
            row.source,
        ],
    )
    .map_err(|err| StoreError::sqlite("insert_agent_rpc", err))?;
    Ok(conn.last_insert_rowid())
}

/// Ensure the inter-agent tables exist, then insert one agent link.
///
/// Returns the row id SQLite assigned.
///
/// # Errors
///
/// [`StoreError::ReadOnly`] when the database was opened read-only.
/// [`StoreError::Sqlite`] when migration fails or a required field is empty.
pub fn store_agent_link(store: &mut Store, row: &AgentLinkInsert) -> Result<i64, StoreError> {
    apply_inter_agent_schema(store)?;
    insert_agent_link(store.connection(), row)
}

/// Insert one agent link. The tables must already exist.
///
/// # Errors
///
/// [`StoreError::Sqlite`] when a required field is empty or SQLite refuses the row.
pub fn insert_agent_link(conn: &Connection, row: &AgentLinkInsert) -> Result<i64, StoreError> {
    if row.evidence.is_empty() || row.source.is_empty() {
        return Err(required("insert_agent_link"));
    }
    conn.execute(
        "INSERT INTO agent_links (
            session_id, from_instance, to_instance, channel_id, evidence, source
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            row.session_id,
            row.from_instance,
            row.to_instance,
            row.channel_id,
            row.evidence,
            row.source,
        ],
    )
    .map_err(|err| StoreError::sqlite("insert_agent_link", err))?;
    Ok(conn.last_insert_rowid())
}

fn required(op: &'static str) -> StoreError {
    StoreError::sqlite(
        op,
        rusqlite::Error::InvalidParameterName(
            "a required field is empty; an unknown value is not stored as \"\"".into(),
        ),
    )
}

/// `""` is not a value. Callers that pass it get NULL, the same as `None`.
fn empty_as_null(value: Option<&str>) -> Option<&str> {
    value.filter(|text| !text.is_empty())
}
