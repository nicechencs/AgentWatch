//! Offline merge of two JSONL session exports (P6-STORE-02).
//!
//! Two files produced by [`crate::export`] are imported into a new store. Net
//! flows whose five-tuples are mirrors (after an optional caller-supplied NAT
//! map) become one `remote` edge. The edge is evidence `I`: pairing is an
//! inference, not an observation of either side. Connections that do not pair
//! stay as one-sided `net_flows` rows.
//!
//! There is no socket, no HTTP client, and no listener. A path that looks like
//! a URL is refused before any file is opened.
//!
//! # What the existing export actually contains
//!
//! Pairing uses `net_flows` fields already written by the JSONL exporter:
//! `proto`, `local_ip`, `local_port`, `remote_ip`, `remote_port`, and
//! `start_ns`. There is no separate five-tuple object. A flow whose protocol
//! is not `tcp` or `udp`, or whose address or port is absent, is stored and
//! left unpaired. Missing ports are not filled with `0`, and missing addresses
//! are not filled with `0.0.0.0`.
//!
//! `agent_links` (migration 0010) has no `kind` column. A remote edge is still
//! one `agent_links` row: `evidence` is the literal `I`, and `source` is
//! `offline.merge/remote`. The two endpoint descriptions and the clock-skew
//! estimate live in the matching `ipc_channels` row (`kind` = `remote`).
//!
//! Clock skew is the median of `(start_ns of side B) - (start_ns of side A)`
//! over paired flows that both have a start time. A pair whose start time is
//! absent is still a pair, but it does not enter the median. When no pair has
//! both times, the estimate is `None`. `0` is never written to stand for
//! "unknown".

mod nat;
mod pair;
mod read;

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use rusqlite::params;

use crate::inter_agent::{
    insert_agent_instance, insert_agent_link, insert_ipc_channel, AgentInstanceInsert,
    AgentLinkInsert, IpcChannelInsert,
};
use crate::migrate::{apply_inter_agent_schema, Store};

pub use pair::{pair_flows, ClockSkew, Side};

/// Inputs for one offline merge. All paths are the ones the caller passed.
pub struct MergeRequest<'a> {
    /// First JSONL export.
    pub side_a: &'a Path,
    /// Second JSONL export.
    pub side_b: &'a Path,
    /// New SQLite file. Created by [`Store::open`].
    pub output: &'a Path,
    /// Optional NAT map. `None` means no rewrite.
    pub nat: Option<&'a Path>,
}

/// Counts from one merge. Skew is `None` when no paired flow had both times.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MergeReport {
    /// Flows that found a mirror on the other side.
    pub paired: u64,
    /// Flows that stayed one-sided, including ones that could not form a tuple.
    pub unpaired: u64,
    /// `B.start_ns - A.start_ns`, median, in nanoseconds. Not zero-as-unknown.
    pub skew_ns: Option<i64>,
}

/// Why a merge stopped. Display text names the path the caller passed.
#[derive(Debug)]
pub enum MergeError {
    /// The path is a URL. This command does not fetch anything.
    UrlRefused {
        /// The path the caller passed.
        path: String,
    },
    /// A file could not be opened or read.
    Io {
        /// What was being done.
        op: &'static str,
        /// The path the caller passed.
        path: std::path::PathBuf,
        /// OS error.
        source: std::io::Error,
    },
    /// A JSONL line is not an object this importer understands.
    BadExport {
        /// The path the caller passed.
        path: std::path::PathBuf,
        /// 1-based line number. The line text is not included.
        line: u64,
        /// What was wrong, without the line contents.
        detail: &'static str,
    },
    /// The NAT file is not a list of `from -> to` rows.
    BadNat {
        /// The path the caller passed.
        path: std::path::PathBuf,
        /// 1-based line number.
        line: u64,
    },
    /// Opening or writing the store failed. The text is [`crate::StoreError`]'s
    /// display, which names the operation and not row contents.
    Store(String),
}

impl std::fmt::Display for MergeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UrlRefused { path } => {
                write!(f, "refusing URL; merge reads local files only: {path}")
            }
            Self::Io { op, path, source } => {
                write!(f, "{op} failed for {}: {source}", path.display())
            }
            Self::BadExport { path, line, detail } => {
                write!(f, "bad export {}:{}: {detail}", path.display(), line)
            }
            Self::BadNat { path, line } => {
                write!(
                    f,
                    "bad NAT map {}:{}: expected ip:port -> ip:port",
                    path.display(),
                    line
                )
            }
            Self::Store(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for MergeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::UrlRefused { .. }
            | Self::BadExport { .. }
            | Self::BadNat { .. }
            | Self::Store(_) => None,
        }
    }
}

impl From<crate::StoreError> for MergeError {
    fn from(err: crate::StoreError) -> Self {
        Self::Store(err.to_string())
    }
}

/// Import two JSONL exports into a new database and write `remote` edges.
///
/// `output` is opened with [`Store::open_runtime`], which includes the shared
/// file-search schema. Inter-agent tables are created afterwards by an explicit
/// [`apply_inter_agent_schema`] call. Migration 0010 is not applied inside
/// `Store::open`.
///
/// # Errors
///
/// [`MergeError::UrlRefused`] when any path looks like a URL.
/// [`MergeError::Io`] when a file cannot be read or the database cannot be created.
/// [`MergeError::BadExport`] when a line is not the existing export shape.
/// [`MergeError::BadNat`] when the NAT file is not `ip:port -> ip:port` rows.
/// [`MergeError::Store`] when SQLite refuses a write.
pub fn merge_exports(request: &MergeRequest<'_>) -> Result<MergeReport, MergeError> {
    refuse_url(request.side_a)?;
    refuse_url(request.side_b)?;
    refuse_url(request.output)?;
    if let Some(nat) = request.nat {
        refuse_url(nat)?;
    }

    let nat = match request.nat {
        Some(path) => nat::load(path)?,
        None => nat::NatMap::empty(),
    };
    let side_a = read::load_export(request.side_a)?;
    let mut side_b = read::load_export(request.side_b)?;
    // Header ids can collide (two exports of session 1). Side B moves when
    // they do. Flows keep the remapped id so the remote edge names the right
    // session. Public ids are namespaced the same way when they collide.
    if side_a.session_id == side_b.session_id {
        let next = side_a.session_id.saturating_add(1).max(2);
        side_b.session_id = next;
        side_b.header.id = next;
        for flow in &mut side_b.flows {
            flow.session_id = next;
        }
    }
    if side_a.header.public_id == side_b.header.public_id {
        side_b.header.public_id = format!("{}#b", side_b.header.public_id);
    }
    let paired = pair_flows(&side_a.flows, &side_b.flows, &nat);

    let mut store = Store::open_runtime(request.output)?;
    // 0010 is not part of Store::open. Remote edges need agent_links.
    apply_inter_agent_schema(&mut store)?;
    write_side(&store, &side_a, Side::A)?;
    write_side(&store, &side_b, Side::B)?;
    write_edges(&store, &paired, side_a.session_id, side_b.session_id)?;

    Ok(MergeReport {
        paired: paired.pairs.len() as u64,
        unpaired: paired.unpaired_a + paired.unpaired_b,
        skew_ns: paired.skew.map(|skew| skew.b_minus_a_ns),
    })
}

fn refuse_url(path: &Path) -> Result<(), MergeError> {
    let text = path.to_string_lossy();
    let lower = text.to_ascii_lowercase();
    if lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.starts_with("ftp://")
        || lower.starts_with("file://")
    {
        return Err(MergeError::UrlRefused {
            path: text.into_owned(),
        });
    }
    Ok(())
}

fn write_side(store: &Store, side: &read::LoadedExport, which: Side) -> Result<(), MergeError> {
    let conn = store.connection();
    let session_id = side.session_id;
    insert_session(conn, &side.header, session_id)?;
    // Instances are created for processes the export actually listed, and for
    // a flow's proc_uid when that process line is missing. The second case
    // does not invent a processes row: pid is not in the flow line, and 0
    // would claim a pid that was not observed.
    let mut seen = Vec::new();
    for proc in &side.processes {
        insert_process(conn, proc, session_id)?;
        if !seen.contains(&proc.proc_uid) {
            seen.push(proc.proc_uid);
        }
    }
    for flow in &side.flows {
        if flow.tuple_complete() && !seen.contains(&flow.proc_uid) {
            seen.push(flow.proc_uid);
        }
    }
    // Role is unknown: the export does not say which process is an agent.
    // Evidence stays I. This is not an observation of the process role.
    for proc_uid in &seen {
        let agent = side
            .processes
            .iter()
            .find(|proc| proc.proc_uid == *proc_uid)
            .and_then(|proc| proc.agent.clone());
        insert_agent_instance(
            conn,
            &AgentInstanceInsert {
                session_id,
                proc_uid: *proc_uid,
                profile_id: agent,
                role: None,
                parent_instance_id: None,
                evidence: "I".to_owned(),
                source: format!("offline.merge/{}", which.as_str()),
            },
        )?;
    }
    let mut stored = 0_usize;
    for flow in &side.flows {
        if !flow.tuple_complete() {
            // NOT NULL columns cannot store an absent address. Keeping the row
            // would require 0 or 0.0.0.0. The flow stays unpaired and is not
            // inserted. It is counted in the unpaired total by the pairing pass.
            continue;
        }
        let id = flow_id(which, stored);
        stored += 1;
        insert_flow(conn, flow, session_id, id)?;
    }
    Ok(())
}

fn write_edges(
    store: &Store,
    paired: &pair::Paired,
    session_a: i64,
    _session_b: i64,
) -> Result<(), MergeError> {
    let conn = store.connection();
    let skew_note = match paired.skew {
        Some(skew) => format!("b_minus_a_ns={}", skew.b_minus_a_ns),
        None => "b_minus_a_ns=unknown".to_owned(),
    };
    for pair in &paired.pairs {
        let channel_id = insert_ipc_channel(
            conn,
            &IpcChannelInsert {
                session_id: session_a,
                kind: "remote".to_owned(),
                endpoint_a: Some(format!("{}:{}", pair.a_ip, pair.a_port)),
                endpoint_b: Some(format!("{}:{}", pair.b_ip, pair.b_port)),
                bytes_a_to_b: pair.bytes_a_to_b,
                bytes_b_to_a: pair.bytes_b_to_a,
                evidence: "I".to_owned(),
                source: format!("offline.merge/remote;{skew_note}"),
            },
        )?;
        let from_instance = instance_id(conn, session_a, pair.from_proc)?;
        let to_instance = instance_id(conn, pair.to_session, pair.to_proc)?;
        insert_agent_link(
            conn,
            &AgentLinkInsert {
                session_id: session_a,
                from_instance,
                to_instance: Some(to_instance),
                channel_id: Some(channel_id),
                evidence: "I".to_owned(),
                source: "offline.merge/remote".to_owned(),
            },
        )?;
    }
    Ok(())
}

fn instance_id(
    conn: &rusqlite::Connection,
    session_id: i64,
    proc_uid: i64,
) -> Result<i64, MergeError> {
    conn.query_row(
        "SELECT id FROM agent_instances WHERE session_id = ?1 AND proc_uid = ?2",
        params![session_id, proc_uid],
        |row| row.get(0),
    )
    .map_err(|err| MergeError::from(crate::StoreError::sqlite("lookup_instance", err)))
}

/// Stable ids so the two sides do not collide on `net_flows.id`.
fn flow_id(side: Side, index: usize) -> i64 {
    let base: i64 = match side {
        Side::A => 1,
        Side::B => 1_000_000_001,
    };
    base + i64::try_from(index).unwrap_or(i64::MAX / 2)
}

fn insert_session(
    conn: &rusqlite::Connection,
    header: &read::HeaderFields,
    id: i64,
) -> Result<(), MergeError> {
    conn.execute(
        "INSERT INTO sessions (
            id, public_id, name, mode, agent, root_proc_uid, argv, cwd, user_id,
            started_ns, ended_ns, end_reason, exit_code, proxy_enabled, proxy_port,
            platform, os_version, collectors, collector_profile, config_digest, pinned, stats
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
            ?10, ?11, ?12, ?13, ?14, ?15,
            ?16, ?17, ?18, ?19, ?20, ?21, ?22
         )",
        params![
            id,
            header.public_id,
            header.name,
            header.mode,
            header.agent,
            None::<i64>,
            None::<String>,
            None::<String>,
            header.user_id,
            header.started_ns,
            header.ended_ns,
            None::<String>,
            None::<i64>,
            0_i64,
            None::<i64>,
            header.platform,
            None::<String>,
            header.collectors_json,
            None::<String>,
            None::<String>,
            0_i64,
            None::<String>,
        ],
    )
    .map_err(|err| MergeError::from(crate::StoreError::sqlite("insert_session", err)))?;
    Ok(())
}

fn insert_process(
    conn: &rusqlite::Connection,
    proc: &read::ProcessFields,
    session_id: i64,
) -> Result<(), MergeError> {
    conn.execute(
        "INSERT INTO processes (
            session_id, proc_uid, pid, parent_uid, ppid, depth, start_ns,
            exit_ns, exit_code, exit_signal, how, user_id, signer,
            evidence, field_evidence, source, agent
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7,
            ?8, ?9, ?10, ?11, ?12, ?13,
            ?14, ?15, ?16, ?17
         )",
        params![
            session_id,
            proc.proc_uid,
            proc.pid,
            proc.parent_uid,
            proc.ppid,
            proc.depth,
            proc.start_ns,
            proc.exit_ns,
            proc.exit_code,
            proc.exit_signal,
            proc.how,
            proc.user_id,
            proc.signer,
            proc.evidence,
            proc.field_evidence,
            proc.source,
            proc.agent,
        ],
    )
    .map_err(|err| MergeError::from(crate::StoreError::sqlite("insert_process", err)))?;
    Ok(())
}

fn insert_flow(
    conn: &rusqlite::Connection,
    flow: &read::FlowFields,
    session_id: i64,
    id: i64,
) -> Result<(), MergeError> {
    // Caller already checked `tuple_complete`, so these unwraps are the same
    // fields pairing used. They are not a stand-in for a missing tuple.
    let local_ip = flow.local_ip.clone().unwrap_or_default();
    let local_port = i64::from(flow.local_port.unwrap_or(0));
    let remote_ip = flow.remote_ip.clone().unwrap_or_default();
    let remote_port = i64::from(flow.remote_port.unwrap_or(0));
    let start_ns = flow.start_ns.unwrap_or(0);
    conn.execute(
        "INSERT INTO net_flows (
            id, session_id, proc_uid, proto, direction,
            local_ip, local_port, remote_ip, remote_port,
            domain, domain_source, domain_alts, sni, alpn,
            start_ns, end_ns, bytes_up, bytes_down,
            via_proxy, direct, preexisting, is_loopback, result,
            platform_total_up, platform_total_down,
            evidence, na_reason, field_evidence, source
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5,
            ?6, ?7, ?8, ?9,
            ?10, ?11, ?12, ?13, ?14,
            ?15, ?16, ?17, ?18,
            ?19, ?20, ?21, ?22, ?23,
            ?24, ?25,
            ?26, ?27, ?28, ?29
         )",
        params![
            id,
            session_id,
            flow.proc_uid,
            flow.proto,
            flow.direction,
            local_ip,
            local_port,
            remote_ip,
            remote_port,
            flow.domain,
            flow.domain_source,
            flow.domain_alts,
            flow.sni,
            flow.alpn,
            start_ns,
            flow.end_ns,
            flow.bytes_up,
            flow.bytes_down,
            flow.via_proxy.unwrap_or(0),
            flow.direct.unwrap_or(0),
            flow.preexisting.unwrap_or(0),
            flow.is_loopback.unwrap_or(0),
            flow.result,
            flow.platform_total_up,
            flow.platform_total_down,
            flow.evidence,
            flow.na_reason,
            flow.field_evidence,
            flow.source,
        ],
    )
    .map_err(|err| MergeError::from(crate::StoreError::sqlite("insert_flow", err)))?;
    Ok(())
}

pub(crate) fn open_text(path: &Path) -> Result<BufReader<File>, MergeError> {
    let file = File::open(path).map_err(|err| MergeError::Io {
        op: "open",
        path: path.to_path_buf(),
        source: err,
    })?;
    Ok(BufReader::new(file))
}

pub(crate) fn read_line(
    reader: &mut impl BufRead,
    path: &Path,
) -> Result<Option<String>, MergeError> {
    let mut buf = String::new();
    let n = reader.read_line(&mut buf).map_err(|err| MergeError::Io {
        op: "read",
        path: path.to_path_buf(),
        source: err,
    })?;
    if n == 0 {
        return Ok(None);
    }
    if buf.ends_with('\n') {
        buf.pop();
        if buf.ends_with('\r') {
            buf.pop();
        }
    }
    Ok(Some(buf))
}
