//! [`RecordSink`]: one transaction per batch of already-aggregated rows.
//!
//! P1-PIPE-05 should depend on this trait. It must not declare a second one.
//! `aw-pipeline` cannot depend on `rusqlite`; the trait and the row types live
//! here, and only [`SqliteSink`] touches SQL.
//!
//! Unknown values are [`Option::None`] and bind as NULL. They are not stored as
//! `0` or `""`. `net_flow_buckets.bytes_up` / `bytes_down` are the exception the
//! DDL itself makes: `INTEGER NOT NULL DEFAULT 0`, because those columns are
//! accumulators. A missing flow byte count stays NULL and is not added in as zero.
//!
//! `net_flows` has no natural UNIQUE beyond `id`. The UPSERT is `ON CONFLICT(id)`.
//! Callers pass the flow id. This crate does not invent a 5-tuple unique key.
//!
//! Rows are not `Debug`: `sessions.argv` and `process_images.argv` / `env` are
//! sensitive. Do not print them.

use rusqlite::{params, Connection, Transaction, TransactionBehavior};

use crate::error::StoreError;
use crate::file_access::{self, FileAccessRow};
use crate::fts::{self, FtsMode, FtsSource};
use crate::migrate::{self, Store};
use crate::retention::WriteMode;

/// Accepts one batch and commits it, or rolls it back.
///
/// P1-PIPE-05 owns retry and gap reporting. This trait only returns the error.
pub trait RecordSink {
    /// Write `batch` in one `BEGIN IMMEDIATE` transaction.
    ///
    /// Order inside the transaction: `sessions`, `processes`, `process_images`,
    /// `file_access`, `net_flows`, `net_flow_buckets`, `dns`, `gaps`. Processes
    /// are written before flows and file rows. A failure rolls the whole batch back.
    fn write_batch(&mut self, batch: &WriteBatch) -> Result<(), StoreError>;
}

/// Rows for one commit. Empty vectors are skipped. Nothing is dropped silently:
/// a constraint failure fails the batch.
#[derive(Clone, Default)]
pub struct WriteBatch {
    /// Session rows. Must exist before processes that reference them.
    pub sessions: Vec<SessionRow>,
    /// Process rows. Written before `net_flows` in the same batch.
    pub processes: Vec<ProcessRow>,
    /// Exec images. `proc_uid` is not a foreign key.
    pub process_images: Vec<ProcessImageRow>,
    /// Aggregated file accesses. `id` is the UPSERT key shared by a partial
    /// snapshot and its final row.
    pub file_access: Vec<FileAccessRow>,
    /// Flows. `id` is the UPSERT key.
    pub net_flows: Vec<NetFlowRow>,
    /// Per-bucket byte accumulators.
    pub net_flow_buckets: Vec<NetFlowBucketRow>,
    /// DNS queries. `proc_uid` may be NULL.
    pub dns: Vec<DnsRow>,
    /// Observation gaps. `session_id` may be NULL for a global gap.
    pub gaps: Vec<GapRow>,
}

/// One `sessions` row. `argv` is already redacted JSON, or `None` when unknown.
#[derive(Clone)]
pub struct SessionRow {
    /// `sessions.id`.
    pub id: i64,
    /// Public id used by the CLI. Not a hostname.
    pub public_id: String,
    /// User-edited label, or unknown.
    pub name: Option<String>,
    /// `launch` or `attach`.
    pub mode: String,
    /// Agent profile id, or unknown.
    pub agent: Option<String>,
    /// Root process, stored as a signed integer bit-cast of `ProcUid`.
    pub root_proc_uid: Option<i64>,
    /// Redacted argv JSON. `None` is unknown, not an empty command.
    pub argv: Option<String>,
    /// Working directory, or unknown.
    pub cwd: Option<String>,
    /// OS user id of the person who started the session. Required by the DDL.
    pub user_id: String,
    /// Wall-clock start, Unix nanoseconds.
    pub started_ns: i64,
    /// Wall-clock end, or still running.
    pub ended_ns: Option<i64>,
    /// `exited` / `stopped` / `daemon_shutdown` / `crashed`, or unknown.
    pub end_reason: Option<String>,
    /// Process exit code, or unknown.
    pub exit_code: Option<i64>,
    /// `1` when the explicit proxy was enabled.
    pub proxy_enabled: i64,
    /// Proxy listen port, or unknown.
    pub proxy_port: Option<i64>,
    /// `linux` / `windows` / `macos`.
    pub platform: String,
    /// OS version string, or unknown.
    pub os_version: Option<String>,
    /// JSON array of collectors. Required by the DDL.
    pub collectors: String,
    /// Collector profile name, or unknown.
    pub collector_profile: Option<String>,
    /// Config digest, or unknown.
    pub config_digest: Option<String>,
    /// `1` when the session is excluded from automatic retention.
    pub pinned: i64,
    /// JSON stats cache, or unknown.
    pub stats: Option<String>,
}

/// One `processes` row. `depth` is required by the DDL; pass `None` only if you
/// intend the documented default `0` (distance from the root). Do not use `0`
/// for a depth you failed to observe — store that in `field_evidence` instead
/// and still pass the integer the DDL requires, or skip the row and surface a gap
/// at the pipeline layer.
#[derive(Clone)]
pub struct ProcessRow {
    /// Owning session.
    pub session_id: i64,
    /// `ProcUid` bit-cast to `i64`.
    pub proc_uid: i64,
    /// OS pid.
    pub pid: i64,
    /// Parent `ProcUid`, or unknown.
    pub parent_uid: Option<i64>,
    /// Parent pid, or unknown.
    pub ppid: Option<i64>,
    /// Distance from the session root. DDL says `NOT NULL`; this is that integer.
    pub depth: i64,
    /// Wall-clock start, Unix nanoseconds.
    pub start_ns: i64,
    /// Wall-clock exit, or still running.
    pub exit_ns: Option<i64>,
    /// Exit code, or unknown.
    pub exit_code: Option<i64>,
    /// Exit signal, or unknown.
    pub exit_signal: Option<i64>,
    /// `fork` / `exec` / `spawn` / `snapshot` / `unknown`.
    pub how: String,
    /// OS user of the process, or unknown.
    pub user_id: Option<String>,
    /// Signer identity, or unknown.
    pub signer: Option<String>,
    /// `E1|E2|E3|S|I|NA`.
    pub evidence: String,
    /// JSON field evidence, or NULL when empty.
    pub field_evidence: Option<String>,
    /// Collector source string.
    pub source: String,
    /// Recognized agent id, or unknown.
    pub agent: Option<String>,
}

/// One `process_images` row.
#[derive(Clone)]
pub struct ProcessImageRow {
    /// Row id. `None` lets SQLite assign one.
    pub id: Option<i64>,
    /// Owning session.
    pub session_id: i64,
    /// `ProcUid` bit-cast to `i64`. Not a foreign key.
    pub proc_uid: i64,
    /// Image sequence, starting at 0.
    pub seq: i64,
    /// Wall-clock time, Unix nanoseconds.
    pub ts_ns: i64,
    /// Executable path, or unknown.
    pub exe: Option<String>,
    /// Redacted argv JSON, or unknown. Never an empty string standing in for unknown.
    pub argv: Option<String>,
    /// Working directory, or unknown.
    pub cwd: Option<String>,
    /// Redacted env JSON, or unknown.
    pub env: Option<String>,
    /// `E1|E2|E3|S|I|NA`.
    pub evidence: String,
    /// JSON field evidence, or NULL when empty.
    pub field_evidence: Option<String>,
    /// Collector source string.
    pub source: String,
}

/// One `net_flows` row. Byte columns stay NULL when the count was not observed.
#[derive(Clone)]
pub struct NetFlowRow {
    /// UPSERT key.
    pub id: i64,
    /// Owning session.
    pub session_id: i64,
    /// `ProcUid` bit-cast to `i64`. Not a foreign key.
    pub proc_uid: i64,
    /// `tcp` or `udp`.
    pub proto: String,
    /// `outbound` / `inbound` / `unknown`.
    pub direction: String,
    /// Local address.
    pub local_ip: String,
    /// Local port.
    pub local_port: i64,
    /// Remote address.
    pub remote_ip: String,
    /// Remote port.
    pub remote_port: i64,
    /// Best domain, or unknown.
    pub domain: Option<String>,
    /// How `domain` was chosen, or unknown.
    pub domain_source: Option<String>,
    /// JSON array of other candidates, or unknown.
    pub domain_alts: Option<String>,
    /// TLS SNI, or unknown.
    pub sni: Option<String>,
    /// ALPN, or unknown.
    pub alpn: Option<String>,
    /// Wall-clock start, Unix nanoseconds.
    pub start_ns: i64,
    /// Wall-clock end, or still open.
    pub end_ns: Option<i64>,
    /// Bytes sent. `None` stays NULL and is not treated as zero.
    pub bytes_up: Option<i64>,
    /// Bytes received. `None` stays NULL and is not treated as zero.
    pub bytes_down: Option<i64>,
    /// `1` when the flow went through the explicit proxy.
    pub via_proxy: i64,
    /// `1` when a proxied session bypassed the proxy.
    pub direct: i64,
    /// `1` when the flow already existed at attach.
    pub preexisting: i64,
    /// `1` when the remote address is loopback.
    pub is_loopback: i64,
    /// Close result, or unknown.
    pub result: Option<i64>,
    /// Platform cumulative bytes up, or unknown.
    pub platform_total_up: Option<i64>,
    /// Platform cumulative bytes down, or unknown.
    pub platform_total_down: Option<i64>,
    /// `E1|E2|E3|S|I|NA`.
    pub evidence: String,
    /// Why the record is `NA`, or NULL.
    pub na_reason: Option<String>,
    /// JSON field evidence, or NULL when empty.
    pub field_evidence: Option<String>,
    /// Collector source string.
    pub source: String,
}

/// One `net_flow_buckets` row. Bytes are accumulators (`NOT NULL` in the DDL).
#[derive(Clone)]
pub struct NetFlowBucketRow {
    /// `net_flows.id`.
    pub flow_id: i64,
    /// Denormalized session id. The DDL does not declare a foreign key on it.
    pub session_id: i64,
    /// Bucket start, Unix nanoseconds, aligned by the caller.
    pub bucket_ns: i64,
    /// Bytes to add. Not an unknown sentinel.
    pub bytes_up: i64,
    /// Bytes to add. Not an unknown sentinel.
    pub bytes_down: i64,
    /// `E1|E2|E3|S|I|NA`.
    pub evidence: String,
}

/// One `dns` row.
#[derive(Clone)]
pub struct DnsRow {
    /// Row id. `None` lets SQLite assign one.
    pub id: Option<i64>,
    /// Owning session.
    pub session_id: i64,
    /// Asking process, or NULL when the resolver could not be attributed.
    pub proc_uid: Option<i64>,
    /// Wall-clock time, Unix nanoseconds.
    pub ts_ns: i64,
    /// Query name.
    pub qname: String,
    /// Query type.
    pub qtype: i64,
    /// Response code, or unknown.
    pub rcode: Option<i64>,
    /// JSON answers, or unknown.
    pub answers: Option<String>,
    /// Minimum TTL, or unknown.
    pub ttl_min: Option<i64>,
    /// Server address, or unknown.
    pub server: Option<String>,
    /// `E1|E2|E3|S|I|NA`.
    pub evidence: String,
    /// Collector source string.
    pub source: String,
}

/// One `gaps` row. `session_id` NULL means the gap is global.
#[derive(Clone)]
pub struct GapRow {
    /// Row id. `None` lets SQLite assign one.
    pub id: Option<i64>,
    /// Session, or NULL for a global gap.
    pub session_id: Option<i64>,
    /// Collector name.
    pub collector: String,
    /// Gap kind string. The store does not map it onto `aw_core::GapKind`.
    pub kind: String,
    /// JSON array of affected categories.
    pub affects: String,
    /// Gap start, Unix nanoseconds.
    pub from_ns: i64,
    /// Gap end, Unix nanoseconds.
    pub to_ns: i64,
    /// How many events were lost, or unknown.
    pub count: Option<i64>,
    /// Short detail, already redacted, or unknown.
    pub detail: Option<String>,
}

/// [`RecordSink`] backed by a [`Store`] write connection.
pub struct SqliteSink<'a> {
    store: &'a mut Store,
    /// From [`crate::Retention::apply`]. [`WriteMode::MetadataAndGapsOnly`]
    /// refuses detail rows (processes, files, flows, dns, images). Sessions
    /// and gaps are still written. The default is [`WriteMode::Normal`].
    write_mode: WriteMode,
}

impl<'a> SqliteSink<'a> {
    /// Wrap the store's write connection. The store must not be read-only.
    pub fn new(store: &'a mut Store) -> Result<Self, StoreError> {
        if store.is_read_only() {
            return Err(StoreError::ReadOnly);
        }
        Ok(Self {
            store,
            write_mode: WriteMode::Normal,
        })
    }

    /// Remember the disk-pressure mode from the last retention pass.
    ///
    /// Not persisted. A new [`SqliteSink`] starts at [`WriteMode::Normal`].
    pub fn set_write_mode(&mut self, mode: WriteMode) {
        self.write_mode = mode;
    }
}

impl RecordSink for SqliteSink<'_> {
    fn write_batch(&mut self, batch: &WriteBatch) -> Result<(), StoreError> {
        if !batch.file_access.is_empty() || image_has_argv(&batch.process_images) {
            // 0003–0005. A P1 database stays at SCHEMA_VERSION until the first
            // file row or indexed argv, which is what the P1 reopen test asserts.
            apply_file_schema(self.store)?;
        }
        let fts = if file_schema_present(self.store.connection())? {
            fts::read_mode(self.store.connection())?
        } else {
            FtsMode::Off
        };
        if self.write_mode == WriteMode::MetadataAndGapsOnly && batch_has_detail(batch) {
            // storage.md §5: below min_free_disk_bytes, keep session metadata
            // and gaps only. Detail is not silently dropped; the caller sees
            // the error and records its own gap. This crate does not invent one.
            return Err(StoreError::sqlite(
                "disk_low_detail_refused",
                rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error {
                        code: rusqlite::ErrorCode::DiskFull,
                        extended_code: 13,
                    },
                    Some("free disk is below min_free_disk_bytes; detail rows were not written".into()),
                ),
            ));
        }
        let tx = self
            .store
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|err| StoreError::sqlite("begin_batch", err))?;
        let result = write_all(&tx, batch, fts);
        match result {
            Ok(()) => tx
                .commit()
                .map_err(|err| StoreError::sqlite("commit_batch", err)),
            Err(err) => {
                drop(tx);
                Err(err)
            }
        }
    }
}

fn batch_has_detail(batch: &WriteBatch) -> bool {
    !batch.processes.is_empty()
        || !batch.process_images.is_empty()
        || !batch.file_access.is_empty()
        || !batch.net_flows.is_empty()
        || !batch.net_flow_buckets.is_empty()
        || !batch.dns.is_empty()
}

fn image_has_argv(rows: &[ProcessImageRow]) -> bool {
    rows.iter()
        .any(|row| row.argv.as_deref().is_some_and(|text| !text.is_empty()))
}

fn file_schema_present(conn: &Connection) -> Result<bool, StoreError> {
    let found: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'file_access'",
            [],
            |row| row.get(0),
        )
        .map_err(|err| StoreError::sqlite("probe_file_access", err))?;
    Ok(found > 0)
}

/// Apply migrations 0003, 0004, and 0005 if `file_access` is not there yet.
///
/// Uses [`Store::open_with_scripts`] on a second connection only when the
/// table is missing. The caller's connection is the one that migrates: the
/// scripts are the same strings, executed here so the open file does not have
/// to be closed and reopened under the sink.
pub fn apply_file_schema(store: &mut Store) -> Result<(), StoreError> {
    if store.is_read_only() {
        return Err(StoreError::ReadOnly);
    }
    if file_schema_present(store.connection())? {
        return Ok(());
    }
    let conn = store.connection();
    let tx = conn
        .unchecked_transaction()
        .map_err(|err| StoreError::sqlite("begin_file_schema", err))?;
    let applied = (|| {
        for (version, sql) in migrate::file_schema_scripts() {
            tx.execute_batch(sql)
                .map_err(|err| StoreError::sqlite("migrate_file_schema", err))?;
            tx.execute(
                "INSERT INTO schema_meta (key, value) VALUES ('schema_version', ?1)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![version.to_string()],
            )
            .map_err(|err| StoreError::sqlite("migrate_file_schema_version", err))?;
        }
        Ok::<(), StoreError>(())
    })();
    match applied {
        Ok(()) => tx
            .commit()
            .map_err(|err| StoreError::sqlite("commit_file_schema", err)),
        Err(err) => {
            drop(tx);
            Err(err)
        }
    }
}

fn write_all(tx: &Transaction<'_>, batch: &WriteBatch, fts: FtsMode) -> Result<(), StoreError> {
    write_sessions(tx, &batch.sessions)?;
    write_processes(tx, &batch.processes)?;
    write_images(tx, &batch.process_images, fts)?;
    file_access::write_rows(tx, &batch.file_access, fts)?;
    write_flows(tx, &batch.net_flows)?;
    write_buckets(tx, &batch.net_flow_buckets)?;
    write_dns(tx, &batch.dns)?;
    write_gaps(tx, &batch.gaps)?;
    Ok(())
}

fn write_sessions(tx: &Transaction<'_>, rows: &[SessionRow]) -> Result<(), StoreError> {
    if rows.is_empty() {
        return Ok(());
    }
    let mut stmt = tx
        .prepare_cached(
            "INSERT INTO sessions (
                id, public_id, name, mode, agent, root_proc_uid, argv, cwd, user_id,
                started_ns, ended_ns, end_reason, exit_code, proxy_enabled, proxy_port,
                platform, os_version, collectors, collector_profile, config_digest, pinned, stats
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
                ?10, ?11, ?12, ?13, ?14, ?15,
                ?16, ?17, ?18, ?19, ?20, ?21, ?22
             )",
        )
        .map_err(|err| StoreError::sqlite("prepare_sessions", err))?;
    for row in rows {
        stmt.execute(params![
            row.id,
            row.public_id,
            row.name,
            row.mode,
            row.agent,
            row.root_proc_uid,
            row.argv,
            row.cwd,
            row.user_id,
            row.started_ns,
            row.ended_ns,
            row.end_reason,
            row.exit_code,
            row.proxy_enabled,
            row.proxy_port,
            row.platform,
            row.os_version,
            row.collectors,
            row.collector_profile,
            row.config_digest,
            row.pinned,
            row.stats,
        ])
        .map_err(|err| StoreError::sqlite("insert_session", err))?;
    }
    Ok(())
}

fn write_processes(tx: &Transaction<'_>, rows: &[ProcessRow]) -> Result<(), StoreError> {
    if rows.is_empty() {
        return Ok(());
    }
    let mut stmt = tx
        .prepare_cached(
            "INSERT INTO processes (
                session_id, proc_uid, pid, parent_uid, ppid, depth, start_ns,
                exit_ns, exit_code, exit_signal, how, user_id, signer,
                evidence, field_evidence, source, agent
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7,
                ?8, ?9, ?10, ?11, ?12, ?13,
                ?14, ?15, ?16, ?17
             )",
        )
        .map_err(|err| StoreError::sqlite("prepare_processes", err))?;
    for row in rows {
        stmt.execute(params![
            row.session_id,
            row.proc_uid,
            row.pid,
            row.parent_uid,
            row.ppid,
            row.depth,
            row.start_ns,
            row.exit_ns,
            row.exit_code,
            row.exit_signal,
            row.how,
            row.user_id,
            row.signer,
            row.evidence,
            row.field_evidence,
            row.source,
            row.agent,
        ])
        .map_err(|err| StoreError::sqlite("insert_process", err))?;
    }
    Ok(())
}

fn write_images(
    tx: &Transaction<'_>,
    rows: &[ProcessImageRow],
    fts: FtsMode,
) -> Result<(), StoreError> {
    if rows.is_empty() {
        return Ok(());
    }
    let mut stmt = tx
        .prepare_cached(
            "INSERT INTO process_images (
                id, session_id, proc_uid, seq, ts_ns, exe, argv, cwd, env,
                evidence, field_evidence, source
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
                ?10, ?11, ?12
             )",
        )
        .map_err(|err| StoreError::sqlite("prepare_images", err))?;
    for row in rows {
        stmt.execute(params![
            row.id,
            row.session_id,
            row.proc_uid,
            row.seq,
            row.ts_ns,
            row.exe,
            row.argv,
            row.cwd,
            row.env,
            row.evidence,
            row.field_evidence,
            row.source,
        ])
        .map_err(|err| StoreError::sqlite("insert_image", err))?;
        if let Some(id) = row.id {
            // argv is already redacted. An unknown argv is not indexed as "".
            if file_schema_present(tx)? {
                fts::upsert(tx, fts, FtsSource::ProcessImage, id, row.argv.as_deref())?;
            }
        }
    }
    Ok(())
}

/// NULL stays NULL. A later observation fills it. Two known counts add.
const ADD_NULLABLE: &str = r#"CASE
    WHEN excluded.{col} IS NULL THEN {table}.{col}
    WHEN {table}.{col} IS NULL THEN excluded.{col}
    ELSE {table}.{col} + excluded.{col} END"#;

fn write_flows(tx: &Transaction<'_>, rows: &[NetFlowRow]) -> Result<(), StoreError> {
    if rows.is_empty() {
        return Ok(());
    }
    let bytes_up = ADD_NULLABLE
        .replace("{col}", "bytes_up")
        .replace("{table}", "net_flows");
    let bytes_down = ADD_NULLABLE
        .replace("{col}", "bytes_down")
        .replace("{table}", "net_flows");
    let sql = format!(
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
         )
         ON CONFLICT(id) DO UPDATE SET
            end_ns = COALESCE(excluded.end_ns, net_flows.end_ns),
            bytes_up = {bytes_up},
            bytes_down = {bytes_down},
            domain = COALESCE(net_flows.domain, excluded.domain),
            domain_source = COALESCE(net_flows.domain_source, excluded.domain_source),
            sni = COALESCE(net_flows.sni, excluded.sni),
            alpn = COALESCE(net_flows.alpn, excluded.alpn),
            result = COALESCE(excluded.result, net_flows.result),
            platform_total_up = COALESCE(excluded.platform_total_up, net_flows.platform_total_up),
            platform_total_down = COALESCE(excluded.platform_total_down, net_flows.platform_total_down)"
    );
    let mut stmt = tx
        .prepare_cached(&sql)
        .map_err(|err| StoreError::sqlite("prepare_flows", err))?;
    for row in rows {
        stmt.execute(params![
            row.id,
            row.session_id,
            row.proc_uid,
            row.proto,
            row.direction,
            row.local_ip,
            row.local_port,
            row.remote_ip,
            row.remote_port,
            row.domain,
            row.domain_source,
            row.domain_alts,
            row.sni,
            row.alpn,
            row.start_ns,
            row.end_ns,
            row.bytes_up,
            row.bytes_down,
            row.via_proxy,
            row.direct,
            row.preexisting,
            row.is_loopback,
            row.result,
            row.platform_total_up,
            row.platform_total_down,
            row.evidence,
            row.na_reason,
            row.field_evidence,
            row.source,
        ])
        .map_err(|err| StoreError::sqlite("upsert_flow", err))?;
    }
    Ok(())
}

fn write_buckets(tx: &Transaction<'_>, rows: &[NetFlowBucketRow]) -> Result<(), StoreError> {
    if rows.is_empty() {
        return Ok(());
    }
    let mut stmt = tx
        .prepare_cached(
            "INSERT INTO net_flow_buckets (
                flow_id, session_id, bucket_ns, bytes_up, bytes_down, evidence
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(flow_id, bucket_ns) DO UPDATE SET
                bytes_up = net_flow_buckets.bytes_up + excluded.bytes_up,
                bytes_down = net_flow_buckets.bytes_down + excluded.bytes_down",
        )
        .map_err(|err| StoreError::sqlite("prepare_buckets", err))?;
    for row in rows {
        stmt.execute(params![
            row.flow_id,
            row.session_id,
            row.bucket_ns,
            row.bytes_up,
            row.bytes_down,
            row.evidence,
        ])
        .map_err(|err| StoreError::sqlite("upsert_bucket", err))?;
    }
    Ok(())
}

fn write_dns(tx: &Transaction<'_>, rows: &[DnsRow]) -> Result<(), StoreError> {
    if rows.is_empty() {
        return Ok(());
    }
    let mut stmt = tx
        .prepare_cached(
            "INSERT INTO dns (
                id, session_id, proc_uid, ts_ns, qname, qtype, rcode,
                answers, ttl_min, server, evidence, source
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7,
                ?8, ?9, ?10, ?11, ?12
             )",
        )
        .map_err(|err| StoreError::sqlite("prepare_dns", err))?;
    for row in rows {
        stmt.execute(params![
            row.id,
            row.session_id,
            row.proc_uid,
            row.ts_ns,
            row.qname,
            row.qtype,
            row.rcode,
            row.answers,
            row.ttl_min,
            row.server,
            row.evidence,
            row.source,
        ])
        .map_err(|err| StoreError::sqlite("insert_dns", err))?;
    }
    Ok(())
}

fn write_gaps(tx: &Transaction<'_>, rows: &[GapRow]) -> Result<(), StoreError> {
    if rows.is_empty() {
        return Ok(());
    }
    let mut stmt = tx
        .prepare_cached(
            "INSERT INTO gaps (
                id, session_id, collector, kind, affects, from_ns, to_ns, count, detail
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        )
        .map_err(|err| StoreError::sqlite("prepare_gaps", err))?;
    for row in rows {
        stmt.execute(params![
            row.id,
            row.session_id,
            row.collector,
            row.kind,
            row.affects,
            row.from_ns,
            row.to_ns,
            row.count,
            row.detail,
        ])
        .map_err(|err| StoreError::sqlite("insert_gap", err))?;
    }
    Ok(())
}

/// Count rows in `table`. Test-only; not a query API.
#[cfg(test)]
pub(crate) fn count_rows(conn: &Connection, table: &str) -> Result<i64, StoreError> {
    // `table` is a fixed identifier from this crate, not user input.
    match table {
        "sessions" | "processes" | "process_images" | "net_flows" | "net_flow_buckets" | "dns"
        | "gaps" => {}
        _ => {
            return Err(StoreError::sqlite(
                "count_rows",
                rusqlite::Error::InvalidParameterName(table.to_string()),
            ));
        }
    }
    let sql = format!("SELECT COUNT(*) FROM {table}");
    conn.query_row(&sql, [], |row| row.get(0))
        .map_err(|err| StoreError::sqlite("count_rows", err))
}

/// `bytes_up` for one flow, distinguishing NULL from zero. Test-only.
#[cfg(test)]
pub(crate) fn flow_bytes_up(conn: &Connection, id: i64) -> Result<Option<i64>, StoreError> {
    conn.query_row(
        "SELECT bytes_up FROM net_flows WHERE id = ?1",
        params![id],
        |row| row.get(0),
    )
    .map_err(|err| StoreError::sqlite("flow_bytes", err))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::migrate::OpenStatus;

    fn temp_db(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("aw-store-sink-{label}-{nanos}.db"))
    }

    fn session(id: i64) -> SessionRow {
        SessionRow {
            id,
            public_id: format!("s{id}"),
            name: None,
            mode: "launch".to_string(),
            agent: None,
            root_proc_uid: None,
            argv: None,
            cwd: None,
            user_id: "uid".to_string(),
            started_ns: 1,
            ended_ns: None,
            end_reason: None,
            exit_code: None,
            proxy_enabled: 0,
            proxy_port: None,
            platform: "windows".to_string(),
            os_version: None,
            collectors: "[]".to_string(),
            collector_profile: None,
            config_digest: None,
            pinned: 0,
            stats: None,
        }
    }

    fn process(session_id: i64, proc_uid: i64) -> ProcessRow {
        ProcessRow {
            session_id,
            proc_uid,
            pid: 10,
            parent_uid: None,
            ppid: None,
            depth: 0,
            start_ns: 1,
            exit_ns: None,
            exit_code: None,
            exit_signal: None,
            how: "spawn".to_string(),
            user_id: None,
            signer: None,
            evidence: "E1".to_string(),
            field_evidence: None,
            source: "test".to_string(),
            agent: None,
        }
    }

    fn flow(id: i64, session_id: i64, proc_uid: i64, bytes_up: Option<i64>) -> NetFlowRow {
        NetFlowRow {
            id,
            session_id,
            proc_uid,
            proto: "tcp".to_string(),
            direction: "outbound".to_string(),
            local_ip: "127.0.0.1".to_string(),
            local_port: 1,
            remote_ip: "127.0.0.1".to_string(),
            remote_port: 9,
            domain: None,
            domain_source: None,
            domain_alts: None,
            sni: None,
            alpn: None,
            start_ns: 2,
            end_ns: None,
            bytes_up,
            bytes_down: None,
            via_proxy: 0,
            direct: 0,
            preexisting: 0,
            is_loopback: 1,
            result: None,
            platform_total_up: None,
            platform_total_down: None,
            evidence: "E1".to_string(),
            na_reason: None,
            field_evidence: None,
            source: "test".to_string(),
        }
    }

    #[test]
    fn batch_writes_processes_before_flows_and_upserts_bytes() {
        let path = temp_db("ok");
        let _ = std::fs::remove_file(&path);
        let mut store = Store::open(&path).expect("open");
        assert!(matches!(store.status(), OpenStatus::Created));
        {
            let mut sink = SqliteSink::new(&mut store).expect("sink");
            let mut batch = WriteBatch::default();
            batch.sessions.push(session(1));
            batch.processes.push(process(1, 7));
            batch.net_flows.push(flow(3, 1, 7, None));
            sink.write_batch(&batch).expect("first");
        }
        assert_eq!(
            flow_bytes_up(store.connection(), 3).expect("null bytes"),
            None,
            "unknown bytes_up stays NULL"
        );
        {
            let mut sink = SqliteSink::new(&mut store).expect("sink");
            let mut again = WriteBatch::default();
            again.net_flows.push(flow(3, 1, 7, Some(10)));
            again.net_flow_buckets.push(NetFlowBucketRow {
                flow_id: 3,
                session_id: 1,
                bucket_ns: 0,
                bytes_up: 4,
                bytes_down: 1,
                evidence: "E1".to_string(),
            });
            sink.write_batch(&again).expect("second");
            again.net_flow_buckets[0].bytes_up = 6;
            again.net_flows[0].bytes_up = Some(5);
            sink.write_batch(&again).expect("third");
        }
        let conn = store.connection();
        assert_eq!(count_rows(conn, "processes").expect("pc"), 1);
        assert_eq!(flow_bytes_up(conn, 3).expect("bytes"), Some(15));
        let down: Option<i64> = conn
            .query_row("SELECT bytes_down FROM net_flows WHERE id = 3", [], |row| {
                row.get(0)
            })
            .expect("down");
        assert_eq!(down, None, "unknown bytes_down stays NULL");
        let bucket: i64 = conn
            .query_row(
                "SELECT bytes_up FROM net_flow_buckets WHERE flow_id = 3 AND bucket_ns = 0",
                [],
                |row| row.get(0),
            )
            .expect("bucket");
        assert_eq!(bucket, 10);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn failed_batch_rolls_back_row_counts() {
        let path = temp_db("fail");
        let _ = std::fs::remove_file(&path);
        let mut store = Store::open(&path).expect("open");
        {
            let mut sink = SqliteSink::new(&mut store).expect("sink");
            let mut batch = WriteBatch::default();
            batch.sessions.push(session(1));
            batch.processes.push(process(1, 7));
            sink.write_batch(&batch).expect("seed");
        }
        let before_proc = count_rows(store.connection(), "processes").expect("before");
        let before_flow = count_rows(store.connection(), "net_flows").expect("before flows");
        {
            let mut sink = SqliteSink::new(&mut store).expect("sink");
            let mut batch = WriteBatch::default();
            batch.processes.push(process(1, 8));
            // Flow references a session that is not in this batch and does not exist.
            batch.net_flows.push(flow(9, 99, 8, Some(1)));
            let err = sink.write_batch(&batch);
            assert!(err.is_err(), "fk failure must fail the batch");
        }
        assert_eq!(
            count_rows(store.connection(), "processes").expect("after"),
            before_proc,
            "process inserted before the failing flow must roll back"
        );
        assert_eq!(
            count_rows(store.connection(), "net_flows").expect("after flows"),
            before_flow
        );
        let _ = std::fs::remove_file(&path);
    }
}
