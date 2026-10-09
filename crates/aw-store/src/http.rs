//! `http` rows: one request's already-redacted metadata.
//!
//! storage.md §3. The body is not a column. Byte counts are `Option`: `None`
//! stays NULL and is not written as `0`. `url` is required by the DDL and is
//! whatever the caller stored; this module does not redact it and does not log it.
//!
//! When `fts_text` exists (migration 0005), the URL is indexed with
//! `src = 'http'`. 0005 reserved that source and installed no trigger, so the
//! insert happens here. A database that has not applied 0005 yet still stores
//! the row; the index is skipped.

use rusqlite::{params, Connection};

use crate::error::StoreError;
use crate::fts::{self, FtsSource};

/// One `http` row. Not `Debug`: `url` and the header JSON are sensitive.
#[derive(Clone)]
pub struct HttpRow {
    /// Caller-assigned id. `None` lets SQLite allocate one.
    pub id: Option<i64>,
    /// Owning session.
    pub session_id: i64,
    /// `ProcUid` bit-cast to `i64`, or unknown.
    pub proc_uid: Option<i64>,
    /// `net_flows.id` this request was attributed to, or unknown.
    pub flow_id: Option<i64>,
    /// Request time, Unix nanoseconds.
    pub ts_ns: i64,
    /// HTTP method. Required by the DDL. A tunnel with no request line is `-`,
    /// not `""`.
    pub method: String,
    /// Redacted URL. Required by the DDL (`NOT NULL`), so this is `String` and
    /// not `Option`. A flow whose URL is `NA` is not inserted: `""` would claim
    /// an empty URL was observed. The reason stays on `net_flows.field_evidence`.
    /// Not logged.
    pub url: String,
    /// Host header or URL host. Required. Not `""`.
    pub host: String,
    /// `HTTP/1.1` / `HTTP/2`, or unknown.
    pub http_version: Option<String>,
    /// Response status, or unknown (the response was not observed).
    pub status: Option<i64>,
    /// Redacted request-header JSON, or NULL when none were kept.
    pub req_headers: Option<String>,
    /// Redacted response-header JSON, or NULL.
    pub resp_headers: Option<String>,
    /// Request body length. `None` stays NULL, not 0.
    pub req_body_bytes: Option<i64>,
    /// Response body length. `None` stays NULL, not 0.
    pub resp_body_bytes: Option<i64>,
    /// `Content-Type`, or unknown.
    pub content_type: Option<String>,
    /// Round-trip time in milliseconds, or unknown.
    pub duration_ms: Option<i64>,
    /// `cert_pinned` / `upstream_tls` / ..., or no error.
    pub error: Option<String>,
    /// `E1|E2|E3|S|I|NA`.
    pub evidence: String,
    /// JSON field evidence. `None` inserts NULL. An empty string is not written:
    /// "no extra field evidence" is NULL, not `""`.
    ///
    /// Direct and QUIC flows have no URL column they can leave empty (`url` is
    /// `NOT NULL`). `NA(direct_bypass_proxy)` / `NA(quic)` lives here under `url`.
    pub field_evidence: Option<String>,
    /// Why the row is `NA`, when `evidence` is `NA`. `None` inserts NULL.
    /// Not `""`, and not `0`.
    pub na_reason: Option<String>,
    /// Collector source string.
    pub source: String,
}

/// Insert one `http` row and, when the FTS table exists, its URL.
///
/// The FTS flag is `schema_meta.storage.fts`, read here. Absent means on.
/// An empty `url` is rejected: the column is `NOT NULL`, and `""` is not an NA
/// reason. `field_evidence` and `na_reason` bind as NULL when the caller passes
/// `None`. A database without `fts_text` (0005 not applied) stores the row and
/// skips the index.
pub fn insert_http(conn: &Connection, row: &HttpRow) -> Result<(), StoreError> {
    // `url` / `host` are `NOT NULL`. An empty string is not an NA reason; the
    // reason belongs in `na_reason` / `field_evidence`, and a row with no URL
    // should not be built. Reject it rather than store `""`.
    if row.url.is_empty() || row.host.is_empty() {
        return Err(StoreError::sqlite(
            "insert_http",
            rusqlite::Error::InvalidParameterName(
                "url is empty; an absent URL is not stored as \"\"".into(),
            ),
        ));
    }
    conn.execute(
        "INSERT INTO http (
            id, session_id, proc_uid, flow_id, ts_ns, method, url, host,
            http_version, status, req_headers, resp_headers,
            req_body_bytes, resp_body_bytes, content_type, duration_ms, error,
            evidence, field_evidence, na_reason, source
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8,
            ?9, ?10, ?11, ?12,
            ?13, ?14, ?15, ?16, ?17,
            ?18, ?19, ?20, ?21
         )",
        params![
            row.id,
            row.session_id,
            row.proc_uid,
            row.flow_id,
            row.ts_ns,
            row.method,
            row.url,
            row.host,
            row.http_version,
            row.status,
            row.req_headers,
            row.resp_headers,
            row.req_body_bytes,
            row.resp_body_bytes,
            row.content_type,
            row.duration_ms,
            row.error,
            row.evidence,
            row.field_evidence,
            row.na_reason,
            row.source,
        ],
    )
    .map_err(|err| StoreError::sqlite("insert_http", err))?;
    if fts_text_present(conn)? {
        let src_id = match row.id {
            Some(id) => id,
            None => conn.last_insert_rowid(),
        };
        let text = Some(row.url.as_str());
        let fts = fts::read_mode(conn)?;
        fts::upsert(conn, fts, FtsSource::Http, src_id, text)?;
    }
    Ok(())
}

fn fts_text_present(conn: &Connection) -> Result<bool, StoreError> {
    let found: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'fts_text'",
            [],
            |row| row.get(0),
        )
        .map_err(|err| StoreError::sqlite("probe_fts_text", err))?;
    Ok(found > 0)
}
