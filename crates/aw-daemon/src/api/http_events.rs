//! `GET /sessions/{sid}/http` (P3-DAEMON-01).
//!
//! `aw-store` exports [`aw_store::insert_http`] and [`aw_store::HttpRow`] but no
//! list. The SELECT below runs on [`aw_store::Store::connection`]. It does not
//! write. User text enters only as bound parameters.
//!
//! A session that exists for this user and has `proxy_enabled = 0` returns an
//! empty list plus `reason: "no_proxy"`. That is not a 404. A session another
//! user owns is 404, the same as a missing id.
//!
//! URL and header values are copied into the JSON body. They are not written to
//! a log and not formatted with `Debug`.

use std::collections::BTreeMap;

use aw_core::filter::{self, Expr as CoreExpr, Op as CoreOp, Value as CoreValue};
use aw_pipeline::wording::Lang;
use aw_store::{
    compile_predicate, redact_host_field, redact_host_text, redact_user_paths,
    session_by_public_id, CompileCtx, Store, StoreExpr, StoreField, StoreOp, StoreParam,
    StoreTarget, StoreTerm, StoreValue,
};
use rusqlite::OptionalExtension;

use super::auth::Caller;
use super::routes::{error_response, ApiResponse, ApiState};

const MAX_PAGE: i64 = 2000;

/// `GET /sessions/{sid}/http?filter=&cursor=&limit=&from=&to=&redact_paths=&redact_hosts=`.
pub(crate) fn get_http(state: &ApiState, caller: &Caller, sid: &str, query: &str) -> ApiResponse {
    let pairs = query_pairs(query);
    let limit = match page_limit(pairs.get("limit").map(String::as_str)) {
        Ok(limit) => limit,
        Err(response) => return response,
    };
    let from_ns = match optional_i64(pairs.get("from").map(String::as_str), "from") {
        Ok(v) => v,
        Err(response) => return response,
    };
    let to_ns = match optional_i64(pairs.get("to").map(String::as_str), "to") {
        Ok(v) => v,
        Err(response) => return response,
    };
    let cursor = match parse_cursor(pairs.get("cursor").map(String::as_str)) {
        Ok(v) => v,
        Err(response) => return response,
    };
    let redact_paths = flag_on(pairs.get("redact_paths").map(String::as_str));
    let redact_hosts = flag_on(pairs.get("redact_hosts").map(String::as_str));

    let Some(path) = state.query.db_path.as_deref() else {
        return error_response(404, "not_found", "session not found");
    };
    let store = match Store::open(path) {
        Ok(store) => store,
        Err(err) => return error_response(500, "store", &err.to_string()),
    };
    let conn = store.connection();
    let session_id = match resolve_session(conn, &caller.user_id, sid) {
        Ok(Some(id)) => id,
        Ok(None) => return error_response(404, "not_found", "session not found"),
        Err(message) => return error_response(500, "store", &message),
    };

    let proxy = match proxy_enabled(conn, session_id, &caller.user_id) {
        Ok(Some(on)) => on,
        Ok(None) => return error_response(404, "not_found", "session not found"),
        Err(message) => return error_response(500, "store", &message),
    };
    if !proxy {
        return json_response(
            200,
            &serde_json::json!({
                "http": [],
                "reason": "no_proxy",
                "next_cursor": null,
            }),
        );
    }

    let filter = match compile_http_filter(
        pairs.get("filter").map(String::as_str).unwrap_or(""),
        session_start_ns(conn, session_id),
    ) {
        Ok(compiled) => compiled,
        Err(response) => return response,
    };

    match list_http(
        conn,
        &HttpQuery {
            session_id,
            user_id: &caller.user_id,
            filter: &filter,
            from_ns,
            to_ns,
            cursor,
            limit,
            redact_paths,
            redact_hosts,
        },
    ) {
        Ok(value) => json_response(200, &value),
        Err(message) => error_response(500, "store", &message),
    }
}

struct BoundFilter {
    sql: String,
    params: Vec<Bound>,
}

enum Bound {
    Text(String),
    Int(i64),
}

fn compile_http_filter(
    filter: &str,
    session_start_ns: Option<i64>,
) -> Result<BoundFilter, ApiResponse> {
    if filter.is_empty() {
        return Ok(BoundFilter {
            sql: String::new(),
            params: Vec::new(),
        });
    }
    // aw-store's public `parse_filter` returns `FilterExpr`, which is not the
    // AST `compile_predicate` accepts (`StoreExpr`, no public parser). The core
    // parser is the shared grammar; map that tree onto `StoreExpr` here.
    let core = filter::parse(filter)
        .map_err(|err| error_response(400, "bad_filter", &format!("filter: {err}")))?;
    let expr = core_to_store(&core);
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_nanos()).ok());
    let ctx = CompileCtx {
        session_start_ns,
        now_ns,
        fts: false,
        case_insensitive_paths: cfg!(windows),
    };
    let compiled = compile_predicate(&expr, StoreTarget::Http, &ctx)
        .map_err(|err| error_response(400, "bad_filter", &format!("filter: {err}")))?;
    let params = compiled
        .params
        .into_iter()
        .map(|param| match param {
            StoreParam::Text(text) => Bound::Text(text),
            StoreParam::Int(n) => Bound::Int(n),
        })
        .collect();
    Ok(BoundFilter {
        sql: compiled.sql,
        params,
    })
}

struct HttpQuery<'a> {
    session_id: i64,
    user_id: &'a str,
    filter: &'a BoundFilter,
    from_ns: Option<i64>,
    to_ns: Option<i64>,
    cursor: Option<(i64, i64)>,
    limit: i64,
    redact_paths: bool,
    redact_hosts: bool,
}

fn list_http(
    conn: &rusqlite::Connection,
    query: &HttpQuery<'_>,
) -> Result<serde_json::Value, String> {
    // aw-store has no list_http. Predicate columns from compile_predicate are
    // unqualified (`method`, `url`, `host`, ...), so the FROM clause is `http`
    // with no join. Process summary is two scalar subqueries. Ownership is the
    // EXISTS on sessions.user_id, matching session_by_public_id.
    let HttpQuery {
        session_id,
        user_id,
        filter,
        from_ns,
        to_ns,
        cursor,
        limit,
        redact_paths,
        redact_hosts,
    } = *query;
    let mut sql = String::from(
        "SELECT id, session_id, proc_uid, flow_id, ts_ns, method, url, host, \
         http_version, status, req_headers, resp_headers, req_body_bytes, \
         resp_body_bytes, content_type, duration_ms, error, evidence, source, \
         (SELECT pid FROM processes p \
            WHERE p.session_id = http.session_id AND p.proc_uid = http.proc_uid), \
         (SELECT exe FROM process_images i \
            WHERE i.session_id = http.session_id AND i.proc_uid = http.proc_uid \
            ORDER BY seq DESC LIMIT 1) \
         FROM http \
         WHERE session_id = ?1 \
           AND EXISTS ( \
             SELECT 1 FROM sessions s \
             WHERE s.id = http.session_id AND s.user_id = ?2)",
    );
    let mut values: Vec<Bound> = vec![Bound::Int(session_id), Bound::Text(user_id.to_owned())];
    if !filter.sql.is_empty() {
        sql.push_str(" AND (");
        sql.push_str(&filter.sql);
        sql.push(')');
        values.extend(filter.params.iter().map(clone_bound));
    }
    if let Some(from_ns) = from_ns {
        sql.push_str(" AND ts_ns >= ?");
        values.push(Bound::Int(from_ns));
    }
    if let Some(to_ns) = to_ns {
        sql.push_str(" AND ts_ns < ?");
        values.push(Bound::Int(to_ns));
    }
    if let Some((ts, id)) = cursor {
        sql.push_str(" AND (ts_ns > ? OR (ts_ns = ? AND id > ?))");
        values.push(Bound::Int(ts));
        values.push(Bound::Int(ts));
        values.push(Bound::Int(id));
    }
    sql.push_str(" ORDER BY ts_ns, id LIMIT ?");
    let fetch = limit.saturating_add(1);
    values.push(Bound::Int(fetch));

    let mut stmt = conn.prepare(&sql).map_err(|err| err.to_string())?;
    let mut rows = stmt
        .query(rusqlite::params_from_iter(values.iter().map(bound_to_sql)))
        .map_err(|err| err.to_string())?;
    let mut items = Vec::new();
    while let Some(row) = rows.next().map_err(|err| err.to_string())? {
        items.push(http_json(row, redact_paths, redact_hosts)?);
        if items.len() as i64 > limit {
            break;
        }
    }
    let next = if items.len() as i64 > limit {
        items.pop().map(|row| {
            let ts = row
                .get("ts_ns")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0);
            let id = row
                .get("id")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0);
            format!("{ts},{id}")
        })
    } else {
        None
    };
    Ok(serde_json::json!({
        "http": items,
        "next_cursor": next,
    }))
}

fn http_json(
    row: &rusqlite::Row<'_>,
    redact_paths: bool,
    redact_hosts: bool,
) -> Result<serde_json::Value, String> {
    let proc_uid: Option<i64> = row.get(2).map_err(|err| err.to_string())?;
    let pid: Option<i64> = row.get(19).map_err(|err| err.to_string())?;
    let exe: Option<String> = row.get(20).map_err(|err| err.to_string())?;
    let mut url: String = row.get(6).map_err(|err| err.to_string())?;
    let mut host: String = row.get(7).map_err(|err| err.to_string())?;
    if redact_paths {
        url = redact_user_paths(&url);
    }
    if redact_hosts {
        host = redact_host_field(&host);
        url = redact_host_text(&url);
    }
    let exe_name = exe.as_deref().and_then(exe_file_name).map(|name| {
        if redact_paths {
            redact_user_paths(name)
        } else {
            name.to_owned()
        }
    });
    let proc = match (pid, exe_name) {
        (None, None) => serde_json::Value::Null,
        (pid, exe_name) => serde_json::json!({ "pid": pid, "exe_name": exe_name }),
    };
    Ok(serde_json::json!({
        "id": i64_field(row, 0)?,
        "session_id": i64_field(row, 1)?,
        "proc_uid": proc_uid.map(|id| format!("{id:x}")),
        "flow_id": opt_i64(row, 3)?,
        "ts_ns": i64_field(row, 4)?,
        "method": text_field(row, 5)?,
        "url": url,
        "host": host,
        "http_version": opt_text(row, 8)?,
        "status": opt_i64(row, 9)?,
        "req_headers": opt_text(row, 10)?,
        "resp_headers": opt_text(row, 11)?,
        "req_body_bytes": opt_i64(row, 12)?,
        "resp_body_bytes": opt_i64(row, 13)?,
        "content_type": opt_text(row, 14)?,
        "duration_ms": opt_i64(row, 15)?,
        "error": opt_text(row, 16)?,
        "evidence": text_field(row, 17)?,
        "source": text_field(row, 18)?,
        "proc": proc,
    }))
}

fn i64_field(row: &rusqlite::Row<'_>, idx: usize) -> Result<i64, String> {
    row.get(idx).map_err(|err| err.to_string())
}

fn text_field(row: &rusqlite::Row<'_>, idx: usize) -> Result<String, String> {
    row.get(idx).map_err(|err| err.to_string())
}

fn opt_i64(row: &rusqlite::Row<'_>, idx: usize) -> Result<Option<i64>, String> {
    row.get(idx).map_err(|err| err.to_string())
}

fn opt_text(row: &rusqlite::Row<'_>, idx: usize) -> Result<Option<String>, String> {
    row.get(idx).map_err(|err| err.to_string())
}

fn exe_file_name(path: &str) -> Option<&str> {
    path.rsplit(['/', '\\'])
        .next()
        .filter(|name| !name.is_empty())
}

/// Shared session lookup. Numeric `sid` is `sessions.id` owned by `user_id`.
/// Anything else is `public_id` via [`session_by_public_id`].
pub(crate) fn resolve_session(
    conn: &rusqlite::Connection,
    user_id: &str,
    sid: &str,
) -> Result<Option<i64>, String> {
    if let Ok(id) = sid.parse::<i64>() {
        return conn
            .query_row(
                "SELECT id FROM sessions WHERE id = ?1 AND user_id = ?2",
                rusqlite::params![id, user_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|err| err.to_string());
    }
    session_by_public_id(conn, user_id, sid).map_err(|err| err.to_string())
}

fn proxy_enabled(
    conn: &rusqlite::Connection,
    session_id: i64,
    user_id: &str,
) -> Result<Option<bool>, String> {
    conn.query_row(
        "SELECT proxy_enabled FROM sessions WHERE id = ?1 AND user_id = ?2",
        rusqlite::params![session_id, user_id],
        |row| row.get::<_, i64>(0),
    )
    .optional()
    .map(|value| value.map(|n| n != 0))
    .map_err(|err| err.to_string())
}

pub(crate) fn session_start_ns(conn: &rusqlite::Connection, session_id: i64) -> Option<i64> {
    conn.query_row(
        "SELECT started_ns FROM sessions WHERE id = ?1",
        rusqlite::params![session_id],
        |row| row.get(0),
    )
    .ok()
}

pub(crate) fn open_owned(
    state: &ApiState,
    user_id: &str,
    sid: &str,
) -> Result<Option<(Store, i64)>, ApiResponse> {
    let Some(path) = state.query.db_path.as_deref() else {
        return Ok(None);
    };
    let store = Store::open(path).map_err(|err| error_response(500, "store", &err.to_string()))?;
    match resolve_session(store.connection(), user_id, sid) {
        Ok(Some(id)) => Ok(Some((store, id))),
        Ok(None) => Ok(None),
        Err(message) => Err(error_response(500, "store", &message)),
    }
}

pub(crate) fn page_limit(raw: Option<&str>) -> Result<i64, ApiResponse> {
    match raw {
        None | Some("") => Ok(100),
        Some(text) => {
            let limit = text
                .parse::<i64>()
                .map_err(|_| error_response(400, "bad_argument", "limit: expected an integer"))?;
            if !(1..=MAX_PAGE).contains(&limit) {
                return Err(error_response(
                    400,
                    "bad_argument",
                    "limit: expected 1..=2000",
                ));
            }
            Ok(limit)
        }
    }
}

pub(crate) fn optional_i64(raw: Option<&str>, key: &str) -> Result<Option<i64>, ApiResponse> {
    match raw {
        None | Some("") => Ok(None),
        Some(text) => text.parse::<i64>().map(Some).map_err(|_| {
            error_response(400, "bad_argument", &format!("{key}: expected an integer"))
        }),
    }
}

pub(crate) fn parse_cursor(raw: Option<&str>) -> Result<Option<(i64, i64)>, ApiResponse> {
    match raw.map(str::trim).filter(|text| !text.is_empty()) {
        None => Ok(None),
        Some(text) => {
            let Some((ts, id)) = text.split_once(',') else {
                return Err(error_response(
                    400,
                    "bad_argument",
                    "cursor: expected ts_ns,id",
                ));
            };
            let ts = ts
                .trim()
                .parse::<i64>()
                .map_err(|_| error_response(400, "bad_argument", "cursor: expected ts_ns,id"))?;
            let id = id
                .trim()
                .parse::<i64>()
                .map_err(|_| error_response(400, "bad_argument", "cursor: expected ts_ns,id"))?;
            Ok(Some((ts, id)))
        }
    }
}

pub(crate) fn flag_on(raw: Option<&str>) -> bool {
    matches!(
        raw.map(str::trim),
        Some("1" | "true" | "TRUE" | "yes" | "YES")
    )
}

pub(crate) fn query_pairs(raw: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for part in raw.split('&') {
        if part.is_empty() {
            continue;
        }
        let (key, value) = part.split_once('=').unwrap_or((part, ""));
        out.insert(percent_decode(key), percent_decode(value));
    }
    out
}

fn percent_decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let Ok(hex) = u8::from_str_radix(
                std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or(""),
                16,
            ) {
                out.push(hex);
                index += 3;
                continue;
            }
        }
        if bytes[index] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[index]);
        }
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub(crate) fn parse_lang(raw: Option<&str>) -> Result<Lang, ApiResponse> {
    match raw.map(str::trim).filter(|text| !text.is_empty()) {
        None | Some("zh") => Ok(Lang::Zh),
        Some("en") => Ok(Lang::En),
        Some(_) => Err(error_response(
            400,
            "bad_argument",
            "lang: expected zh or en",
        )),
    }
}

pub(crate) fn json_response(status: u16, value: &serde_json::Value) -> ApiResponse {
    let mut headers = BTreeMap::new();
    headers.insert("content-type".to_owned(), "application/json".to_owned());
    let body = serde_json::to_vec(value).unwrap_or_else(|_| br#"{"error":"encode"}"#.to_vec());
    ApiResponse {
        status,
        headers,
        body,
    }
}

fn core_to_store(expr: &CoreExpr) -> StoreExpr {
    match expr {
        CoreExpr::True => StoreExpr::True,
        CoreExpr::And(left, right) => StoreExpr::And(
            Box::new(core_to_store(left)),
            Box::new(core_to_store(right)),
        ),
        CoreExpr::Or(left, right) => StoreExpr::Or(
            Box::new(core_to_store(left)),
            Box::new(core_to_store(right)),
        ),
        CoreExpr::Not(inner) => StoreExpr::Not(Box::new(core_to_store(inner))),
        CoreExpr::Term(term) => StoreExpr::Term(StoreTerm {
            field: store_field(term.field.name()),
            op: store_op(term.op),
            values: term.values.iter().map(store_value).collect(),
            offset: term.offset,
        }),
    }
}

fn store_op(op: CoreOp) -> StoreOp {
    match op {
        CoreOp::Match => StoreOp::Match,
        CoreOp::Eq => StoreOp::Eq,
        CoreOp::Ne => StoreOp::Ne,
        CoreOp::Gt => StoreOp::Gt,
        CoreOp::Ge => StoreOp::Ge,
        CoreOp::Lt => StoreOp::Lt,
        CoreOp::Le => StoreOp::Le,
        CoreOp::Contains => StoreOp::Contains,
        CoreOp::In => StoreOp::In,
    }
}

fn store_value(value: &CoreValue) -> StoreValue {
    match value {
        CoreValue::Text(text) => StoreValue::Text(text.clone()),
        CoreValue::Number(n) => StoreValue::Number(*n),
        CoreValue::RelativeTime {
            from_session_start,
            nanos,
        } => StoreValue::RelativeTime {
            from_session_start: *from_session_start,
            nanos: *nanos,
        },
        CoreValue::Bool(flag) => StoreValue::Bool(*flag),
    }
}

fn store_field(name: &str) -> StoreField {
    match name {
        "" => StoreField::Bare,
        "kind" => StoreField::Kind,
        "time" => StoreField::Time,
        "evidence" => StoreField::Evidence,
        "source" => StoreField::Source,
        "proc" => StoreField::Proc,
        "pid" => StoreField::Pid,
        "proc_uid" => StoreField::ProcUid,
        "subtree" => StoreField::Subtree,
        "tag" => StoreField::Tag,
        "exe" => StoreField::Exe,
        "argv" => StoreField::Argv,
        "cwd" => StoreField::Cwd,
        "path" => StoreField::Path,
        "dir" => StoreField::Dir,
        "op" => StoreField::FileOp,
        "access" => StoreField::Access,
        "bytes_read" => StoreField::BytesRead,
        "bytes_written" => StoreField::BytesWritten,
        "domain" => StoreField::Domain,
        "ip" => StoreField::Ip,
        "port" => StoreField::Port,
        "remote.ip" => StoreField::RemoteIp,
        "remote.port" => StoreField::RemotePort,
        "local.port" => StoreField::LocalPort,
        "proto" => StoreField::Proto,
        "bytes_up" => StoreField::BytesUp,
        "bytes_down" => StoreField::BytesDown,
        "direct" => StoreField::Direct,
        "via_proxy" => StoreField::ViaProxy,
        "qname" => StoreField::Qname,
        "qtype" => StoreField::Qtype,
        "rcode" => StoreField::Rcode,
        "method" => StoreField::Method,
        "url" => StoreField::Url,
        "host" => StoreField::Host,
        "status" => StoreField::Status,
        "req_bytes" => StoreField::ReqBytes,
        "resp_bytes" => StoreField::RespBytes,
        "tool" => StoreField::Tool,
        "agent" => StoreField::Agent,
        "ipc_kind" => StoreField::IpcKind,
        "peer" => StoreField::Peer,
        "channel" => StoreField::Channel,
        "target" => StoreField::Target,
        "rule" => StoreField::Rule,
        "severity" => StoreField::Severity,
        other => StoreField::Other(other.to_owned()),
    }
}

fn clone_bound(bound: &Bound) -> Bound {
    match bound {
        Bound::Text(text) => Bound::Text(text.clone()),
        Bound::Int(n) => Bound::Int(*n),
    }
}

fn bound_to_sql(bound: &Bound) -> rusqlite::types::Value {
    match bound {
        Bound::Text(text) => rusqlite::types::Value::Text(text.clone()),
        Bound::Int(n) => rusqlite::types::Value::Integer(*n),
    }
}
