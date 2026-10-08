//! `GET` and `PATCH /sessions/{sid}/findings` (P3-DAEMON-01).
//!
//! `aw-store` exports [`aw_store::upsert_finding`] but no list and no user-state
//! update. The SELECT and the UPDATE below run on [`aw_store::Store::connection`].
//! The UPSERT is not used for PATCH: it increments `count` and leaves
//! `user_state` alone.
//!
//! Rendered `text` comes only from [`aw_pipeline::wording::render`]. A render
//! error sets `text` to null and adds `error`. It does not concatenate a
//! fallback sentence. `params` is returned as stored so a client can render
//! again.

use std::collections::BTreeMap;

use aw_pipeline::wording::{render, Lang, WordingError};

use super::auth::Caller;
use super::http_events::{
    json_response, open_owned, page_limit, parse_cursor, parse_lang, query_pairs,
};
use super::routes::{error_response, ApiResponse, ApiState};

/// Names the Markdown module can import. `export` is a sibling of `api`, and
/// `api`'s modules are private, so this module re-exports the types it already uses.
pub(crate) mod share {
    pub(crate) use super::super::auth::Caller;
    pub(crate) use super::super::http_events::{
        flag_on, json_response, open_owned, parse_lang, query_pairs,
    };
    pub(crate) use super::super::routes::{error_response, ApiResponse, ApiState};
    pub(crate) use super::{findings_for_report, FindingView};
}

/// `GET /sessions/{sid}/findings?lang=zh|en&min_severity=&evidence=&cursor=&limit=`.
pub(crate) fn get_findings(
    state: &ApiState,
    caller: &Caller,
    sid: &str,
    query: &str,
) -> ApiResponse {
    let pairs = query_pairs(query);
    let lang = match parse_lang(pairs.get("lang").map(String::as_str)) {
        Ok(lang) => lang,
        Err(response) => return response,
    };
    let limit = match page_limit(pairs.get("limit").map(String::as_str)) {
        Ok(limit) => limit,
        Err(response) => return response,
    };
    let cursor = match parse_cursor(pairs.get("cursor").map(String::as_str)) {
        Ok(cursor) => cursor,
        Err(response) => return response,
    };
    let min_severity = match pairs.get("min_severity").map(String::as_str) {
        None | Some("") => None,
        Some("info" | "notice" | "warn") => pairs.get("min_severity").map(String::as_str),
        Some(_) => {
            return error_response(
                400,
                "bad_argument",
                "min_severity: expected info, notice, or warn",
            )
        }
    };
    let evidence = match pairs.get("evidence").map(String::as_str) {
        None | Some("") => Vec::new(),
        Some(text) => text
            .split(',')
            .map(str::trim)
            .filter(|token| !token.is_empty())
            .map(str::to_owned)
            .collect(),
    };
    for token in &evidence {
        if !matches!(
            token.as_str(),
            "E1" | "E2" | "E3" | "S" | "I" | "NA" | "content_match"
        ) {
            return error_response(
                400,
                "bad_argument",
                "evidence: expected E1, E2, E3, S, I, NA, or content_match",
            );
        }
    }

    let opened = match open_owned(state, &caller.user_id, sid) {
        Ok(Some(pair)) => pair,
        Ok(None) => return error_response(404, "not_found", "session not found"),
        Err(response) => return response,
    };
    let (store, session_id) = opened;
    match list_findings(
        store.connection(),
        session_id,
        &caller.user_id,
        lang,
        min_severity,
        &evidence,
        cursor,
        limit,
    ) {
        Ok(value) => json_response(200, &value),
        Err(message) => error_response(500, "store", &message),
    }
}

/// `PATCH /sessions/{sid}/findings/{id}` body `{ "user_state": "confirmed"|"ignored"|null }`.
pub(crate) fn patch_finding(
    state: &ApiState,
    caller: &Caller,
    sid: &str,
    finding_id: &str,
    body: &[u8],
) -> ApiResponse {
    let finding_id = match finding_id.parse::<i64>() {
        Ok(id) => id,
        Err(_) => {
            return error_response(400, "bad_argument", "finding id: expected an integer")
        }
    };
    let value: serde_json::Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(_) => return error_response(400, "bad_request", "body is not json"),
    };
    let Some(state_value) = value.get("user_state") else {
        return error_response(400, "bad_request", "user_state is required");
    };
    let user_state = match state_value {
        serde_json::Value::Null => None,
        serde_json::Value::String(text) if text == "confirmed" || text == "ignored" => {
            Some(text.clone())
        }
        _ => {
            return error_response(
                400,
                "bad_request",
                "user_state: expected confirmed, ignored, or null",
            )
        }
    };

    let opened = match open_owned(state, &caller.user_id, sid) {
        Ok(Some(pair)) => pair,
        Ok(None) => return error_response(404, "not_found", "session not found"),
        Err(response) => return response,
    };
    let (store, session_id) = opened;
    let now_ns = unix_ns();
    // A null body clears the mark and who/when. A set records this caller.
    let (mark, by, at): (Option<&str>, Option<&str>, Option<i64>) = match user_state.as_deref() {
        Some(mark) => (Some(mark), Some(caller.user_id.as_str()), Some(now_ns)),
        None => (None, None, None),
    };
    // Direct UPDATE. upsert_finding would bump count and would not clear a mark.
    let changed = store.connection().execute(
        "UPDATE findings \
         SET user_state = ?1, user_state_by = ?2, user_state_ns = ?3 \
         WHERE id = ?4 AND session_id = ?5 \
           AND EXISTS ( \
             SELECT 1 FROM sessions s \
             WHERE s.id = findings.session_id AND s.user_id = ?6)",
        rusqlite::params![
            mark,
            by,
            at,
            finding_id,
            session_id,
            caller.user_id.as_str()
        ],
    );
    match changed {
        Ok(0) => error_response(404, "not_found", "finding not found"),
        Ok(_) => json_response(
            200,
            &serde_json::json!({
                "id": finding_id,
                "user_state": user_state,
                "user_state_by": by,
                "user_state_ns": at,
            }),
        ),
        Err(err) => error_response(500, "store", &err.to_string()),
    }
}

#[allow(clippy::too_many_arguments)]
fn list_findings(
    conn: &rusqlite::Connection,
    session_id: i64,
    user_id: &str,
    lang: Lang,
    min_severity: Option<&str>,
    evidence: &[String],
    cursor: Option<(i64, i64)>,
    limit: i64,
) -> Result<serde_json::Value, String> {
    let mut sql = String::from(
        "SELECT id, rule_id, rule_version, kind, evidence, severity, wording_id, params, \
         first_ns, last_ns, count, dedup_key, refs, caveats, \
         user_state, user_state_by, user_state_ns \
         FROM findings \
         WHERE session_id = ?1 \
           AND EXISTS ( \
             SELECT 1 FROM sessions s \
             WHERE s.id = findings.session_id AND s.user_id = ?2)",
    );
    let mut values: Vec<rusqlite::types::Value> = vec![
        rusqlite::types::Value::Integer(session_id),
        rusqlite::types::Value::Text(user_id.to_owned()),
    ];
    match min_severity {
        Some("warn") => {
            sql.push_str(" AND severity = 'warn'");
        }
        Some("notice") => {
            sql.push_str(" AND severity IN ('notice','warn')");
        }
        Some("info") | None | Some(_) => {}
    }
    if !evidence.is_empty() {
        sql.push_str(" AND (");
        let mut first = true;
        for token in evidence {
            if !first {
                sql.push_str(" OR ");
            }
            first = false;
            if token == "content_match" {
                sql.push_str("kind = 'content_match'");
            } else {
                sql.push_str("evidence = ?");
                values.push(rusqlite::types::Value::Text(token.clone()));
            }
        }
        sql.push(')');
    }
    if let Some((ts, id)) = cursor {
        sql.push_str(" AND (first_ns > ? OR (first_ns = ? AND id > ?))");
        values.push(rusqlite::types::Value::Integer(ts));
        values.push(rusqlite::types::Value::Integer(ts));
        values.push(rusqlite::types::Value::Integer(id));
    }
    sql.push_str(" ORDER BY first_ns, id LIMIT ?");
    values.push(rusqlite::types::Value::Integer(limit.saturating_add(1)));

    let mut stmt = conn.prepare(&sql).map_err(|err| err.to_string())?;
    let mut rows = stmt
        .query(rusqlite::params_from_iter(values.iter()))
        .map_err(|err| err.to_string())?;
    let mut items = Vec::new();
    while let Some(row) = rows.next().map_err(|err| err.to_string())? {
        items.push(finding_json(row, lang)?);
        if items.len() as i64 > limit {
            break;
        }
    }
    let next = if items.len() as i64 > limit {
        items.pop().map(|row| {
            let ts = row
                .get("first_ns")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0);
            let id = row.get("id").and_then(serde_json::Value::as_i64).unwrap_or(0);
            format!("{ts},{id}")
        })
    } else {
        None
    };
    Ok(serde_json::json!({
        "findings": items,
        "next_cursor": next,
    }))
}

fn finding_json(row: &rusqlite::Row<'_>, lang: Lang) -> Result<serde_json::Value, String> {
    let wording_id: String = row.get(6).map_err(|err| err.to_string())?;
    let params_text: String = row.get(7).map_err(|err| err.to_string())?;
    let params_value = serde_json::from_str::<serde_json::Value>(&params_text)
        .unwrap_or(serde_json::Value::String(params_text.clone()));
    let (text, error) = render_text(&wording_id, &params_value, lang);
    let refs: String = row.get(12).map_err(|err| err.to_string())?;
    let refs_value =
        serde_json::from_str::<serde_json::Value>(&refs).unwrap_or(serde_json::Value::String(refs));
    let caveats: Option<String> = row.get(13).map_err(|err| err.to_string())?;
    let caveats_value = match caveats {
        None => serde_json::Value::Null,
        Some(text) => serde_json::from_str(&text).unwrap_or(serde_json::Value::String(text)),
    };
    Ok(serde_json::json!({
        "id": row.get::<_, i64>(0).map_err(|err| err.to_string())?,
        "rule_id": row.get::<_, String>(1).map_err(|err| err.to_string())?,
        "rule_version": row.get::<_, i64>(2).map_err(|err| err.to_string())?,
        "kind": row.get::<_, String>(3).map_err(|err| err.to_string())?,
        "evidence": row.get::<_, String>(4).map_err(|err| err.to_string())?,
        "severity": row.get::<_, String>(5).map_err(|err| err.to_string())?,
        "wording_id": wording_id,
        "params": params_value,
        "text": text,
        "error": error,
        "first_ns": row.get::<_, i64>(8).map_err(|err| err.to_string())?,
        "last_ns": row.get::<_, i64>(9).map_err(|err| err.to_string())?,
        "count": row.get::<_, i64>(10).map_err(|err| err.to_string())?,
        "dedup_key": row.get::<_, String>(11).map_err(|err| err.to_string())?,
        "refs": refs_value,
        "caveats": caveats_value,
        "user_state": row.get::<_, Option<String>>(14).map_err(|err| err.to_string())?,
        "user_state_by": row.get::<_, Option<String>>(15).map_err(|err| err.to_string())?,
        "user_state_ns": row.get::<_, Option<i64>>(16).map_err(|err| err.to_string())?,
    }))
}

fn render_text(
    wording_id: &str,
    params_value: &serde_json::Value,
    lang: Lang,
) -> (Option<String>, Option<String>) {
    let pairs = match param_pairs(params_value) {
        Ok(pairs) => pairs,
        Err(message) => return (None, Some(message)),
    };
    let refs: Vec<(&str, &str)> = pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    match render(wording_id, &refs, lang) {
        Ok(text) => (Some(text), None),
        Err(err) => (None, Some(wording_error(&err))),
    }
}

fn param_pairs(value: &serde_json::Value) -> Result<BTreeMap<String, String>, String> {
    let Some(object) = value.as_object() else {
        return Err("params is not a json object".to_owned());
    };
    let mut pairs = BTreeMap::new();
    for (key, item) in object {
        let text = match item {
            serde_json::Value::String(text) => text.clone(),
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::Bool(flag) => flag.to_string(),
            serde_json::Value::Null => {
                return Err(format!("params.{key} is null"));
            }
            _ => return Err(format!("params.{key} is not a scalar")),
        };
        pairs.insert(key.clone(), text);
    }
    Ok(pairs)
}

fn wording_error(err: &WordingError) -> String {
    err.to_string()
}

fn unix_ns() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_nanos()).ok())
        .unwrap_or(0)
}

/// Rows the Markdown report groups. Same SELECT as the list, no page cap.
pub(crate) struct FindingView {
    /// Evidence label stored on the row.
    pub evidence: String,
    /// `fact` / `inference` / `content_match` / ...
    pub kind: String,
    /// Template id. `evidence.content_match` is the lint exception.
    pub wording_id: String,
    /// Rendered sentence, or the render error when `text` is absent.
    pub text: Option<String>,
    /// Render error. Present only when `text` is absent.
    pub error: Option<String>,
    /// `info` / `notice` / `warn`.
    pub severity: String,
}

/// Load every finding of a session this user owns. Used by Markdown export.
pub(crate) fn findings_for_report(
    conn: &rusqlite::Connection,
    session_id: i64,
    user_id: &str,
    lang: Lang,
) -> Result<Vec<FindingView>, String> {
    let value = list_findings(conn, session_id, user_id, lang, None, &[], None, 10_000)?;
    let Some(items) = value.get("findings").and_then(serde_json::Value::as_array) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for item in items {
        out.push(FindingView {
            evidence: item
                .get("evidence")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("NA")
                .to_owned(),
            kind: item
                .get("kind")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_owned(),
            wording_id: item
                .get("wording_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_owned(),
            text: item
                .get("text")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            error: item
                .get("error")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            severity: item
                .get("severity")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_owned(),
        });
    }
    Ok(out)
}
