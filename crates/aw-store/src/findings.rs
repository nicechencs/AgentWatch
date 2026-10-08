//! `findings` rows and the dedup UPSERT.
//!
//! storage.md §4: conflict key is `(session_id, rule_id, dedup_key)`. A repeat
//! adds one to `count`, moves `last_ns` forward, and appends `refs`. `refs` is
//! a JSON array of `{"table","id"}` objects and keeps at most [`MAX_REFS`]
//! entries. Older entries are dropped from the front.
//!
//! The cap is applied in Rust. The existing array is read, parsed back into
//! [`FindingRef`] values, extended, and written as one JSON text. SQLite's
//! `json_insert` would append without a bound, and this crate does not enable
//! the JSON1 functions. NULL is never stored for an empty list: `refs` is
//! `NOT NULL`, and an empty observation is `[]`.
//!
//! `user_state` is not touched on conflict. A later observation does not clear
//! a mark the user already made.

use rusqlite::{params, Connection, OptionalExtension};

use crate::error::StoreError;

/// How many `refs` entries one finding keeps. storage.md §4.
pub const MAX_REFS: usize = 50;

/// One reference inside `findings.refs`.
///
/// `table` is a table name (`file_access`, `http`, ...). `id` is that table's
/// row id. Neither is optional: a ref that names nothing is not stored.
#[derive(Clone, PartialEq, Eq)]
pub struct FindingRef {
    /// Source table name.
    pub table: String,
    /// Row id in `table`.
    pub id: i64,
}

/// One `findings` row. Not `Debug`: `params` may quote a path or a host.
#[derive(Clone)]
pub struct FindingRow {
    /// Caller-assigned id. `None` lets SQLite allocate one on insert.
    /// Ignored when the dedup key already exists.
    pub id: Option<i64>,
    /// Owning session.
    pub session_id: i64,
    /// Rule id.
    pub rule_id: String,
    /// Rule version.
    pub rule_version: i64,
    /// `fact` / `fact_conjunction` / `inference` / `content_match`.
    pub kind: String,
    /// `E1|E2|E3|S|I|NA`.
    pub evidence: String,
    /// `info` / `notice` / `warn`.
    pub severity: String,
    /// Wording template id.
    pub wording_id: String,
    /// JSON object of template parameters. Required; not an empty string.
    pub params: String,
    /// First hit, Unix nanoseconds.
    pub first_ns: i64,
    /// Latest hit, Unix nanoseconds.
    pub last_ns: i64,
    /// Dedup key. Together with `session_id` and `rule_id`.
    pub dedup_key: String,
    /// Evidence rows for this hit. Appended on conflict, then capped.
    pub refs: Vec<FindingRef>,
    /// JSON caveat list, or NULL when there is none.
    pub caveats: Option<String>,
    /// `confirmed` / `ignored`, or unmarked.
    pub user_state: Option<String>,
    /// Who set `user_state`, or unknown.
    pub user_state_by: Option<String>,
    /// When `user_state` was set, Unix nanoseconds, or unknown.
    pub user_state_ns: Option<i64>,
}

/// Insert `row`, or on `(session_id, rule_id, dedup_key)` add 1 to `count`,
/// keep the later `last_ns`, and append `row.refs` up to [`MAX_REFS`].
pub fn upsert_finding(conn: &Connection, row: &FindingRow) -> Result<(), StoreError> {
    let existing = load_refs(conn, row)?;
    let refs_json = match existing {
        Some(prior) => merge_refs(&prior, &row.refs)?,
        None => encode_refs(trim_tail(&row.refs)),
    };
    conn.execute(
        "INSERT INTO findings (
            id, session_id, rule_id, rule_version, kind, evidence, severity,
            wording_id, params, first_ns, last_ns, count, dedup_key, refs, caveats,
            user_state, user_state_by, user_state_ns
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7,
            ?8, ?9, ?10, ?11, 1, ?12, ?13, ?14,
            ?15, ?16, ?17
         )
         ON CONFLICT (session_id, rule_id, dedup_key) DO UPDATE SET
            last_ns = CASE
                WHEN excluded.last_ns > findings.last_ns THEN excluded.last_ns
                ELSE findings.last_ns END,
            first_ns = CASE
                WHEN excluded.first_ns < findings.first_ns THEN excluded.first_ns
                ELSE findings.first_ns END,
            count = findings.count + 1,
            refs = excluded.refs,
            rule_version = excluded.rule_version,
            kind = excluded.kind,
            evidence = excluded.evidence,
            severity = excluded.severity,
            wording_id = excluded.wording_id,
            params = excluded.params,
            caveats = COALESCE(excluded.caveats, findings.caveats)",
        params![
            row.id,
            row.session_id,
            row.rule_id,
            row.rule_version,
            row.kind,
            row.evidence,
            row.severity,
            row.wording_id,
            row.params,
            row.first_ns,
            row.last_ns,
            row.dedup_key,
            refs_json,
            row.caveats,
            row.user_state,
            row.user_state_by,
            row.user_state_ns,
        ],
    )
    .map_err(|err| StoreError::sqlite("upsert_finding", err))?;
    Ok(())
}

fn load_refs(conn: &Connection, row: &FindingRow) -> Result<Option<String>, StoreError> {
    conn.query_row(
        "SELECT refs FROM findings
         WHERE session_id = ?1 AND rule_id = ?2 AND dedup_key = ?3",
        params![row.session_id, row.rule_id, row.dedup_key],
        |found| found.get(0),
    )
    .optional()
    .map_err(|err| StoreError::sqlite("read_finding_refs", err))
}

/// Parse `prior`, append `extra`, keep the last [`MAX_REFS`].
///
/// A `prior` this writer did not produce (not a JSON array of objects) is an
/// error. Replacing it would drop evidence the row already cited.
fn merge_refs(prior: &str, extra: &[FindingRef]) -> Result<String, StoreError> {
    let mut items = decode_refs(prior)?;
    items.extend(extra.iter().cloned());
    Ok(encode_refs(trim_tail(&items)))
}

fn trim_tail(items: &[FindingRef]) -> &[FindingRef] {
    if items.len() > MAX_REFS {
        &items[items.len() - MAX_REFS..]
    } else {
        items
    }
}

fn decode_refs(text: &str) -> Result<Vec<FindingRef>, StoreError> {
    let inner = text
        .trim()
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .ok_or_else(|| bad_refs(text))?;
    let inner = inner.trim();
    if inner.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for object in split_objects(inner)? {
        out.push(decode_one(object)?);
    }
    Ok(out)
}

/// Split a JSON array body on top-level `},{`. Strings are not split, so a
/// table name that contains `}` does not break the scan.
fn split_objects(inner: &str) -> Result<Vec<&str>, StoreError> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut depth = 0_i32;
    let mut in_string = false;
    let mut escape = false;
    for (index, ch) in inner.char_indices() {
        if in_string {
            if escape {
                escape = false;
            } else if ch == '\\' {
                escape = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        match ch {
            '"' => in_string = true,
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    let end = index + ch.len_utf8();
                    out.push(inner[start..end].trim());
                    start = end;
                } else if depth < 0 {
                    return Err(bad_refs(inner));
                }
            }
            ',' if depth == 0 => {
                if !inner[start..index].trim().is_empty() {
                    return Err(bad_refs(inner));
                }
                start = index + ch.len_utf8();
            }
            c if depth == 0 && !c.is_whitespace() => return Err(bad_refs(inner)),
            _ => {}
        }
    }
    if in_string || depth != 0 || !inner[start..].trim().is_empty() {
        return Err(bad_refs(inner));
    }
    Ok(out)
}

fn decode_one(object: &str) -> Result<FindingRef, StoreError> {
    let body = object
        .trim()
        .strip_prefix('{')
        .and_then(|rest| rest.strip_suffix('}'))
        .ok_or_else(|| bad_refs(object))?;
    let mut table: Option<String> = None;
    let mut id: Option<i64> = None;
    for field in split_fields(body)? {
        let (key, value) = split_key(field)?;
        match key {
            "table" => table = Some(decode_string(value)?),
            "id" => {
                id = Some(value.trim().parse::<i64>().map_err(|_| bad_refs(object))?);
            }
            _ => {}
        }
    }
    match (table, id) {
        (Some(table), Some(id)) => Ok(FindingRef { table, id }),
        _ => Err(bad_refs(object)),
    }
}

fn split_fields(body: &str) -> Result<Vec<&str>, StoreError> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut depth = 0_i32;
    let mut in_string = false;
    let mut escape = false;
    for (index, ch) in body.char_indices() {
        if in_string {
            if escape {
                escape = false;
            } else if ch == '\\' {
                escape = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        match ch {
            '"' => in_string = true,
            '{' | '[' => depth += 1,
            '}' | ']' => depth -= 1,
            ',' if depth == 0 => {
                out.push(body[start..index].trim());
                start = index + 1;
            }
            _ => {}
        }
    }
    if in_string || depth != 0 {
        return Err(bad_refs(body));
    }
    let tail = body[start..].trim();
    if !tail.is_empty() {
        out.push(tail);
    }
    Ok(out)
}

fn split_key(field: &str) -> Result<(&str, &str), StoreError> {
    let mut in_string = false;
    let mut escape = false;
    for (index, ch) in field.char_indices() {
        if in_string {
            if escape {
                escape = false;
            } else if ch == '\\' {
                escape = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        if ch == '"' {
            in_string = true;
        } else if ch == ':' {
            let raw_key = field[..index].trim();
            let bare = raw_key
                .strip_prefix('"')
                .and_then(|rest| rest.strip_suffix('"'))
                .ok_or_else(|| bad_refs(field))?;
            // This writer emits unescaped keys. An escaped key is not one of them.
            if bare.contains('\\') {
                return Err(bad_refs(field));
            }
            return Ok((bare, field[index + 1..].trim()));
        }
    }
    Err(bad_refs(field))
}

fn decode_string(value: &str) -> Result<String, StoreError> {
    let value = value.trim();
    let inner = value
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .ok_or_else(|| bad_refs(value))?;
    let mut out = String::new();
    let mut chars = inner.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('"') => out.push('"'),
            Some('\\') => out.push('\\'),
            Some('/') => out.push('/'),
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('u') => {
                let mut hex = String::new();
                for _ in 0..4 {
                    hex.push(chars.next().ok_or_else(|| bad_refs(value))?);
                }
                let code = u32::from_str_radix(&hex, 16).map_err(|_| bad_refs(value))?;
                out.push(char::from_u32(code).ok_or_else(|| bad_refs(value))?);
            }
            _ => return Err(bad_refs(value)),
        }
    }
    Ok(out)
}

fn encode_refs(refs: &[FindingRef]) -> String {
    let mut out = String::from("[");
    for (index, item) in refs.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str("{\"table\":");
        out.push_str(&json_string(&item.table));
        out.push_str(",\"id\":");
        out.push_str(&item.id.to_string());
        out.push('}');
    }
    out.push(']');
    out
}

/// JSON string literal. `table` is a caller-supplied name, so quotes and
/// controls are escaped. The result is not SQL.
fn json_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let code = c as u32;
                out.push_str(&format!("\\u{code:04x}"));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn bad_refs(text: &str) -> StoreError {
    // `text` is a stored JSON array of table names and ids, not a URL or argv.
    // Keep the message short: a large refs list must not land in a log line.
    let preview: String = text.chars().take(80).collect();
    StoreError::BadSchemaVersion {
        found: Some(format!("findings.refs is not a JSON array: {preview}")),
    }
}
