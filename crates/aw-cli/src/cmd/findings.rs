//! `aw findings <SESSION> [--min-severity] [--evidence] [--lang] [--json]`
//! (P3-CLI-01).
//!
//! Rows come from a [`QuerySource`]. The live route is
//! `GET /api/v1/sessions/{sid}/findings`. [`super::query::findings_request`]
//! builds that call. This command does not open the database and does not dial
//! the daemon.
//!
//! The table prints the rendered sentence, the evidence level, the count, and
//! the first and last timestamps. `--json` also includes `refs`. A row whose
//! wording failed to render keeps `text: null` and an `error`; this command
//! does not invent a sentence. Evidence is printed as stored and is not raised.

use std::io;

use serde_json::{json, Value};

use crate::exit;
use crate::output::OutputMode;

use super::query::{self, FindingItem, FindingQuery, QuerySource};
use super::sessions::query_outcome;
use super::Outcome;

/// Evidence tokens `--evidence` accepts. `content_match` filters on `kind`;
/// the rest filter on the stored evidence string (api-and-cli §3).
const EVIDENCE_TOKENS: &[&str] = &["E1", "E2", "E3", "S", "I", "NA", "content_match"];

/// Parsed `aw findings` arguments.
pub(crate) struct FindingsArgs<'a> {
    /// `<SESSION>`: public id, name, or `@last`.
    pub session: &'a str,
    /// `--min-severity info|notice|warn`.
    pub min_severity: Option<&'a str>,
    /// `--evidence`, comma-separated.
    pub evidence: Option<&'a str>,
    /// `--lang`, or the global `--lang` when this one is absent.
    pub lang: Option<&'a str>,
    /// `--json`.
    pub json: bool,
}

/// Render findings for one session.
///
/// # Errors
///
/// A failure to format the outcome. The process code is [`Outcome::code`].
pub(crate) fn run(args: FindingsArgs<'_>, source: &dyn QuerySource) -> io::Result<Outcome> {
    if args.session.trim().is_empty() {
        return Ok(super::error_outcome(
            exit::USAGE,
            "usage",
            "会话不能为空",
            args.json,
        ));
    }
    if let Some(severity) = args.min_severity {
        if !matches!(severity, "info" | "notice" | "warn") {
            return Ok(super::error_outcome(
                exit::USAGE,
                "usage",
                &format!("--min-severity `{severity}` 不是 info、notice 或 warn"),
                args.json,
            ));
        }
    }
    let evidence = match parse_evidence(args.evidence) {
        Ok(tokens) => tokens,
        Err(detail) => {
            return Ok(super::error_outcome(
                exit::USAGE,
                "usage",
                &detail,
                args.json,
            ));
        }
    };
    let lang = match args.lang {
        Some("zh" | "en") => args.lang.map(str::to_owned),
        Some(other) => {
            return Ok(super::error_outcome(
                exit::USAGE,
                "usage",
                &format!("--lang `{other}` 不是 zh 或 en"),
                args.json,
            ));
        }
        None => None,
    };
    let query = FindingQuery {
        min_severity: args.min_severity.map(str::to_owned),
        evidence,
        lang,
    };
    let _request = query::findings_request(args.session, &query);
    let mode = OutputMode::from_json_flag(args.json);
    match source.findings(args.session, &query) {
        Ok(rows) => Ok(render_findings(&rows, mode)),
        Err(err) => Ok(query_outcome(err, args.json)),
    }
}

fn render_findings(rows: &[FindingItem], mode: OutputMode) -> Outcome {
    let text = match mode {
        OutputMode::Json => format!("{}\n", findings_json(rows)),
        OutputMode::Table => findings_table(rows),
    };
    Outcome {
        code: exit::OK,
        stdout: text.into_bytes(),
        stderr: Vec::new(),
    }
}

fn parse_evidence(text: Option<&str>) -> Result<Vec<String>, String> {
    let Some(text) = text else {
        return Ok(Vec::new());
    };
    let mut tokens = Vec::new();
    for part in text.split(',') {
        let token = part.trim();
        if token.is_empty() {
            return Err("--evidence 含有空项".to_owned());
        }
        if !EVIDENCE_TOKENS.contains(&token) {
            return Err(format!(
                "--evidence `{token}` 不是 E1、E2、E3、S、I、NA 或 content_match"
            ));
        }
        if !tokens.iter().any(|have: &String| have == token) {
            tokens.push(token.to_owned());
        }
    }
    Ok(tokens)
}

/// Five columns, evidence printed as stored.
///
/// The shared table appends a badge and turns anything it does not know
/// (`content_match`) into `不可得`. That would hide the level this command is
/// asked to show, so the grid is drawn here and the stored string is the cell.
fn findings_table(rows: &[FindingItem]) -> String {
    let headers = ["text", "evidence", "count", "first_ns", "last_ns"];
    let mut grid = Vec::with_capacity(rows.len() + 1);
    grid.push(headers.iter().map(|cell| (*cell).to_owned()).collect());
    for row in rows {
        grid.push(vec![
            text_cell(row),
            row.evidence.clone(),
            row.count.to_string(),
            row.first_ns.to_string(),
            row.last_ns.to_string(),
        ]);
    }
    align(&grid)
}

fn align(grid: &[Vec<String>]) -> String {
    let cols = grid.first().map(Vec::len).unwrap_or(0);
    let mut widths = vec![0_usize; cols];
    for row in grid {
        for (index, cell) in row.iter().enumerate() {
            widths[index] = widths[index].max(cell.chars().count());
        }
    }
    let mut out = String::new();
    for row in grid {
        for (index, cell) in row.iter().enumerate() {
            if index > 0 {
                out.push_str("  ");
            }
            out.push_str(cell);
            let pad = widths[index].saturating_sub(cell.chars().count());
            out.push_str(&" ".repeat(pad));
        }
        out.push('\n');
    }
    out
}

/// The rendered sentence. A failed render is `不可得`, not a made-up line.
fn text_cell(row: &FindingItem) -> String {
    match row.text.as_deref() {
        Some(text) if !text.is_empty() => text.to_owned(),
        _ => "不可得".to_owned(),
    }
}

fn findings_json(rows: &[FindingItem]) -> Value {
    json!({
        "findings": rows.iter().map(|row| json!({
            "id": row.id,
            "rule_id": row.rule_id,
            "kind": row.kind,
            "evidence": row.evidence,
            "severity": row.severity,
            "wording_id": row.wording_id,
            "params": params_json(&row.params),
            "text": row.text,
            "error": row.error,
            "count": row.count,
            "first_ns": row.first_ns,
            "last_ns": row.last_ns,
            "refs": row.refs.iter().map(|item| json!({
                "table": item.table,
                "id": item.id,
            })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
    })
}

fn params_json(params: &[(String, String)]) -> Value {
    let mut map = serde_json::Map::new();
    for (key, value) in params {
        map.insert(key.clone(), Value::String(value.clone()));
    }
    Value::Object(map)
}
