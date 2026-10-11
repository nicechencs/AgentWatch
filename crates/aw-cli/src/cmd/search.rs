//! `aw search <TEXT> [--since] [--kind file|proc|url]` (P2-CLI-01).
//!
//! Cross-session search. The live route is `GET /api/v1/search?q&kind&since`.
//! [`super::query::search_request`] builds that call. This command does not
//! open the database. `--since` accepts RFC 3339 and relative-to-now forms.
//! A sensitive hit is highlighted only when `color` is set.

use std::io;

use crate::exit;
use crate::output::OutputMode;

use super::query::{QuerySource, SearchQuery};
use super::render;
use super::sessions::{query_outcome, write_ok};
use super::Outcome;

/// Parsed `aw search` arguments.
pub(crate) struct SearchArgs<'a> {
    /// Free text or a filter expression.
    pub text: &'a str,
    /// `--since`, raw text.
    pub since: Option<&'a str>,
    /// `--kind file|proc|url`.
    pub kind: Option<&'a str>,
    /// `--json`.
    pub json: bool,
    /// Color a sensitive hit. Production passes `false`.
    pub color: bool,
}

/// Render cross-session hits.
///
/// # Errors
///
/// A failure to format the outcome.
pub(crate) fn run(args: SearchArgs<'_>, source: &dyn QuerySource) -> io::Result<Outcome> {
    if args.text.trim().is_empty() {
        return Ok(super::error_outcome(
            exit::USAGE,
            "usage",
            "搜索文本为空",
            args.json,
        ));
    }
    if let Some(kind) = args.kind {
        if !matches!(kind, "file" | "proc" | "url") {
            return Ok(super::error_outcome(
                exit::USAGE,
                "usage",
                &format!("--kind `{kind}` 不是 file、proc 或 url"),
                args.json,
            ));
        }
    }
    let since_ns = match args.since {
        Some(text) => match resolve_since(text) {
            Ok(ns) => Some(ns),
            Err(detail) => {
                return Ok(super::error_outcome(
                    exit::USAGE,
                    "usage",
                    &detail,
                    args.json,
                ));
            }
        },
        None => None,
    };
    let query = SearchQuery {
        text: args.text.to_owned(),
        since_ns,
        kind: args.kind.map(str::to_owned),
    };
    let _request = super::query::search_request(&query, args.since);
    let mode = OutputMode::from_json_flag(args.json);
    match source.search(&query) {
        Ok(hits) => {
            let table = render::search_table(&hits, args.color);
            let doc = render::search_json(&hits);
            write_ok(mode, &table, &doc)
        }
        Err(err) => Ok(query_outcome(err, args.json)),
    }
}

/// RFC 3339 and relative-to-now forms resolve against the caller's clock.
fn resolve_since(text: &str) -> Result<i64, String> {
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_nanos()).unwrap_or(i64::MAX))
        .unwrap_or_default();
    super::query::resolve_time(text, None, now_ns).map_err(|_| {
        format!("`search --since` 的值 `{text}` 无效；请输入 `10m` 或 `2026-10-11T09:00:00+08:00`")
    })
}
