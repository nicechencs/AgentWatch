//! `aw search <TEXT> [--since] [--kind file|proc|url]` (P2-CLI-01).
//!
//! Cross-session search. The live route is `GET /api/v1/search?q&kind&since`.
//! [`super::query::search_request`] builds that call. This command does not
//! open the database. `--since -10m` needs a clock this production path does
//! not have, so that form is refused rather than treated as the epoch.
//! A sensitive hit is highlighted only when `color` is set.

use std::io;

use crate::exit;
use crate::output::OutputMode;

use super::query::{SearchQuery, QuerySource};
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
            "search text is empty",
            args.json,
        ));
    }
    if let Some(kind) = args.kind {
        if !matches!(kind, "file" | "proc" | "url") {
            return Ok(super::error_outcome(
                exit::USAGE,
                "usage",
                &format!("--kind `{kind}` is not file, proc, or url"),
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

/// RFC 3339 and `+30s` resolve. `-10m` does not: there is no clock on this path.
fn resolve_since(text: &str) -> Result<i64, String> {
    if text.trim().starts_with('-') || looks_bare_duration(text) {
        return Err(
            "`search --since` relative-to-now (-10m) needs a clock this build does not have; pass RFC 3339"
                .to_owned(),
        );
    }
    super::query::resolve_time(text, None, 0)
}

fn looks_bare_duration(text: &str) -> bool {
    let text = text.trim();
    !text.is_empty()
        && text
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_digit())
}
