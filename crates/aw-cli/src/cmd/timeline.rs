//! `aw timeline <S> [--filter --from --to --follow --limit]` (P1-CLI-03).
//!
//! `--follow` renders the same lines a live subscription would. The daemon has
//! no `/sessions/{sid}/live` handler, so the production source returns
//! `not_connected` and says the real subscription is not wired (真实订阅未接通).
//! Tests inject a [`QuerySource`] and check the rendered gap marker and evidence
//! column. The NFR-05 delay (< 2 s) is not measured here.

use std::io;

use crate::exit;
use crate::output::OutputMode;

use super::query::{QuerySource, TimelineBounds};
use super::render;
use super::sessions::{query_outcome, write_ok};
use super::Outcome;

/// Arguments already parsed by clap.
pub(crate) struct TimelineArgs<'a> {
    /// Public id, name, or `@last`.
    pub session: &'a str,
    /// Filter text. Substring on the summary in the memory source.
    pub filter: Option<&'a str>,
    /// `--from`.
    pub from: Option<&'a str>,
    /// `--to`.
    pub to: Option<&'a str>,
    /// Subscribe. See the module comment.
    pub follow: bool,
    /// Page size.
    pub limit: Option<u64>,
    /// JSON mode.
    pub json: bool,
    /// ANSI red on gap lines. Tests pass `false` so snapshots stay stable.
    pub color: bool,
}

/// Render one timeline page, or the follow buffer when `follow` is set.
///
/// # Errors
///
/// A failure to format the outcome.
pub(crate) fn run(args: TimelineArgs<'_>, source: &dyn QuerySource) -> io::Result<Outcome> {
    let mode = OutputMode::from_json_flag(args.json);
    let key = match crate::output::parse_session(args.session) {
        Ok(crate::output::SessionRef::Last) => "@last",
        Ok(crate::output::SessionRef::IdOrName(name)) => {
            // Re-borrow: `name` is owned. Fall through with the original text.
            let _ = name;
            args.session
        }
        Err(detail) => {
            return Ok(super::error_outcome(
                exit::USAGE,
                "usage",
                &detail,
                args.json,
            ));
        }
    };
    let key = if args.session.trim() == "@last" {
        "@last"
    } else {
        key
    };

    if args.follow {
        return follow(key, mode, args.color, source);
    }

    let started = source
        .show_session(key)
        .ok()
        .and_then(|shown| shown.item.started_ns);
    let from_ns = match resolve(args.from, started, args.json) {
        Ok(value) => value,
        Err(outcome) => return Ok(outcome),
    };
    let to_ns = match resolve(args.to, started, args.json) {
        Ok(value) => value,
        Err(outcome) => return Ok(outcome),
    };
    let bounds = TimelineBounds {
        filter: args.filter.map(str::to_owned),
        from_ns,
        to_ns,
        limit: args.limit,
    };
    match source.timeline(key, &bounds) {
        Ok(page) => {
            let table = render::timeline_table(&page.rows, args.color);
            let doc = render::timeline_json(&page.rows, false);
            write_ok(mode, &table, &doc)
        }
        Err(err) => Ok(query_outcome(err, args.json)),
    }
}

fn follow(
    key: &str,
    mode: OutputMode,
    color: bool,
    source: &dyn QuerySource,
) -> io::Result<Outcome> {
    // One poll of the injected source. A live daemon would loop; this build
    // does not, because `/live` is not connected. The poll interval is recorded
    // so a later card can stay under the 2 s bound.
    let _interval = super::query::follow_poll_interval();
    match source.follow(key, None) {
        Ok(rows) => {
            let table = render::timeline_table(&rows, color);
            let doc = render::timeline_json(&rows, false);
            write_ok(mode, &table, &doc)
        }
        Err(err) => Ok(query_outcome(err, mode == OutputMode::Json)),
    }
}

fn resolve(text: Option<&str>, started: Option<i64>, json: bool) -> Result<Option<i64>, Outcome> {
    let Some(text) = text else {
        return Ok(None);
    };
    if text.trim().starts_with('-') {
        return Err(super::error_outcome(
            exit::USAGE,
            "usage",
            "`--from`/`--to` 的相对当前时间（-10m）需要此构建没有的时钟；请传入 RFC 3339 或 +30s",
            json,
        ));
    }
    match super::query::resolve_time(text, started, 0) {
        Ok(ns) => Ok(Some(ns)),
        Err(detail) => Err(super::error_outcome(exit::USAGE, "usage", &detail, json)),
    }
}
