//! `aw around <SESSION> <TABLE>:<ID> [--window 10s]` (P2-CLI-01).
//!
//! The window defaults to 10 seconds on either side of the named record.
//! The live route is `GET /api/v1/sessions/{sid}/around?ref=<table>:<id>&window=<dur>`.
//! [`super::query::around_request`] builds that call. This command does not
//! open the database and does not color a non-TTY.

use std::io;

use crate::exit;
use crate::output::OutputMode;

use super::query::{split_reference, AroundQuery, QuerySource};
use super::render;
use super::sessions::{query_outcome, write_ok};
use super::Outcome;

/// Default `--window` when the flag is omitted: 10 seconds.
const DEFAULT_WINDOW: &str = "10s";

/// Parsed `aw around` arguments.
pub(crate) struct AroundArgs<'a> {
    /// `<SESSION>`.
    pub session: &'a str,
    /// `<TABLE>:<ID>`.
    pub reference: &'a str,
    /// `--window`, raw text. `None` means [`DEFAULT_WINDOW`].
    pub window: Option<&'a str>,
    /// `--json`.
    pub json: bool,
    /// Color a sensitive neighbour. Production passes `false`.
    pub color: bool,
}

/// Render the events around one record.
///
/// # Errors
///
/// A failure to format the outcome.
pub(crate) fn run(args: AroundArgs<'_>, source: &dyn QuerySource) -> io::Result<Outcome> {
    if args.session.trim().is_empty() {
        return Ok(super::error_outcome(
            exit::USAGE,
            "usage",
            "会话不能为空",
            args.json,
        ));
    }
    if let Err(err) = split_reference(args.reference) {
        return Ok(query_outcome(err, args.json));
    }
    let window_text = args.window.unwrap_or(DEFAULT_WINDOW);
    let window_ns = match window_ns(window_text) {
        Ok(ns) => ns,
        Err(detail) => {
            return Ok(super::error_outcome(
                exit::USAGE,
                "usage",
                &detail,
                args.json,
            ));
        }
    };
    let query = AroundQuery {
        reference: args.reference.to_owned(),
        window_ns,
    };
    let _request = super::query::around_request(args.session, args.reference, window_text);
    let mode = OutputMode::from_json_flag(args.json);
    match source.around(args.session, &query) {
        Ok(page) => {
            let table = render::around_table(&page.rows, args.color);
            let doc = render::around_json(&page.rows);
            write_ok(mode, &table, &doc)
        }
        Err(err) => Ok(query_outcome(err, args.json)),
    }
}

/// `--window` is a duration (`10s`, `500ms`). An absolute time is refused:
/// the window is a width, not an instant.
fn window_ns(text: &str) -> Result<i64, String> {
    let arg = crate::output::parse_time(text)?;
    let duration = match arg {
        crate::output::TimeArg::BeforeNow(duration) => duration,
        crate::output::TimeArg::FromSessionStart(_) => {
            return Err("`--window` 必须是 10s 这样的时长，不能是相对会话的时间".to_owned());
        }
        crate::output::TimeArg::Rfc3339(_) => {
            return Err("`--window` 必须是 10s 这样的时长，不能是绝对时间".to_owned());
        }
    };
    let count = i64::try_from(duration.count).map_err(|_| "窗口时长超出 i64 范围".to_owned())?;
    let unit: i64 = match duration.unit {
        crate::output::TimeUnit::Millis => 1_000_000,
        crate::output::TimeUnit::Seconds => 1_000_000_000,
        crate::output::TimeUnit::Minutes => 60 * 1_000_000_000,
        crate::output::TimeUnit::Hours => 3_600 * 1_000_000_000,
        crate::output::TimeUnit::Days => 86_400 * 1_000_000_000,
    };
    count
        .checked_mul(unit)
        .ok_or_else(|| "窗口时长换算为纳秒时溢出".to_owned())
}
