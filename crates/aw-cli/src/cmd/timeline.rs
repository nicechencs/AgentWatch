//! `aw timeline <S> [--filter --from --to --follow --limit]` (P1-CLI-03).
//!
//! `--follow` polls the daemon's bounded SSE snapshot endpoint.  That is the
//! same cursor protocol used by the App: every response contains records after
//! the last SSE `id`, then closes.  On Unix SIGINT/SIGTERM stop the poll loop
//! cleanly rather than leaving a terminal in a half-written state.

use std::io;
#[cfg(not(test))]
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

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
        return follow(key, args.filter, mode, args.color, source);
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
    filter: Option<&str>,
    mode: OutputMode,
    color: bool,
    source: &dyn QuerySource,
) -> io::Result<Outcome> {
    #[cfg(test)]
    {
        // Unit tests provide an in-memory source, not a daemon that can be
        // interrupted. The transport parser has its own multi-poll tests.
        follow_once(key, filter, mode, color, source)
    }
    #[cfg(not(test))]
    {
        let cancelled = interrupt_flag();
        let mut cursor = None;
        let mut collected = Vec::new();
        while !cancelled.load(Ordering::Relaxed) {
            match source.follow(key, filter, cursor) {
                Ok(rows) => {
                    if let Some(last) = rows.last() {
                        cursor = Some(last.id);
                    }
                    collected.extend(rows);
                }
                Err(err) => return Ok(query_outcome(err, mode == OutputMode::Json)),
            }
            // `/live` deliberately closes its snapshot promptly. Avoid a busy
            // reconnect loop while preserving the App's one-second cadence.
            std::thread::sleep(super::query::follow_poll_interval());
        }
        let table = render::timeline_table(&collected, color);
        let doc = render::timeline_json(&collected, true);
        write_ok(mode, &table, &doc)
    }
}

#[cfg(test)]
fn follow_once(
    key: &str,
    filter: Option<&str>,
    mode: OutputMode,
    color: bool,
    source: &dyn QuerySource,
) -> io::Result<Outcome> {
    match source.follow(key, filter, None) {
        Ok(rows) => {
            let table = render::timeline_table(&rows, color);
            let doc = render::timeline_json(&rows, true);
            write_ok(mode, &table, &doc)
        }
        Err(err) => Ok(query_outcome(err, mode == OutputMode::Json)),
    }
}

/// Receive terminal stop signals with `sigwait`, which needs no unsafe signal
/// handler. The calling thread blocks the two signals before the worker is
/// made; the worker turns either into a cooperative cancellation flag.
#[cfg(all(not(test), any(target_os = "linux", target_os = "macos")))]
fn interrupt_flag() -> Arc<AtomicBool> {
    use nix::sys::signal::{SigSet, Signal};

    let mut signals = SigSet::empty();
    signals.add(Signal::SIGINT);
    signals.add(Signal::SIGTERM);
    let stopped = Arc::new(AtomicBool::new(false));
    if signals.thread_block().is_ok() {
        let stop = Arc::clone(&stopped);
        let _ = std::thread::Builder::new()
            .name("aw-timeline-interrupt".to_owned())
            .spawn(move || {
                let _ = signals.wait();
                stop.store(true, Ordering::Relaxed);
            });
    }
    stopped
}

#[cfg(all(not(test), not(any(target_os = "linux", target_os = "macos"))))]
fn interrupt_flag() -> Arc<AtomicBool> {
    // Windows has the console handler owned by the platform launcher. A normal
    // Ctrl-C still ends this foreground command; this flag is for the Unix
    // cooperative path above.
    Arc::new(AtomicBool::new(false))
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
