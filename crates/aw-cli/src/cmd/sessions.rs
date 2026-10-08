//! `aw sessions list|show|rename|pin|unpin|delete` (P1-CLI-03).
//!
//! Records come from a [`QuerySource`]. The live daemon is not queried: its
//! session routes are still a stub.

use std::io;

use serde_json::json;

use crate::exit;
use crate::output::OutputMode;

use super::query::{QueryError, QuerySource, SessionQuery};
use super::render::{self, mutation_json};
use super::tree::SessionsCmd;
use super::Outcome;

/// Run one `sessions` subcommand.
///
/// # Errors
///
/// A failure to format the outcome. The process code is [`Outcome::code`].
pub(crate) fn run(
    cmd: &SessionsCmd,
    json: bool,
    source: &mut dyn QuerySource,
) -> io::Result<Outcome> {
    let mode = OutputMode::from_json_flag(json);
    match cmd {
        SessionsCmd::List {
            since,
            agent,
            active,
            limit,
        } => list(
            since.as_deref(),
            agent.clone(),
            *active,
            *limit,
            mode,
            source,
        ),
        SessionsCmd::Show { session } => show(session, mode, source),
        SessionsCmd::Rename { session, name } => rename(session, name, mode, source),
        SessionsCmd::Pin { session } => pin(session, true, mode, source),
        SessionsCmd::Unpin { session } => pin(session, false, mode, source),
        SessionsCmd::Delete { sessions, yes } => delete(sessions, *yes, mode, source),
    }
}

fn list(
    since: Option<&str>,
    agent: Option<String>,
    active: bool,
    limit: Option<u64>,
    mode: OutputMode,
    source: &dyn QuerySource,
) -> io::Result<Outcome> {
    let since_ns = match since {
        Some(text) => match super::query::resolve_time(text, None, 0) {
            Ok(ns) => Some(ns),
            Err(detail) => {
                return Ok(super::error_outcome(
                    exit::USAGE,
                    "usage",
                    &detail,
                    mode == OutputMode::Json,
                ));
            }
        },
        None => None,
    };
    // `--since -10m` is relative to now. This card has no clock injection on the
    // list path beyond `resolve_time(..., now_ns = 0)` for RFC 3339 and `+`.
    // A relative-to-now form cannot be anchored, so refuse it instead of using 0.
    if let Some(text) = since {
        if text.trim().starts_with('-') {
            return Ok(super::error_outcome(
                exit::USAGE,
                "usage",
                "`sessions list --since` relative-to-now (-10m) needs a clock this build does not have; pass RFC 3339",
                mode == OutputMode::Json,
            ));
        }
    }
    let query = SessionQuery {
        agent,
        active_only: active,
        since_ns,
        limit,
    };
    match source.list_sessions(&query) {
        Ok(items) => {
            let table = render::session_table(&items);
            let doc = render::session_json(&items);
            Ok(write_ok(mode, &table, &doc)?)
        }
        Err(err) => Ok(query_outcome(err, mode == OutputMode::Json)),
    }
}

fn show(session: &str, mode: OutputMode, source: &dyn QuerySource) -> io::Result<Outcome> {
    match source.show_session(session) {
        Ok(shown) => {
            let table = render::show_table(&shown);
            let doc = render::show_json(&shown);
            Ok(write_ok(mode, &table, &doc)?)
        }
        Err(err) => Ok(query_outcome(err, mode == OutputMode::Json)),
    }
}

fn rename(
    session: &str,
    name: &str,
    mode: OutputMode,
    source: &mut dyn QuerySource,
) -> io::Result<Outcome> {
    if name.trim().is_empty() {
        return Ok(super::error_outcome(
            exit::USAGE,
            "usage",
            "session name is empty",
            mode == OutputMode::Json,
        ));
    }
    match source.rename_session(session, name) {
        Ok(item) => {
            let doc = mutation_json("rename", &render::session_json(std::slice::from_ref(&item)));
            let table = render::session_table(std::slice::from_ref(&item));
            Ok(write_ok(mode, &table, &doc)?)
        }
        Err(err) => Ok(query_outcome(err, mode == OutputMode::Json)),
    }
}

fn pin(
    session: &str,
    pinned: bool,
    mode: OutputMode,
    source: &mut dyn QuerySource,
) -> io::Result<Outcome> {
    match source.set_pinned(session, pinned) {
        Ok(item) => {
            let action = if pinned { "pin" } else { "unpin" };
            let doc = mutation_json(
                action,
                &json!({ "id": item.public_id, "pinned": item.pinned }),
            );
            let table = render::session_table(std::slice::from_ref(&item));
            Ok(write_ok(mode, &table, &doc)?)
        }
        Err(err) => Ok(query_outcome(err, mode == OutputMode::Json)),
    }
}

fn delete(
    sessions: &[String],
    yes: bool,
    mode: OutputMode,
    source: &mut dyn QuerySource,
) -> io::Result<Outcome> {
    if !yes {
        return Ok(super::error_outcome(
            exit::USAGE,
            "usage",
            "sessions delete refuses without --yes",
            mode == OutputMode::Json,
        ));
    }
    match source.delete_sessions(sessions) {
        Ok(removed) => {
            let doc = mutation_json("delete", &json!({ "removed": removed }));
            let table = crate::output::Table {
                headers: vec!["removed".to_owned()],
                rows: vec![crate::output::Row {
                    cells: vec![removed.to_string()],
                    evidence: aw_core::Evidence::E1,
                }],
            };
            Ok(write_ok(mode, &table, &doc)?)
        }
        Err(err) => Ok(query_outcome(err, mode == OutputMode::Json)),
    }
}

pub(crate) fn write_ok(
    mode: OutputMode,
    table: &crate::output::Table,
    doc: &serde_json::Value,
) -> io::Result<Outcome> {
    let mut stdout = Vec::new();
    render::write_out(&mut stdout, mode, table, doc)?;
    Ok(Outcome {
        code: exit::OK,
        stdout,
        stderr: Vec::new(),
    })
}

pub(crate) fn query_outcome(err: QueryError, json: bool) -> Outcome {
    let (code, machine) = match &err {
        QueryError::NotFound { .. } => (exit::GENERAL, "not_found"),
        QueryError::BadArgument { .. } => (exit::USAGE, "usage"),
        QueryError::Unavailable { .. } => (exit::GENERAL, "not_connected"),
    };
    super::error_outcome(code, machine, &err.to_string(), json)
}
