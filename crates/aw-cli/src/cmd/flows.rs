//! `aw flows <S> [--group-by domain|ip|proc|port] [--sort up|down|total]` (P1-CLI-03).
//!
//! Grouped byte totals use the same rule as `aw-store`: `None + None = None`,
//! and a known side plus an unknown side keeps the known side. Unknown is not
//! zero, so a group total can equal the sum of the member flows.

use std::io;

use crate::exit;
use crate::output::OutputMode;

use super::query::QuerySource;
use super::render;
use super::sessions::{query_outcome, write_ok};
use super::Outcome;

/// Render flows.
///
/// # Errors
///
/// A failure to format the outcome.
pub(crate) fn run(
    session: &str,
    filter: Option<&str>,
    group_by: Option<&str>,
    sort: Option<&str>,
    json: bool,
    source: &dyn QuerySource,
) -> io::Result<Outcome> {
    if session.trim().is_empty() {
        return Ok(super::error_outcome(
            exit::USAGE,
            "usage",
            "会话不能为空",
            json,
        ));
    }
    let mode = OutputMode::from_json_flag(json);
    match source.flows(session, filter, group_by, sort) {
        Ok(rows) => {
            let table = render::flows_table(&rows);
            let doc = render::flows_json(&rows);
            write_ok(mode, &table, &doc)
        }
        Err(err) => Ok(query_outcome(err, json)),
    }
}
