//! `aw gaps <S>` (P1-CLI-03).
//!
//! A missing count stays `不可得`. It is not printed as `0`.

use std::io;

use crate::exit;
use crate::output::OutputMode;

use super::query::QuerySource;
use super::render;
use super::sessions::{query_outcome, write_ok};
use super::Outcome;

/// Render the gaps for one session.
///
/// # Errors
///
/// A failure to format the outcome.
pub(crate) fn run(session: &str, json: bool, source: &dyn QuerySource) -> io::Result<Outcome> {
    if session.trim().is_empty() {
        return Ok(super::error_outcome(
            exit::USAGE,
            "usage",
            "会话不能为空",
            json,
        ));
    }
    let mode = OutputMode::from_json_flag(json);
    match source.gaps(session) {
        Ok(rows) => {
            let table = render::gaps_table(&rows);
            let doc = render::gaps_json(&rows);
            write_ok(mode, &table, &doc)
        }
        Err(err) => Ok(query_outcome(err, json)),
    }
}
