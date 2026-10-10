//! `aw procs <S> [--tree]` (P1-CLI-03).
//!
//! The command line column is the pipeline's redacted placeholder. P1 redaction
//! is itself a placeholder, so every row is labeled `P1 脱敏为占位`. Raw argv
//! is not stored on [`super::query::ProcItem`] and is not printed.

use std::io;

use crate::exit;
use crate::output::OutputMode;

use super::query::QuerySource;
use super::render;
use super::sessions::{query_outcome, write_ok};
use super::Outcome;

/// Render the process list or tree.
///
/// # Errors
///
/// A failure to format the outcome.
pub(crate) fn run(
    session: &str,
    tree: bool,
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
    match source.procs(session, tree) {
        Ok(nodes) => {
            let table = render::procs_table(&nodes, tree);
            let doc = render::procs_json(&nodes, tree);
            write_ok(mode, &table, &doc)
        }
        Err(err) => Ok(query_outcome(err, json)),
    }
}
