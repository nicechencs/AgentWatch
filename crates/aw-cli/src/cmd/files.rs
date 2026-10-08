//! `aw files <SESSION> [--filter] [--group-by path|dir|proc] [--sort]` (P2-CLI-01).
//!
//! Records come from a [`QuerySource`]. The live daemon route
//! `GET /api/v1/sessions/{sid}/files` is not dialed here: [`super::query::files_request`]
//! builds that call for the client that will own the socket. Missing byte
//! columns render as `n/a`, never `0`. Each row keeps an evidence column.
//! A sensitive-path hit is highlighted only when the caller sets `color`
//! (a TTY). This command does not open the database.

use std::io;

use crate::exit;
use crate::output::OutputMode;

use super::query::{FileQuery, QuerySource};
use super::render;
use super::sessions::{query_outcome, write_ok};
use super::Outcome;

/// Parsed `aw files` arguments.
pub(crate) struct FilesArgs<'a> {
    /// `<SESSION>`: public id, name, or `@last`.
    pub session: &'a str,
    /// `--filter`. Forwarded; not compiled in the CLI.
    pub filter: Option<&'a str>,
    /// `--group-by path|dir|proc`.
    pub group_by: Option<&'a str>,
    /// `--sort`.
    pub sort: Option<&'a str>,
    /// `--json`.
    pub json: bool,
    /// Color sensitive rows. Production passes `false` until a TTY check exists.
    pub color: bool,
}

/// Render file access for one session.
///
/// # Errors
///
/// A failure to format the outcome.
pub(crate) fn run(args: FilesArgs<'_>, source: &dyn QuerySource) -> io::Result<Outcome> {
    if args.session.trim().is_empty() {
        return Ok(super::error_outcome(
            exit::USAGE,
            "usage",
            "session is empty",
            args.json,
        ));
    }
    if let Some(group_by) = args.group_by {
        if !matches!(group_by, "path" | "dir" | "proc") {
            return Ok(super::error_outcome(
                exit::USAGE,
                "usage",
                &format!("--group-by `{group_by}` is not path, dir, or proc"),
                args.json,
            ));
        }
    }
    if let Some(sort) = args.sort {
        if !matches!(
            sort,
            "time" | "path" | "opens" | "bytes_read" | "bytes_written" | "read" | "write"
        ) {
            return Ok(super::error_outcome(
                exit::USAGE,
                "usage",
                &format!(
                    "--sort `{sort}` is not time, path, opens, bytes_read, or bytes_written"
                ),
                args.json,
            ));
        }
    }
    let query = FileQuery {
        filter: args.filter.map(str::to_owned),
        group_by: args.group_by.map(str::to_owned),
        sort: args.sort.map(str::to_owned),
    };
    // The request is built so a wired client sends exactly the documented query.
    // The source, not this function, performs the lookup.
    let _request = super::query::files_request(args.session, &query);
    let mode = OutputMode::from_json_flag(args.json);
    match source.files(args.session, &query) {
        Ok(rows) => {
            let table = render::files_table(&rows, args.color);
            let doc = render::files_json(&rows);
            write_ok(mode, &table, &doc)
        }
        Err(err) => Ok(query_outcome(err, args.json)),
    }
}
