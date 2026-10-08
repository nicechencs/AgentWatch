//! Rows a degrade level must keep (P2-PIPE-04).
//!
//! The per-process token bucket remains [`crate::limits::Limiter`]. File and
//! network aggregators add byte counts before a degrade drop, so dropping a
//! detail row does not zero those counters. This module does not sample.

use crate::output::FileAccessRec;

/// Sensitive-path hits, deletes, and execs stay at every level.
pub fn file_row_protected(row: &FileAccessRec) -> bool {
    row.sensitive_rule.is_some() || row.op == "delete" || row.op == "exec"
}

/// A non-sensitive read-only `file_access`.
///
/// L2 and above keep a directory count instead of this row. Writes, creates,
/// and renames are not ordinary reads.
pub fn is_ordinary_read(row: &FileAccessRec) -> bool {
    if file_row_protected(row) || row.op != "access" {
        return false;
    }
    let wrote = matches!(row.access.as_deref(), Some("write") | Some("read_write"))
        || row.bytes_written.is_some()
        || row.writes.is_some_and(|count| count > 0);
    !wrote
}
