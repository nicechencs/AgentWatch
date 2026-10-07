//! JSONL export. The first line is the header. Later lines are records.
//!
//! [`write_jsonl_pages`] drops each [`Page`] before it asks for the next one,
//! so a source that hands out one page at a time never has two pages alive
//! inside the writer.

use std::io::Write;

use rusqlite::Connection;

use crate::export::records::{self, GapsSummary, PageSource, SessionHeader};
use crate::export::source::{self, SqlitePages};
use crate::export::{io_err, ExportError, ExportOptions, Redact};

/// Write one session as JSONL into `out`.
pub fn write_jsonl<W: Write>(
    conn: &Connection,
    options: &ExportOptions<'_>,
    out: &mut W,
) -> Result<u64, ExportError> {
    let loaded = source::load_session(conn, options)?;
    let mut pages = SqlitePages::new(conn, options, loaded.header.started_ns)?;
    write_jsonl_pages(&loaded.header, &loaded.gaps, &mut pages, loaded.redact, out)
}

/// Write `header` and then every page from `source`.
///
/// Returns the number of record lines, not counting the header. The header is
/// not redacted. Record fields are redacted according to `redact`.
pub fn write_jsonl_pages<W: Write>(
    header: &SessionHeader,
    gaps: &GapsSummary,
    source: &mut dyn PageSource,
    redact: Redact,
    out: &mut W,
) -> Result<u64, ExportError> {
    records::write_header(out, header, gaps)?;
    let mut count = 0_u64;
    while let Some(page) = source.next_page()? {
        for record in &page.records {
            records::write_record(out, record, redact)?;
            count = count.saturating_add(1);
        }
        drop(page);
    }
    out.flush().map_err(|err| io_err("write_jsonl", err))?;
    Ok(count)
}
