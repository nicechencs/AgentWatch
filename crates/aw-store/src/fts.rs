//! FTS5 trigram index over already-redacted path, argv, and URL text.
//!
//! storage.md §3.2. The virtual table is created by migration `0005_fts.sql`.
//! This module only inserts and deletes rows, and it only inserts text the
//! caller already stored. It does not read a pre-redaction value, and it does
//! not log the text.
//!
//! `storage.fts = false` ([`FtsMode::Off`]) skips the insert. The table stays,
//! so a later open with the flag on can index new rows. Existing rows are not
//! backfilled here: that would re-read every path, and the task does not ask
//! for a rebuild command.
//!
//! Session deletion does not call this module. `0005_fts.sql` installs
//! `BEFORE DELETE` triggers on `file_access` and `process_images`, and session
//! removal reaches those tables through `ON DELETE CASCADE`.

use rusqlite::{params, Connection, OptionalExtension};

use crate::error::StoreError;

/// `schema_meta` key for the `storage.fts` switch.
pub const META_FTS: &str = "storage.fts";

/// Whether new rows are added to `fts_text`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FtsMode {
    /// Insert a row for each indexed text. Default when the meta key is absent.
    On,
    /// Do not insert. Deletes still happen, so a session purge cannot leave
    /// FTS rows behind for source rows that were indexed earlier.
    Off,
}

impl FtsMode {
    /// `true` for [`FtsMode::On`].
    pub fn enabled(self) -> bool {
        matches!(self, Self::On)
    }
}

/// Which table a `fts_text` row points at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FtsSource {
    /// `file_access.path`, optionally with the rename target.
    FileAccess,
    /// `process_images.argv`.
    ProcessImage,
    /// Reserved for `http.url`. The `http` table is not created in P2.
    Http,
}

impl FtsSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::FileAccess => "file_access",
            Self::ProcessImage => "process_images",
            Self::Http => "http",
        }
    }
}

/// Read `storage.fts` from `schema_meta`.
///
/// Absent, `true`, `1`, and `on` are [`FtsMode::On`]. `false`, `0`, and `off`
/// are [`FtsMode::Off`]. Anything else is an error: a typo must not silently
/// disable the index or silently enable it.
pub fn read_mode(conn: &Connection) -> Result<FtsMode, StoreError> {
    let value: Option<String> = conn
        .query_row(
            "SELECT value FROM schema_meta WHERE key = ?1",
            params![META_FTS],
            |row| row.get(0),
        )
        .optional()
        .map_err(|err| StoreError::sqlite("read_fts_mode", err))?;
    match value.as_deref() {
        None => Ok(FtsMode::On),
        Some(text) => parse_mode(text),
    }
}

/// Write `storage.fts`. Does not rebuild or drop `fts_text`.
pub fn set_mode(conn: &Connection, mode: FtsMode) -> Result<(), StoreError> {
    let value = match mode {
        FtsMode::On => "true",
        FtsMode::Off => "false",
    };
    conn.execute(
        "INSERT INTO schema_meta (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![META_FTS, value],
    )
    .map_err(|err| StoreError::sqlite("set_fts_mode", err))?;
    Ok(())
}

/// Replace the FTS row for one source id.
///
/// `text` is what the writer stored (path, argv JSON, URL). `None` or `""`
/// deletes the FTS row and does not insert a placeholder: an empty string is
/// not a document. When `mode` is [`FtsMode::Off`] the previous row is still
/// deleted, and nothing is inserted.
pub fn upsert(
    conn: &Connection,
    mode: FtsMode,
    source: FtsSource,
    src_id: i64,
    text: Option<&str>,
) -> Result<(), StoreError> {
    delete(conn, source, src_id)?;
    if !mode.enabled() {
        return Ok(());
    }
    let Some(text) = text.filter(|text| !text.is_empty()) else {
        return Ok(());
    };
    conn.execute(
        "INSERT INTO fts_text (src, src_id, body) VALUES (?1, ?2, ?3)",
        params![source.as_str(), src_id, text],
    )
    .map_err(|err| StoreError::sqlite("fts_insert", err))?;
    Ok(())
}

/// Delete every FTS row for one source id. Used when the source row is removed
/// outside the trigger (the trigger covers `DELETE` on the source table).
pub fn delete(conn: &Connection, source: FtsSource, src_id: i64) -> Result<(), StoreError> {
    conn.execute(
        "DELETE FROM fts_text WHERE src = ?1 AND src_id = ?2",
        params![source.as_str(), src_id],
    )
    .map_err(|err| StoreError::sqlite("fts_delete", err))?;
    Ok(())
}

/// `MATCH` operand for a substring query.
///
/// FTS5 trigram query syntax treats `*` and `^` as operators. Wrapping the
/// whole string in double quotes makes it a phrase. Embedded quotes are
/// doubled, which is the FTS5 escape, and the result is still one bound
/// parameter: this function does not build SQL.
pub fn match_query(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for ch in text.chars() {
        if ch == '"' {
            out.push('"');
        }
        out.push(ch);
    }
    out.push('"');
    out
}

fn parse_mode(text: &str) -> Result<FtsMode, StoreError> {
    match text {
        "true" | "1" | "on" => Ok(FtsMode::On),
        "false" | "0" | "off" => Ok(FtsMode::Off),
        _ => Err(StoreError::BadSchemaVersion {
            found: Some(format!("storage.fts={text}")),
        }),
    }
}

