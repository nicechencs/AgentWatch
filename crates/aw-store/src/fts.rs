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

/// Index a source row that was inserted in this same transaction.
///
/// `src_id` is UNINDEXED in fts5, so [`delete`] (and therefore [`upsert`]) is a
/// full scan of `fts_text`: about 65 ms per call on a 200 MB database, and a
/// whole-machine sampling batch of ~430 rows held the write lock for 16-25 s.
/// A row the caller has just inserted (`changes() == 1`) cannot have an FTS row
/// yet: the `BEFORE DELETE` triggers drop the FTS row whenever a source row
/// goes away. So this inserts directly, with no delete. Use [`upsert`] only
/// when an existing source row's indexed text may have changed.
pub fn insert_new(
    conn: &Connection,
    mode: FtsMode,
    source: FtsSource,
    src_id: i64,
    text: Option<&str>,
) -> Result<(), StoreError> {
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

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::{insert_new, upsert, FtsMode, FtsSource};
    use rusqlite::{params, Connection};

    fn conn() -> Connection {
        let conn = Connection::open_in_memory().expect("memory db");
        conn.execute_batch(
            "CREATE VIRTUAL TABLE fts_text USING fts5(src, src_id UNINDEXED, body, tokenize = 'trigram');",
        )
        .expect("fts table");
        conn
    }

    fn hits(conn: &Connection, needle: &str) -> Vec<(String, i64)> {
        let mut stmt = conn
            .prepare("SELECT src, src_id FROM fts_text WHERE fts_text MATCH ?1 ORDER BY src_id")
            .expect("prepare");
        stmt.query_map(params![super::match_query(needle)], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .expect("query")
        .collect::<Result<_, _>>()
        .expect("rows")
    }

    /// A freshly inserted source row is indexed without touching any other
    /// FTS row (no delete-then-insert), and the text is searchable.
    #[test]
    fn insert_new_indexes_without_deleting_other_rows() {
        let conn = conn();
        insert_new(
            &conn,
            FtsMode::On,
            FtsSource::ProcessImage,
            1,
            Some("/usr/bin/python3 a.py"),
        )
        .expect("first");
        insert_new(
            &conn,
            FtsMode::On,
            FtsSource::FileAccess,
            1,
            Some("/home/u/python3.txt"),
        )
        .expect("other source, same id");
        insert_new(
            &conn,
            FtsMode::On,
            FtsSource::ProcessImage,
            2,
            Some("/usr/bin/python3 b.py"),
        )
        .expect("second");
        let mut found = hits(&conn, "python3");
        found.sort();
        assert_eq!(
            found,
            vec![
                ("file_access".to_owned(), 1),
                ("process_images".to_owned(), 1),
                ("process_images".to_owned(), 2),
            ]
        );
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM fts_text", [], |row| row.get(0))
            .expect("count");
        assert_eq!(count, 3);
    }

    #[test]
    fn insert_new_skips_off_mode_and_empty_text() {
        let conn = conn();
        insert_new(
            &conn,
            FtsMode::Off,
            FtsSource::ProcessImage,
            1,
            Some("sleep"),
        )
        .expect("off");
        insert_new(&conn, FtsMode::On, FtsSource::ProcessImage, 2, Some("")).expect("empty");
        insert_new(&conn, FtsMode::On, FtsSource::ProcessImage, 3, None).expect("none");
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM fts_text", [], |row| row.get(0))
            .expect("count");
        assert_eq!(count, 0);
    }

    /// `upsert` still replaces an existing row's text (the rename path).
    #[test]
    fn upsert_still_replaces_changed_text() {
        let conn = conn();
        insert_new(
            &conn,
            FtsMode::On,
            FtsSource::FileAccess,
            7,
            Some("/tmp/old-name"),
        )
        .expect("insert");
        upsert(
            &conn,
            FtsMode::On,
            FtsSource::FileAccess,
            7,
            Some("/tmp/new-name"),
        )
        .expect("upsert");
        assert!(hits(&conn, "old-name").is_empty());
        assert_eq!(hits(&conn, "new-name"), vec![("file_access".to_owned(), 7)]);
    }
}
