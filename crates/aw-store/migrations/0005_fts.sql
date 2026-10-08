-- P2-STORE-01. FTS5 trigram index over path, argv, and URL (storage.md §3.2).
--
-- The virtual table is external-content. `content` names no table: this crate
-- inserts the row itself, because the indexed text is a projection (path, or
-- path || path_to, or argv, or url) and not one source column. `content=''`
-- keeps the index from storing a second copy of the text.
--
-- Columns:
--   src    'file_access' | 'process_images' | 'http'
--   src_id the source row id (file_access.id, process_images.id, http.id)
--   body   already-redacted text. This script never reads a pre-redaction value;
--          the writer only inserts what it was given.
--
-- `http` does not exist yet (P3). The src value is reserved so a later writer
-- can insert URL rows without another FTS migration. No trigger references http.
--
-- Cascading cleanup (task card: deleting a session removes its FTS rows):
--   * file_access.id is stable across the partial UPSERT, so an UPDATE of the
--     source row does not touch FTS. The writer deletes and reinserts the FTS
--     row when the indexed text changes.
--   * BEFORE DELETE on file_access / process_images drops the matching FTS rows.
--     Session deletion reaches those tables through ON DELETE CASCADE, which
--     fires the trigger. A direct DELETE does too.
--
-- tokenize = 'trigram' is the bundled SQLite build (3.45+). No extra extension.
-- The index is created here and left in place. `storage.fts = false` is a
-- writer flag (see fts.rs): the table still exists, and the writer skips inserts.
-- Dropping it would be a schema change this migration does not make.

CREATE VIRTUAL TABLE fts_text USING fts5(
  src,
  src_id UNINDEXED,
  body,
  tokenize = 'trigram'
);

CREATE TRIGGER fts_text_delete_file_access
BEFORE DELETE ON file_access
BEGIN
  DELETE FROM fts_text WHERE src = 'file_access' AND src_id = OLD.id;
END;

CREATE TRIGGER fts_text_delete_process_images
BEFORE DELETE ON process_images
BEGIN
  DELETE FROM fts_text WHERE src = 'process_images' AND src_id = OLD.id;
END;
