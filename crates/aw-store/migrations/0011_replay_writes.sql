-- Replay markers for bounded writer chunks.
--
-- A delivery can commit one 500-row transaction and then fail in a later
-- transaction.  Retrying the original delivery must not apply the committed
-- rows a second time: some row writers intentionally merge counters.  The
-- marker key is a deterministic hash of the complete already-redacted row;
-- it is never random or based on write time.
--
-- This is deliberately a side table rather than a new column on every event
-- table.  It covers the P1 batch writer without changing historical records.

CREATE TABLE replay_writes (
  table_name  TEXT NOT NULL,
  row_key     TEXT NOT NULL,
  -- Lets retention discard markers with the session they protect. NULL is a
  -- global gap marker, whose lifetime is not tied to a session.
  session_id  INTEGER,
  PRIMARY KEY (table_name, row_key)
) WITHOUT ROWID;

CREATE INDEX replay_writes_session_idx ON replay_writes(session_id);
