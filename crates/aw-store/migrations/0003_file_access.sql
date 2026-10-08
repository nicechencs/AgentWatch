-- P2-STORE-01. file_access and its four indexes (storage.md §3).
--
-- Does not ALTER any table created by 0001_init.sql. The timeline view is
-- rebuilt by 0004_timeline_file.sql, in the same open, after this script.
-- schema_version is written by the migrator, not by this file.
--
-- NULL means "not observed". reads / bytes_read / bytes_written / result have
-- no DEFAULT 0. partial defaults to 0 because the DDL says the row is final
-- unless the writer marks an intermediate snapshot.

CREATE TABLE file_access (
  id              INTEGER PRIMARY KEY,
  session_id      INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  proc_uid        INTEGER NOT NULL,
  op              TEXT NOT NULL CHECK (op IN ('access','create','delete','rename','exec')),
  path            TEXT NOT NULL,
  path_to         TEXT,
  access          TEXT,
  first_ns        INTEGER NOT NULL,
  last_ns         INTEGER NOT NULL,
  opens           INTEGER NOT NULL DEFAULT 1,
  reads           INTEGER,
  bytes_read      INTEGER,
  writes          INTEGER,
  bytes_written   INTEGER,
  created         INTEGER,
  truncated       INTEGER,
  modified        INTEGER,
  result          INTEGER,
  partial         INTEGER NOT NULL DEFAULT 0,
  sensitive_rule  TEXT,
  evidence        TEXT NOT NULL,
  na_reason       TEXT,
  field_evidence  TEXT,
  source          TEXT NOT NULL
);
CREATE INDEX idx_fa_session_ts ON file_access(session_id, first_ns);
CREATE INDEX idx_fa_proc       ON file_access(session_id, proc_uid, first_ns);
CREATE INDEX idx_fa_path       ON file_access(path);
CREATE INDEX idx_fa_sensitive  ON file_access(session_id, sensitive_rule) WHERE sensitive_rule IS NOT NULL;
