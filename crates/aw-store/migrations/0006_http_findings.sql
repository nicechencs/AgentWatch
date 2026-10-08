-- P3-STORE-01. http and findings (storage.md §3).
--
-- Neither table is in 0001_init.sql (that file's header lists them as later
-- phases). This script creates them. It does not ALTER any table from
-- 0001–0005, and it does not DROP or CREATE the timeline view.
--
-- The view rebuild that adds the 'http' and 'finding' branches lives in
-- 0007_timeline_http.sql. Splitting it keeps this script runnable on a
-- database that does not have file_access yet: the view still reads that
-- table, so rebuilding it here would fail.
--
-- findings.user_state* are part of this CREATE, not a follow-up ALTER.
-- The CHECK values are 'confirmed' and 'ignored' (ui.md §3.8, P3-STORE-01).
-- storage.md §3 still said 'open' / 'acknowledged' / 'dismissed'; that line is
-- updated in the same change. NULL is "the user has not marked this row".
--
-- refs is a JSON array of {"table","id"} objects (storage.md §3). The writer
-- caps it at 50 entries. caveats is the same kind of JSON, or NULL when absent.
--
-- schema_version is written by the migrator, not by this file.
-- 0005 reserved fts_text.src = 'http'. This script does not add an FTS trigger;
-- the http writer inserts the URL row itself, matching file_access.

CREATE TABLE http (
  id              INTEGER PRIMARY KEY,
  session_id      INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  proc_uid        INTEGER,
  flow_id         INTEGER REFERENCES net_flows(id) ON DELETE SET NULL,
  ts_ns           INTEGER NOT NULL,
  method          TEXT NOT NULL,
  url             TEXT NOT NULL,
  host            TEXT NOT NULL,
  http_version    TEXT,
  status          INTEGER,
  req_headers     TEXT,
  resp_headers    TEXT,
  req_body_bytes  INTEGER,
  resp_body_bytes INTEGER,
  content_type    TEXT,
  duration_ms     INTEGER,
  error           TEXT,
  evidence        TEXT NOT NULL,
  source          TEXT NOT NULL
);
CREATE INDEX idx_http_session_ts ON http(session_id, ts_ns);
CREATE INDEX idx_http_host       ON http(host);

CREATE TABLE findings (
  id              INTEGER PRIMARY KEY,
  session_id      INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  rule_id         TEXT NOT NULL,
  rule_version    INTEGER NOT NULL,
  kind            TEXT NOT NULL,
  evidence        TEXT NOT NULL,
  severity        TEXT NOT NULL,
  wording_id      TEXT NOT NULL,
  params          TEXT NOT NULL,
  first_ns        INTEGER NOT NULL,
  last_ns         INTEGER NOT NULL,
  count           INTEGER NOT NULL DEFAULT 1,
  dedup_key       TEXT NOT NULL,
  refs            TEXT NOT NULL,
  caveats         TEXT,
  user_state      TEXT CHECK (user_state IN ('confirmed','ignored')),
  user_state_by   TEXT,
  user_state_ns   INTEGER,
  UNIQUE (session_id, rule_id, dedup_key)
);
CREATE INDEX idx_find_session ON findings(session_id, first_ns);
