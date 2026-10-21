-- P5-SEC-01. One row per deny / rewrite / ask / downgrade (ADR-0014).
--
-- before_summary and after_summary are already redacted and cut to 256
-- Unicode scalars by the caller. before_hash and after_hash are hex SHA-256
-- of (session salt || 0xff || original bytes). The original command, URL,
-- prompt, file body, and HTTP body are not columns and must not be written
-- into reason.
--
-- A field that was not observed is NULL. There is no default of '' or 0.
-- session_id has no foreign key: an intercept can arrive before the session
-- row, and an unknown session is NULL rather than 0.
--
-- delivered is daemon / local_backup / dropped. dropped means neither write
-- worked; the caller also inserts a gaps row with kind intercept_audit_dropped.
--
-- schema_version is written by the migrator, not by this file.

CREATE TABLE intercept_events (
  id                INTEGER PRIMARY KEY,
  session_id        INTEGER,
  ts_ns             INTEGER NOT NULL,
  agent             TEXT,
  layer             TEXT NOT NULL,
  event             TEXT,
  rule_id           TEXT,
  action            TEXT NOT NULL,
  effective_action  TEXT NOT NULL,
  tool              TEXT,
  host              TEXT,
  mcp_method        TEXT,
  before_summary    TEXT NOT NULL,
  before_hash       TEXT NOT NULL,
  after_summary     TEXT,
  after_hash        TEXT,
  reason            TEXT,
  evidence          TEXT NOT NULL,
  source            TEXT NOT NULL,
  delivered         TEXT NOT NULL,
  downgraded        INTEGER NOT NULL
);
CREATE INDEX idx_intercept_events_session_ts ON intercept_events(session_id, ts_ns);
