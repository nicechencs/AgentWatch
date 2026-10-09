-- P5-AGENT-02. E3 self-reports (storage.md timeline branch `agent`).
--
-- One row is a bounded tool-call summary. Columns are the structured fields
-- the adapter is allowed to keep: tool, phase, call id, and command / path /
-- url / query. A prompt, a model completion, a file body, an HTTP body, and
-- the values of Authorization or Cookie are not columns and must not be
-- written into summary_json.
--
-- A field that was not observed is NULL. There is no default of '' or 0:
-- either would mean "unknown". field_evidence is JSON (storage.md §2) and is
-- NULL when every present field shares the row's evidence. na_reason is NULL
-- unless evidence is NA.
--
-- session_id has no foreign key. A self-report can arrive before the session
-- row, and an unknown session is NULL rather than 0. The writer looks the
-- integer id up; a miss stays NULL and is named in na_reason.
--
-- schema_version is written by the migrator, not by this file.

CREATE TABLE agent_events (
  id              INTEGER PRIMARY KEY,
  session_id      INTEGER,
  ts_ns           INTEGER NOT NULL,
  agent           TEXT NOT NULL,
  tool            TEXT,
  phase           TEXT,
  call_id         TEXT,
  command         TEXT,
  path            TEXT,
  url             TEXT,
  query           TEXT,
  summary_json    TEXT,
  evidence        TEXT NOT NULL,
  source          TEXT NOT NULL,
  field_evidence  TEXT,
  na_reason       TEXT
);
CREATE INDEX idx_agent_events_session_ts ON agent_events(session_id, ts_ns);
CREATE INDEX idx_agent_events_call ON agent_events(call_id);
