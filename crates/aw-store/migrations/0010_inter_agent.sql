-- P6-STORE-01. Inter-agent tables (inter-agent-communication §7, storage.md §3).
--
-- 0001_init.sql deferred these: watch_groups, agent_instances, ipc_channels,
-- agent_rpc, agent_links, and sessions.group_id. This script creates them.
-- It does not rewrite 0001–0009 and it does not rebuild the timeline view.
--
-- Order matters: watch_groups exists before sessions.group_id references it.
-- SQLite checks that reference when the ALTER runs (foreign_keys=ON).
--
-- A column that was not observed is NULL. Byte counts are NULL until a probe
-- reports them. 0 is a measured zero, not a stand-in for "unknown".
-- role and profile are NULL when the instance was not classified.
-- agent_rpc stores method and evidence only. Arguments, results, and bodies
-- are not columns.
--
-- agent_links.session_id and agent_links.group_id have no foreign key: a link
-- can cross sessions, and deleting a group must not be ordered by this table
-- (storage.md §2). agent_rpc.session_id is present so a row can be filtered
-- without joining; the session still comes from the channel.
--
-- schema_version is written by the migrator, not by this file.

CREATE TABLE watch_groups (
  id            INTEGER PRIMARY KEY,
  public_id     TEXT NOT NULL UNIQUE,
  user_id       TEXT NOT NULL,
  name          TEXT NOT NULL,
  created_ns    INTEGER NOT NULL
);

ALTER TABLE sessions ADD COLUMN group_id INTEGER REFERENCES watch_groups(id);
CREATE INDEX idx_sessions_group ON sessions(group_id);

CREATE TABLE agent_instances (
  id                  INTEGER PRIMARY KEY,
  session_id          INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  proc_uid            INTEGER NOT NULL,
  profile_id          TEXT,
  role                TEXT,
  parent_instance_id  INTEGER REFERENCES agent_instances(id),
  evidence            TEXT NOT NULL,
  source              TEXT NOT NULL
);
CREATE INDEX idx_agent_instances_session ON agent_instances(session_id);

CREATE TABLE ipc_channels (
  id            INTEGER PRIMARY KEY,
  session_id    INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  kind          TEXT NOT NULL,
  endpoint_a    TEXT,
  endpoint_b    TEXT,
  bytes_a_to_b  INTEGER,
  bytes_b_to_a  INTEGER,
  evidence      TEXT NOT NULL,
  source        TEXT NOT NULL
);
CREATE INDEX idx_ipc_channels_session ON ipc_channels(session_id);

CREATE TABLE agent_rpc (
  id            INTEGER PRIMARY KEY,
  session_id    INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  channel_id    INTEGER REFERENCES ipc_channels(id) ON DELETE CASCADE,
  method        TEXT,
  evidence      TEXT NOT NULL,
  source        TEXT NOT NULL
);
CREATE INDEX idx_agent_rpc_session ON agent_rpc(session_id);

CREATE TABLE agent_links (
  id            INTEGER PRIMARY KEY,
  session_id    INTEGER NOT NULL,
  from_instance INTEGER NOT NULL REFERENCES agent_instances(id),
  to_instance   INTEGER REFERENCES agent_instances(id),
  channel_id    INTEGER REFERENCES ipc_channels(id),
  evidence      TEXT NOT NULL,
  source        TEXT NOT NULL
);
CREATE INDEX idx_agent_links_session ON agent_links(session_id);
