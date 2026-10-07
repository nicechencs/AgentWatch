-- P1 schema (storage.md §3). Tables that belong to later phases are not created here:
-- watch_groups, file_access, http, agent_events, findings, raw_events,
-- agent_instances, ipc_channels, agent_rpc, agent_links.
-- sessions.group_id is added by P6-STORE-01 together with watch_groups.
-- findings.user_state* are added by P3-STORE-01.
--
-- Initial schema_meta rows (schema_version, created_ns, app_version, host_id)
-- are inserted by the migrator in the same transaction. host_id is a random UUID,
-- not a hostname.

CREATE TABLE schema_meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE sessions (
  id              INTEGER PRIMARY KEY,
  public_id       TEXT NOT NULL UNIQUE,
  name            TEXT,
  mode            TEXT NOT NULL CHECK (mode IN ('launch','attach')),
  agent           TEXT,
  root_proc_uid   INTEGER,
  argv            TEXT,
  cwd             TEXT,
  user_id         TEXT NOT NULL,
  started_ns      INTEGER NOT NULL,
  ended_ns        INTEGER,
  end_reason      TEXT,
  exit_code       INTEGER,
  proxy_enabled   INTEGER NOT NULL DEFAULT 0,
  proxy_port      INTEGER,
  platform        TEXT NOT NULL,
  os_version      TEXT,
  collectors      TEXT NOT NULL,
  collector_profile TEXT,
  config_digest   TEXT,
  pinned          INTEGER NOT NULL DEFAULT 0,
  stats           TEXT
);
CREATE INDEX idx_sessions_started ON sessions(started_ns);

CREATE TABLE processes (
  session_id      INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  proc_uid        INTEGER NOT NULL,
  pid             INTEGER NOT NULL,
  parent_uid      INTEGER,
  ppid            INTEGER,
  depth           INTEGER NOT NULL DEFAULT 0,
  start_ns        INTEGER NOT NULL,
  exit_ns         INTEGER,
  exit_code       INTEGER,
  exit_signal     INTEGER,
  how             TEXT NOT NULL,
  user_id         TEXT,
  signer          TEXT,
  evidence        TEXT NOT NULL,
  field_evidence  TEXT,
  source          TEXT NOT NULL,
  agent           TEXT,
  PRIMARY KEY (session_id, proc_uid)
) WITHOUT ROWID;
CREATE INDEX idx_proc_parent ON processes(session_id, parent_uid);
CREATE INDEX idx_proc_pid    ON processes(session_id, pid);

CREATE TABLE process_images (
  id              INTEGER PRIMARY KEY,
  session_id      INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  proc_uid        INTEGER NOT NULL,
  seq             INTEGER NOT NULL,
  ts_ns           INTEGER NOT NULL,
  exe             TEXT,
  argv            TEXT,
  cwd             TEXT,
  env             TEXT,
  evidence        TEXT NOT NULL,
  field_evidence  TEXT,
  source          TEXT NOT NULL,
  UNIQUE (session_id, proc_uid, seq)
);
CREATE INDEX idx_img_ts  ON process_images(session_id, ts_ns);
CREATE INDEX idx_img_exe ON process_images(exe);

CREATE TABLE net_flows (
  id              INTEGER PRIMARY KEY,
  session_id      INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  proc_uid        INTEGER NOT NULL,
  proto           TEXT NOT NULL CHECK (proto IN ('tcp','udp')),
  direction       TEXT NOT NULL,
  local_ip        TEXT NOT NULL,
  local_port      INTEGER NOT NULL,
  remote_ip       TEXT NOT NULL,
  remote_port     INTEGER NOT NULL,
  domain          TEXT,
  domain_source   TEXT,
  domain_alts     TEXT,
  sni             TEXT,
  alpn            TEXT,
  start_ns        INTEGER NOT NULL,
  end_ns          INTEGER,
  bytes_up        INTEGER,
  bytes_down      INTEGER,
  via_proxy       INTEGER NOT NULL DEFAULT 0,
  direct          INTEGER NOT NULL DEFAULT 0,
  preexisting     INTEGER NOT NULL DEFAULT 0,
  is_loopback     INTEGER NOT NULL DEFAULT 0,
  result          INTEGER,
  platform_total_up   INTEGER,
  platform_total_down INTEGER,
  evidence        TEXT NOT NULL,
  na_reason       TEXT,
  field_evidence  TEXT,
  source          TEXT NOT NULL
);
CREATE INDEX idx_nf_session_ts ON net_flows(session_id, start_ns);
CREATE INDEX idx_nf_proc       ON net_flows(session_id, proc_uid);
CREATE INDEX idx_nf_domain     ON net_flows(domain);
CREATE INDEX idx_nf_remote     ON net_flows(remote_ip, remote_port);

CREATE TABLE net_flow_buckets (
  flow_id         INTEGER NOT NULL REFERENCES net_flows(id) ON DELETE CASCADE,
  session_id      INTEGER NOT NULL,
  bucket_ns       INTEGER NOT NULL,
  bytes_up        INTEGER NOT NULL DEFAULT 0,
  bytes_down      INTEGER NOT NULL DEFAULT 0,
  evidence        TEXT NOT NULL,
  PRIMARY KEY (flow_id, bucket_ns)
) WITHOUT ROWID;
CREATE INDEX idx_nfb_session_ts ON net_flow_buckets(session_id, bucket_ns);

CREATE TABLE dns (
  id              INTEGER PRIMARY KEY,
  session_id      INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  proc_uid        INTEGER,
  ts_ns           INTEGER NOT NULL,
  qname           TEXT NOT NULL,
  qtype           INTEGER NOT NULL,
  rcode           INTEGER,
  answers         TEXT,
  ttl_min         INTEGER,
  server          TEXT,
  evidence        TEXT NOT NULL,
  source          TEXT NOT NULL
);
CREATE INDEX idx_dns_session_ts ON dns(session_id, ts_ns);
CREATE INDEX idx_dns_qname      ON dns(qname);

CREATE TABLE gaps (
  id              INTEGER PRIMARY KEY,
  session_id      INTEGER REFERENCES sessions(id) ON DELETE CASCADE,
  collector       TEXT NOT NULL,
  kind            TEXT NOT NULL,
  affects         TEXT NOT NULL,
  from_ns         INTEGER NOT NULL,
  to_ns           INTEGER NOT NULL,
  count           INTEGER,
  detail          TEXT
);
CREATE INDEX idx_gaps_session_ts ON gaps(session_id, from_ns);
