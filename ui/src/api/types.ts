/**
 * Hand-written types mirroring docs/01-architecture/api-and-cli.md §3 and the
 * storage schema (docs/01-architecture/storage.md). Field names match the
 * tables. `openapi-typescript` generation is wired in scripts/gen-api-types.mjs
 * and replaces this file once the daemon serves /api/v1/openapi.json.
 */

export type EvidenceLevel = "E1" | "E2" | "E3" | "S" | "I" | "NA";

export type NaReason =
  | "es_no_read_event"
  | "mmap_not_observable"
  | "tls_no_proxy"
  | "direct_bypass_proxy"
  | "cert_pinned"
  | "quic"
  | "ech"
  | "no_dns_observed"
  | "preexisting"
  | "collector_unavailable"
  | "redacted"
  | "attribution_break"
  | "partial_client_hello"
  | "h2_hpack"
  | "too_large"
  | "file_changed"
  | "peer_unknown"
  | "protocol_not_observed";

/** Field-level evidence, present only when a field's source differs from the record. */
export interface FieldEvidence {
  evidence: EvidenceLevel;
  na_reason?: NaReason | null;
  source?: string | null;
}

export interface ProcSummary {
  pid: number;
  exe_name: string | null;
}

export interface Page<T> {
  items: T[];
  next_cursor: string | null;
}

export interface ApiErrorBody {
  error: { code: string; message: string; column?: number; suggestion?: string };
}

export type SessionMode = "launch" | "attach";

export interface CollectorCapability {
  kind: string;
  evidence: EvidenceLevel;
  na_reason?: NaReason | null;
  note?: string | null;
}

export interface CollectorInfo {
  name: string;
  version?: string | null;
  mode?: string | null;
  capabilities: CollectorCapability[];
}

export interface SessionStats {
  proc_count?: number | null;
  event_count?: number | null;
  file_count?: number | null;
  write_count?: number | null;
  delete_count?: number | null;
  domain_count?: number | null;
  bytes_up?: number | null;
  bytes_down?: number | null;
  finding_count?: number | null;
  gap_count?: number | null;
  bytes?: number | null;
  /** True when part of the totals come from sampling or cover a gap window. */
  approximate?: boolean | null;
  approximate_reason?: string | null;
}

export interface Session {
  id: number;
  public_id: string;
  name: string | null;
  mode: SessionMode;
  agent: string | null;
  root_proc_uid: string | null;
  argv: string[] | null;
  cwd: string | null;
  user_id: string;
  started_ns: number;
  ended_ns: number | null;
  end_reason: string | null;
  exit_code: number | null;
  proxy_enabled: boolean;
  proxy_port: number | null;
  platform: string;
  os_version: string | null;
  collectors: CollectorInfo[];
  pinned: boolean;
  stats: SessionStats | null;
  /** Present when the session was removed by the retention policy. */
  purged?: boolean | null;
  purged_reason?: string | null;
}

export interface SessionListQuery {
  since?: string;
  until?: string;
  agent?: string;
  active?: boolean;
  q?: string;
  cursor?: string;
  limit?: number;
}

export interface CreateSessionBody {
  mode: SessionMode;
  argv?: string[];
  cwd?: string;
  env?: Record<string, string>;
  pid?: number;
  follow_children?: boolean;
  include_existing_children?: boolean;
  proxy?: boolean;
  agent?: string;
  name?: string;
  self_report?: "auto" | "off" | "hooks" | "otel";
  pin?: boolean;
}

export interface TopEntry {
  label: string;
  count: number;
  writes?: number | null;
  bytes_up?: number | null;
  bytes_down?: number | null;
  evidence?: EvidenceLevel | null;
}

export interface SessionSummary {
  session: Session;
  counts_by_kind: Record<string, number>;
  counts_by_evidence: Record<string, number>;
  top_dirs: TopEntry[];
  top_domains: TopEntry[];
  top_commands: TopEntry[];
  /** False for a top list the daemon did not send. Optional for older test fixtures. */
  top_available?: { domains: boolean; dirs: boolean; commands: boolean };
  direct_count: number;
  gap_count: number;
  finding_count: number;
  approximate: boolean;
  approximate_reason: string | null;
}

export type TimelineKind =
  | "proc"
  | "file"
  | "net"
  | "dns"
  | "http"
  | "agent"
  | "ipc"
  | "rpc"
  | "finding"
  | "gap";

export interface TimelineItem {
  kind: TimelineKind;
  id: number;
  ts_ns: number;
  end_ns?: number | null;
  evidence: EvidenceLevel;
  na_reason?: NaReason | null;
  field_evidence?: Record<string, FieldEvidence> | null;
  source: string | null;
  corroborated_by?: string[] | null;
  proc_uid: string | null;
  proc: ProcSummary | null;
  summary: string;
  fields: Record<string, unknown>;
  /** Collapse group produced by the "merge" density mode. */
  collapsed?: { count: number; dir: string } | null;
  gap?: Gap | null;
  /** `proc` rows: running before the session began (daemon decides; attach baselines only). */
  pre_existing?: boolean;
}

export interface HistogramBucket {
  start_ns: number;
  end_ns: number;
  count: number;
  gap: boolean;
}

export interface ProcessImage {
  seq: number;
  ts_ns: number;
  exe: string | null;
  argv: string[] | null;
  cwd: string | null;
  evidence: EvidenceLevel;
}

export interface ProcessNode {
  proc_uid: string;
  pid: number;
  parent_uid: string | null;
  depth: number;
  start_ns: number;
  exit_ns: number | null;
  exit_code: number | null;
  how: "fork" | "exec" | "spawn" | "snapshot" | string;
  evidence: EvidenceLevel;
  source: string;
  agent: string | null;
  images: ProcessImage[];
  /** Base name of the latest image's executable, as the daemon sends it. */
  exe_name?: string | null;
  children: ProcessNode[];
  /** Own counters; subtree counters cover descendants. */
  files: number;
  writes: number;
  deletes: number;
  bytes_up: number | null;
  bytes_down: number | null;
  subtree_files: number;
  subtree_writes: number;
  subtree_deletes: number;
  subtree_bytes_up: number | null;
  subtree_bytes_down: number | null;
  sensitive: boolean;
  attribution_break: boolean;
  truncated?: boolean;
}

export type FileOp = "access" | "create" | "delete" | "rename" | "exec";

export interface FileAccess {
  id: number;
  proc_uid: string;
  proc: ProcSummary | null;
  op: FileOp;
  path: string;
  path_to: string | null;
  access: string | null;
  first_ns: number;
  last_ns: number;
  opens: number;
  reads: number | null;
  bytes_read: number | null;
  writes: number | null;
  bytes_written: number | null;
  result: number | null;
  sensitive_rule: string | null;
  evidence: EvidenceLevel;
  na_reason: NaReason | null;
  field_evidence: Record<string, FieldEvidence> | null;
  source: string;
}

export interface DirNode {
  path: string;
  count: number;
  writes: number;
  children?: DirNode[];
}

export interface NetFlow {
  id: number;
  proc_uid: string;
  proc: ProcSummary | null;
  proto: "tcp" | "udp";
  local_ip: string;
  local_port: number;
  remote_ip: string;
  remote_port: number;
  domain: string | null;
  domain_source: string | null;
  domain_alts: string[] | null;
  start_ns: number;
  end_ns: number | null;
  bytes_up: number | null;
  bytes_down: number | null;
  via_proxy: boolean;
  direct: boolean;
  evidence: EvidenceLevel;
  na_reason: NaReason | null;
  field_evidence: Record<string, FieldEvidence> | null;
  source: string;
}

export interface FlowGroup {
  key: string;
  label: string;
  domain_source: string | null;
  alt_count: number;
  inferred: boolean;
  direct: boolean;
  bytes_up: number | null;
  bytes_down: number | null;
  connections: number;
  evidence: EvidenceLevel;
  flows: NetFlow[];
}

export interface TrafficSeries {
  labels: string[];
  buckets: { start_ns: number; values_up: number[]; values_down: number[] }[];
  approximate: boolean;
}

export interface Gap {
  id: number;
  from_ns: number;
  to_ns: number;
  collector: string;
  kinds: string[];
  affected: string[];
  count: number;
  reason: string;
  degradation: boolean;
}

export interface DoctorCapability {
  kind: string;
  evidence: EvidenceLevel | null;
  available: boolean;
  na_reason: NaReason | null;
  note: string | null;
}

export interface DoctorReport {
  platform: string;
  os_version: string | null;
  mode: string | null;
  capabilities: DoctorCapability[];
  /** Runtime state from the service, not the config: `running` / `stopped` / `not_built` / `unknown`. */
  collectors: {
    name: string;
    status: string;
    note?: string | null;
    running?: boolean | null;
    daemon_sample?: boolean;
    watched_roots?: number;
    last_sample_ns?: number | null;
    capabilities?: { kind: string; evidence: string | null; na_reason?: string | null }[];
  }[];
  /** False when the daemon did not probe collectors (capabilities is then empty). */
  probed: boolean;
  reason: string | null;
  privileged: boolean | null;
  privileged_note: string | null;
}

export interface SystemProcess {
  pid: number;
  ppid: number | null;
  name: string;
  exe: string | null;
  /** Redacted by the service before it is sent. Null when unreadable. */
  argv: string[] | null;
  /** Owner uid or SID. Null when the service could not read it. */
  user_id: string | null;
  agent: string | null;
  children: SystemProcess[];
}

/** `GET /processes`. `available: false` is "not collected", not an empty table. */
export interface SystemProcessTable {
  available: boolean;
  reason: string | null;
  /** "all" for an administrator, "own" for everyone else. */
  scope: string | null;
  roots: SystemProcess[];
}

export interface SearchHit {
  session_id: string;
  session_name: string | null;
  /** UI category: `file`, `proc`, `url`, or the source table when unknown. */
  kind: string;
  id: number;
  /** The daemon's search answer names the row only; time, text and evidence stay null. */
  ts_ns: number | null;
  summary: string | null;
  evidence: EvidenceLevel | null;
}

export interface SearchGroup {
  session_id: string;
  session_name: string | null;
  count: number;
  hits: SearchHit[];
}

export interface SearchResult {
  groups: SearchGroup[];
  fts_enabled: boolean;
}

export interface RedactionRule {
  id: string;
  builtin: boolean;
  pattern: string;
  description: string | null;
  /** Built-in rules: `text`, `argv`, `env`, `url` or `header`. */
  scope?: string | null;
}

export interface ConfigView {
  retention: {
    max_db_bytes: number;
    max_age_days: number;
    min_free_disk_bytes: number;
    max_session_bytes: number;
    check_interval_secs: number;
  };
  redaction: { rules: RedactionRule[] };
  collectors: { name: string; enabled: boolean; note: string | null }[];
  proxy: { default_enabled: boolean; ca_fingerprint: string | null; ca_created_ns: number | null };
  rules: { id: string; enabled: boolean }[];
}

export interface DbStats {
  /** False when the daemon did not report sizes; the numbers are then absent. */
  available?: boolean;
  reason?: string | null;
  db_bytes: number;
  wal_bytes: number;
  max_db_bytes: number;
  max_age_days: number;
  oldest_session_ns: number | null;
  table_rows: Record<string, number>;
}

export interface Me {
  user_id: string;
  admin: boolean;
}
