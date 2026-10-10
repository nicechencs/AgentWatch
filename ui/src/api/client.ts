/**
 * API client for the local daemon (docs/01-architecture/api-and-cli.md §3).
 * The bearer token lives in memory, mirrored to this tab's sessionStorage so a
 * reload keeps the session. Nothing here touches localStorage: another tab or
 * a later browser start does not inherit the token.
 */
import { ApiError } from "./errors";
import { send as transportSend } from "./transport";
import type {
  ApiErrorBody,
  ConfigView,
  CreateSessionBody,
  DbStats,
  DoctorReport,
  FileAccess,
  FlowGroup,
  Gap,
  HistogramBucket,
  Me,
  Page,
  ProcessNode,
  SearchResult,
  Session,
  SessionListQuery,
  SessionSummary,
  SystemProcess,
  TimelineItem,
  TrafficSeries,
} from "./types";

const API = "/api/v1";

const TOKEN_KEY = "aw.ui_token";

function storage(): Storage | null {
  try {
    return typeof window === "undefined" ? null : window.sessionStorage;
  } catch {
    return null;
  }
}

let token: string | null = storage()?.getItem(TOKEN_KEY) ?? null;

export function getToken(): string | null {
  return token;
}

export function setToken(next: string | null): void {
  token = next;
  const store = storage();
  if (!store) return;
  if (next) store.setItem(TOKEN_KEY, next);
  else store.removeItem(TOKEN_KEY);
}

function qs(params: Record<string, unknown> | undefined): string {
  if (!params) return "";
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "") continue;
    if (Array.isArray(value)) search.set(key, value.join(","));
    else search.set(key, String(value));
  }
  const text = search.toString();
  return text ? `?${text}` : "";
}

async function request<T>(method: string, path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.body && !headers.has("content-type")) headers.set("content-type", "application/json");
  if (token) headers.set("authorization", `Bearer ${token}`);
  const response = await transportSend(`${API}${path}`, { ...init, method, headers });
  if (response.status === 204) return undefined as T;
  const text = await response.text();
  const body = text ? (JSON.parse(text) as unknown) : null;
  if (!response.ok) {
    throw new ApiError(response.status, body as ApiErrorBody | null, response.statusText);
  }
  return body as T;
}

/**
 * The one request path every feature uses (findings, network HTTP rows, proxy
 * CA). Features must not call `fetch("/api/v1…")` themselves: a second copy of
 * the token and error handling is what a transport change would miss.
 */
export function apiCall<T>(method: string, path: string, body?: unknown): Promise<T> {
  return request<T>(method, path, body === undefined ? {} : { body: JSON.stringify(body) });
}

/*
 * Daemon → UI shape adapters.
 *
 * The daemon's list bodies name their array after the resource (`sessions`,
 * `rows`, `files`, `processes`, `flows`) and a session's string id is `id`
 * with the integer row id in `session_id`. The pages were written against
 * `Page<T>.items` and `Session.public_id`. Mapping here keeps one place to
 * change when the contract settles; a field the daemon does not send stays
 * null/empty, never invented.
 */
type Raw = Record<string, unknown>;
const isObj = (v: unknown): v is Raw => typeof v === "object" && v !== null && !Array.isArray(v);
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const strOrNull = (v: unknown): string | null => (typeof v === "string" ? v : null);
const numOrNull = (v: unknown): number | null => (typeof v === "number" ? v : null);

export function toSession(raw: unknown): Session {
  const r = isObj(raw) ? raw : {};
  const stats = isObj(r.stats) ? r.stats : null;
  const publicId = typeof r.public_id === "string" ? r.public_id : typeof r.id === "string" ? r.id : String(r.id ?? "");
  const rowId = typeof r.session_id === "number" ? r.session_id : typeof r.id === "number" ? r.id : 0;
  return {
    ...(r as object),
    id: rowId,
    public_id: publicId,
    name: strOrNull(r.name),
    mode: r.mode === "launch" ? "launch" : "attach",
    agent: strOrNull(r.agent),
    root_proc_uid: strOrNull(r.root_proc_uid),
    argv: Array.isArray(r.argv) ? (r.argv as string[]) : null,
    cwd: strOrNull(r.cwd),
    user_id: typeof r.user_id === "string" ? r.user_id : "",
    started_ns: typeof r.started_ns === "number" ? r.started_ns : 0,
    ended_ns: numOrNull(r.ended_ns),
    end_reason: strOrNull(r.end_reason),
    exit_code: numOrNull(r.exit_code),
    proxy_enabled: Boolean(r.proxy_enabled),
    proxy_port: numOrNull(r.proxy_port),
    platform: typeof r.platform === "string" ? r.platform : "",
    os_version: strOrNull(r.os_version),
    collectors: arr(r.collectors).filter(isObj) as unknown as Session["collectors"],
    pinned: Boolean(r.pinned),
    stats: stats ? { ...(stats as object), proc_count: numOrNull(stats.proc_count ?? stats.process_count) } : null,
  } as Session;
}

/** `{items}` from whichever array key the daemon used. */
export function toPage<T>(raw: unknown, keys: string[], map: (row: unknown) => T = (row) => row as T): Page<T> {
  const r = isObj(raw) ? raw : {};
  const key = ["items", ...keys].find((k) => Array.isArray(r[k]));
  return { ...(r as object), items: key ? arr(r[key]).map(map) : [], next_cursor: strOrNull(r.next_cursor) } as Page<T>;
}

/** Timeline rows: the daemon sends `cat`; the UI reads `kind`, `summary`, `fields`. */
export function toTimelineItem(raw: unknown): TimelineItem {
  const r = isObj(raw) ? raw : {};
  return {
    ...(r as object),
    kind: (r.kind ?? r.cat ?? "proc") as TimelineItem["kind"],
    summary: typeof r.summary === "string" ? r.summary : "",
    fields: isObj(r.fields) ? r.fields : {},
    source: strOrNull(r.source),
    proc_uid: strOrNull(r.proc_uid),
    proc: isObj(r.proc) ? (r.proc as unknown as TimelineItem["proc"]) : null,
  } as TimelineItem;
}

/** Summary: the daemon answers the session row with `stats`; pages read `summary.session`. */
export function toSummary(raw: unknown): SessionSummary {
  const r = isObj(raw) ? raw : {};
  const session = toSession(isObj(r.session) ? r.session : r);
  const obj = (v: unknown): Record<string, number> => (isObj(v) ? (v as Record<string, number>) : {});
  const list = (v: unknown) => arr(v) as SessionSummary["top_dirs"];
  const stats = isObj(r.stats) ? r.stats : {};
  return {
    ...(r as object),
    session,
    counts_by_kind: obj(r.counts_by_kind),
    counts_by_evidence: obj(r.counts_by_evidence),
    top_dirs: list(r.top_dirs),
    top_domains: list(r.top_domains),
    top_commands: list(r.top_commands),
    direct_count: typeof r.direct_count === "number" ? r.direct_count : 0,
    gap_count: typeof r.gap_count === "number" ? r.gap_count : typeof stats.gap_count === "number" ? stats.gap_count : 0,
    finding_count: typeof r.finding_count === "number" ? r.finding_count : 0,
    approximate: Boolean(r.approximate),
    approximate_reason: strOrNull(r.approximate_reason),
  } as SessionSummary;
}

/** Gap rows: `affects` is stored as a JSON array string and `detail` holds the reason. */
export function toGap(raw: unknown): Gap {
  const r = isObj(raw) ? raw : {};
  const list = (v: unknown): string[] => {
    if (Array.isArray(v)) return v.filter((x): x is string => typeof x === "string");
    if (typeof v === "string") {
      try {
        const parsed: unknown = JSON.parse(v);
        if (Array.isArray(parsed)) return parsed.filter((x): x is string => typeof x === "string");
      } catch {
        return v ? [v] : [];
      }
    }
    return [];
  };
  return {
    ...(r as object),
    id: typeof r.id === "number" ? r.id : 0,
    from_ns: typeof r.from_ns === "number" ? r.from_ns : 0,
    to_ns: typeof r.to_ns === "number" ? r.to_ns : 0,
    collector: typeof r.collector === "string" ? r.collector : "",
    kinds: list(r.kinds ?? r.kind),
    affected: list(r.affected ?? r.affects),
    count: typeof r.count === "number" ? r.count : 0,
    reason: typeof r.reason === "string" ? r.reason : typeof r.detail === "string" ? r.detail : "",
    degradation: Boolean(r.degradation),
  } as Gap;
}

/**
 * `GET /config` answers `{config: {retention: {max_db_size_mb, …}, proxy, …}}`.
 * Keys the daemon does not send stay undefined (the page shows 不可得), and
 * object-shaped sections it does not list as arrays become empty lists.
 */
export function toConfigView(raw: unknown): ConfigView {
  const outer = isObj(raw) ? raw : {};
  const r = isObj(outer.config) ? outer.config : outer;
  const retention = isObj(r.retention) ? r.retention : {};
  const mb = numOrNull(retention.max_db_size_mb);
  const redaction = isObj(r.redaction) ? r.redaction : {};
  const proxy = isObj(r.proxy) ? r.proxy : {};
  return {
    ...(r as object),
    retention: {
      ...(retention as object),
      max_db_bytes: numOrNull(retention.max_db_bytes) ?? (mb === null ? undefined : mb * 1024 * 1024),
    },
    redaction: { ...(redaction as object), rules: arr(redaction.rules) },
    collectors: arr(r.collectors),
    proxy: { ca_fingerprint: null, ca_created_ns: null, ...(proxy as object) },
    rules: arr(r.rules),
  } as unknown as ConfigView;
}

function toProcessNode(raw: unknown): ProcessNode {
  const r = isObj(raw) ? raw : {};
  return {
    ...(r as object),
    images: arr(r.images),
    children: arr(r.children).map(toProcessNode),
  } as ProcessNode;
}

const get = <T>(path: string) => request<T>("GET", path);
const send = <T>(method: string, path: string, body?: unknown) =>
  request<T>(method, path, body === undefined ? {} : { body: JSON.stringify(body) });

export const api = {
  health: () => get<{ version: string; active_sessions: number }>("/health"),
  me: () => get<Me>("/me"),
  exchangeTicket: (ticket: string) =>
    send<{ token: string }>("POST", "/auth/ui-token", { ticket }),

  sessions: async (query: SessionListQuery = {}) =>
    toPage(await get<unknown>(`/sessions${qs({ ...query })}`), ["sessions"], toSession),
  session: async (sid: string) => toSession(await get<unknown>(`/sessions/${sid}`)),
  createSession: (body: CreateSessionBody) => send<Session>("POST", "/sessions", body),
  patchSession: (sid: string, body: { name?: string; pinned?: boolean }) =>
    send<Session>("PATCH", `/sessions/${sid}`, body),
  stopSession: (sid: string) => send<Session>("POST", `/sessions/${sid}/stop`),
  deleteSession: (sid: string) => send<void>("DELETE", `/sessions/${sid}`),
  summary: async (sid: string) => toSummary(await get<unknown>(`/sessions/${sid}/summary`)),
  exportUrl: (sid: string, format: "jsonl" | "csv" | "md") =>
    `${API}/sessions/${sid}/export?format=${format}`,

  timeline: async (sid: string, query: Record<string, unknown>) =>
    toPage(await get<unknown>(`/sessions/${sid}/timeline${qs(query)}`), ["rows"], toTimelineItem),
  histogram: (sid: string, query: Record<string, unknown>) =>
    get<{ buckets: HistogramBucket[] }>(`/sessions/${sid}/timeline/histogram${qs(query)}`),
  around: async (sid: string, ref: string, window = "10s") =>
    toPage(await get<unknown>(`/sessions/${sid}/around${qs({ ref, window })}`), ["rows"], toTimelineItem),

  processes: async (sid: string, tree = true) => {
    const raw = await get<{ roots?: unknown[]; processes?: unknown[] }>(`/sessions/${sid}/processes${qs({ tree: tree ? 1 : 0 })}`);
    return { roots: arr(raw.roots ?? raw.processes).map(toProcessNode) };
  },
  processChildren: (sid: string, procUid: string) =>
    get<{ children: ProcessNode[] }>(`/sessions/${sid}/processes/${procUid}`),

  files: async (sid: string, query: Record<string, unknown>) =>
    toPage<FileAccess>(await get<unknown>(`/sessions/${sid}/files${qs(query)}`), ["files", "rows"]),
  fileTree: (sid: string, query: Record<string, unknown>) =>
    get<{ roots: { path: string; count: number; writes: number }[] }>(
      `/sessions/${sid}/files${qs({ ...query, group_by: "dir" })}`,
    ),

  flows: async (sid: string, query: Record<string, unknown>) => {
    // Without grouping the daemon answers `{flows: [...]}`; the page reads groups.
    const raw = await get<{ groups?: FlowGroup[] }>(`/sessions/${sid}/flows${qs(query)}`);
    return { ...raw, groups: Array.isArray(raw.groups) ? raw.groups : [] };
  },
  traffic: (sid: string, query: Record<string, unknown>) =>
    get<TrafficSeries>(`/sessions/${sid}/traffic${qs(query)}`),

  gaps: async (sid: string) => {
    const raw = await get<{ gaps?: unknown[] }>(`/sessions/${sid}/gaps`);
    return { gaps: arr(raw.gaps).map(toGap) };
  },

  search: (query: Record<string, unknown>) => get<SearchResult>(`/search${qs(query)}`),

  doctor: () => get<DoctorReport>("/doctor"),
  systemProcesses: (query: { agents_only?: boolean; q?: string }) =>
    get<{ roots: SystemProcess[] }>(`/processes${qs({ ...query })}`),

  config: async () => toConfigView(await get<unknown>("/config")),
  putConfig: (body: unknown) => send<ConfigView>("PUT", "/config", body),
  dbStats: () => get<DbStats>("/db/stats"),
  purge: (body: { older_than?: string; all?: boolean }) => send<void>("POST", "/db/purge", body),
};

export interface LiveHandlers {
  onRecord: (item: TimelineItem) => void;
  onLagged: (dropped: number) => void;
  onError: () => void;
}

/** SSE subscription to /live. Returns a close function. */
export function subscribeLive(sid: string, filter: string, handlers: LiveHandlers): () => void {
  const params = new URLSearchParams();
  if (filter) params.set("filter", filter);
  if (token) params.set("access_token", token);
  const source = new EventSource(`${API}/sessions/${sid}/live?${params.toString()}`);
  source.addEventListener("record", (event) => {
    handlers.onRecord(JSON.parse((event as MessageEvent).data) as TimelineItem);
  });
  source.addEventListener("lagged", (event) => {
    const data = JSON.parse((event as MessageEvent).data) as { dropped?: number };
    handlers.onLagged(data.dropped ?? 0);
  });
  source.onerror = () => handlers.onError();
  return () => source.close();
}
