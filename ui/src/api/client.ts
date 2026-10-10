/**
 * API client for the local daemon (docs/01-architecture/api-and-cli.md §3).
 * The bearer token lives in memory, mirrored to this tab's sessionStorage so a
 * reload keeps the session. Nothing here touches localStorage: another tab or
 * a later browser start does not inherit the token.
 */
import { ApiError } from "./errors";
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
  const response = await fetch(`${API}${path}`, { ...init, method, headers });
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

const get = <T>(path: string) => request<T>("GET", path);
const send = <T>(method: string, path: string, body?: unknown) =>
  request<T>(method, path, body === undefined ? {} : { body: JSON.stringify(body) });

export const api = {
  health: () => get<{ version: string; active_sessions: number }>("/health"),
  me: () => get<Me>("/me"),
  exchangeTicket: (ticket: string) =>
    send<{ token: string }>("POST", "/auth/ui-token", { ticket }),

  sessions: (query: SessionListQuery = {}) => get<Page<Session>>(`/sessions${qs({ ...query })}`),
  session: (sid: string) => get<Session>(`/sessions/${sid}`),
  createSession: (body: CreateSessionBody) => send<Session>("POST", "/sessions", body),
  patchSession: (sid: string, body: { name?: string; pinned?: boolean }) =>
    send<Session>("PATCH", `/sessions/${sid}`, body),
  stopSession: (sid: string) => send<Session>("POST", `/sessions/${sid}/stop`),
  deleteSession: (sid: string) => send<void>("DELETE", `/sessions/${sid}`),
  summary: (sid: string) => get<SessionSummary>(`/sessions/${sid}/summary`),
  exportUrl: (sid: string, format: "jsonl" | "csv" | "md") =>
    `${API}/sessions/${sid}/export?format=${format}`,

  timeline: (sid: string, query: Record<string, unknown>) =>
    get<Page<TimelineItem>>(`/sessions/${sid}/timeline${qs(query)}`),
  histogram: (sid: string, query: Record<string, unknown>) =>
    get<{ buckets: HistogramBucket[] }>(`/sessions/${sid}/timeline/histogram${qs(query)}`),
  around: (sid: string, ref: string, window = "10s") =>
    get<Page<TimelineItem>>(`/sessions/${sid}/around${qs({ ref, window })}`),

  processes: (sid: string, tree = true) =>
    get<{ roots: ProcessNode[] }>(`/sessions/${sid}/processes${qs({ tree: tree ? 1 : 0 })}`),
  processChildren: (sid: string, procUid: string) =>
    get<{ children: ProcessNode[] }>(`/sessions/${sid}/processes/${procUid}`),

  files: (sid: string, query: Record<string, unknown>) =>
    get<Page<FileAccess>>(`/sessions/${sid}/files${qs(query)}`),
  fileTree: (sid: string, query: Record<string, unknown>) =>
    get<{ roots: { path: string; count: number; writes: number }[] }>(
      `/sessions/${sid}/files${qs({ ...query, group_by: "dir" })}`,
    ),

  flows: (sid: string, query: Record<string, unknown>) =>
    get<{ groups: FlowGroup[] }>(`/sessions/${sid}/flows${qs(query)}`),
  traffic: (sid: string, query: Record<string, unknown>) =>
    get<TrafficSeries>(`/sessions/${sid}/traffic${qs(query)}`),

  gaps: (sid: string) => get<{ gaps: Gap[] }>(`/sessions/${sid}/gaps`),

  search: (query: Record<string, unknown>) => get<SearchResult>(`/search${qs(query)}`),

  doctor: () => get<DoctorReport>("/doctor"),
  systemProcesses: (query: { agents_only?: boolean; q?: string }) =>
    get<{ roots: SystemProcess[] }>(`/processes${qs({ ...query })}`),

  config: () => get<ConfigView>("/config"),
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
