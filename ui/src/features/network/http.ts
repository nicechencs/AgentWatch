/**
 * HTTP rows for the network page (P3-UI-02).
 *
 * `GET /sessions/{sid}/http` is not in src/api/client.ts yet (that file is
 * outside this task's file range), so the call lives here and reuses the
 * in-memory token from the shared client. Field names follow
 * crates/aw-daemon/src/api/http_events.rs.
 */
import { getToken } from "@/api/client";
import { ApiError } from "@/api/errors";
import type { ApiErrorBody, EvidenceLevel, NetFlow, ProcSummary } from "@/api/types";

export interface HttpRow {
  id: number;
  session_id: number;
  proc_uid: string | null;
  flow_id: number | null;
  ts_ns: number;
  method: string;
  /** Redacted by the daemon before it is stored. Rendered as-is. */
  url: string;
  host: string;
  http_version: string | null;
  status: number | null;
  /** JSON object or array of pairs; whitelisted and redacted server-side. */
  req_headers: string | null;
  resp_headers: string | null;
  req_body_bytes: number | null;
  resp_body_bytes: number | null;
  content_type: string | null;
  duration_ms: number | null;
  /** `cert_pinned`, `upstream_tls`, ... */
  error: string | null;
  evidence: EvidenceLevel;
  source: string;
  proc: { pid: ProcSummary["pid"] | null; exe_name: ProcSummary["exe_name"] } | null;
}

export interface HttpPage {
  http: HttpRow[];
  reason?: "no_proxy";
  next_cursor: string | null;
}

export const HTTP_PAGE_LIMIT = 2000;

export async function fetchHttp(sid: string, filter: string): Promise<HttpPage> {
  const params = new URLSearchParams({ limit: String(HTTP_PAGE_LIMIT) });
  if (filter) params.set("filter", filter);
  const headers = new Headers();
  const token = getToken();
  if (token) headers.set("authorization", `Bearer ${token}`);
  const response = await fetch(`/api/v1/sessions/${encodeURIComponent(sid)}/http?${params.toString()}`, { headers });
  const text = await response.text();
  const body = text ? (JSON.parse(text) as unknown) : null;
  if (!response.ok) throw new ApiError(response.status, body as ApiErrorBody | null, response.statusText);
  return body as HttpPage;
}

/** Index rows by flow_id. Rows with no flow_id are counted, not dropped silently. */
export function groupByFlow(rows: HttpRow[]): { byFlow: Map<number, HttpRow[]>; unlinked: number } {
  const byFlow = new Map<number, HttpRow[]>();
  let unlinked = 0;
  for (const row of rows) {
    if (row.flow_id === null || row.flow_id === undefined) {
      unlinked += 1;
      continue;
    }
    const list = byFlow.get(row.flow_id);
    if (list) list.push(row);
    else byFlow.set(row.flow_id, [row]);
  }
  return { byFlow, unlinked };
}

export type FlowMark = "direct" | "quic" | "via_proxy";

/** Marks shown on a connection row. Order is display order. */
export function flowMarks(flow: Pick<NetFlow, "direct" | "via_proxy" | "proto" | "remote_port" | "na_reason">): FlowMark[] {
  const marks: FlowMark[] = [];
  if (flow.direct) marks.push("direct");
  if (flow.na_reason === "quic" || (flow.proto === "udp" && flow.remote_port === 443)) marks.push("quic");
  if (flow.via_proxy) marks.push("via_proxy");
  return marks;
}

export function isCertPinned(row: Pick<HttpRow, "error">): boolean {
  return row.error === "cert_pinned";
}

/**
 * Header names never rendered, even if a row carries them. The proxy already
 * drops these (security-privacy §3); this is a second guard in the UI.
 */
const NEVER_SHOW = new Set([
  "authorization",
  "proxy-authorization",
  "cookie",
  "set-cookie",
  "x-api-key",
]);

/** Parse the whitelisted header JSON. Returns shown pairs and how many were withheld. */
export function visibleHeaders(raw: string | null): { shown: [string, string][]; hidden: number } {
  if (!raw) return { shown: [], hidden: 0 };
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { shown: [], hidden: 0 };
  }
  const pairs: [string, string][] = [];
  if (Array.isArray(parsed)) {
    for (const item of parsed) {
      if (Array.isArray(item) && typeof item[0] === "string" && typeof item[1] === "string") pairs.push([item[0], item[1]]);
    }
  } else if (parsed && typeof parsed === "object") {
    for (const [key, value] of Object.entries(parsed as Record<string, unknown>)) {
      if (typeof value === "string") pairs.push([key, value]);
      else if (Array.isArray(value)) pairs.push([key, value.filter((v) => typeof v === "string").join(", ")]);
    }
  }
  const shown = pairs.filter(([name]) => !NEVER_SHOW.has(name.toLowerCase()));
  return { shown, hidden: pairs.length - shown.length };
}
