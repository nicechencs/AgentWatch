/**
 * Reads for the self-report view.
 *
 * E3 rows come from `GET /sessions/{sid}/agent-events`, which this daemon
 * implements. There is no alignment route, so nothing is paired.
 */
import { api } from "@/api/client";
import { ApiError } from "@/api/errors";
import type { TimelineItem } from "@/api/types";
import { fetchHttp, type HttpPage } from "@/features/network/http";

const PAGE = 500;

/** 404/501 means the route is not wired, not that the session has no rows. */
export function routeMissing(caught: unknown): boolean {
  return caught instanceof ApiError && (caught.status === 404 || caught.status === 501);
}

/** One `agent_events` row as a timeline-shaped item for the left column. */
export function agentEventToItem(row: Record<string, unknown>): TimelineItem {
  const text = (key: string) => (typeof row[key] === "string" ? (row[key] as string) : null);
  const detail = text("command") ?? text("path") ?? text("url") ?? text("query");
  const summary = [text("agent"), text("tool"), text("phase"), detail].filter(Boolean).join(" · ");
  return {
    kind: "agent",
    id: typeof row.id === "number" ? row.id : 0,
    ts_ns: typeof row.ts_ns === "number" ? row.ts_ns : 0,
    evidence: (text("evidence") ?? "E3") as TimelineItem["evidence"],
    na_reason: text("na_reason") as TimelineItem["na_reason"],
    source: text("source"),
    proc_uid: null,
    proc: null,
    summary,
    fields: row,
  };
}

/** E3 self-reports from the agent-events list. `reason` is the daemon's note for an empty list. */
export async function agentEvents(sid: string): Promise<{ items: TimelineItem[]; reason: string | null }> {
  const page = await api.agentEvents(sid);
  return { items: page.events.map(agentEventToItem), reason: page.reason };
}

export async function observedTimeline(sid: string): Promise<TimelineItem[]> {
  const page = await api.timeline(sid, { cats: "proc,file,net,http", limit: PAGE });
  return page.items.filter((item) => item.evidence === "E1" || item.evidence === "E2");
}

/** HTTP rows when the route exists. `missing` is the 404/501 case, not an empty session. */
export async function httpOrMissing(sid: string): Promise<{ page: HttpPage | null; missing: boolean }> {
  try {
    return { page: await fetchHttp(sid, ""), missing: false };
  } catch (caught) {
    if (routeMissing(caught)) return { page: null, missing: true };
    throw caught;
  }
}
