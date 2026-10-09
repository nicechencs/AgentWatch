/**
 * Reads for the self-report view.
 *
 * E3 rows are timeline items with `kind: agent`. There is no list route for
 * `agent_events` (`GET /sessions/{sid}/agent-events` is reserved and answers
 * 501), and there is no alignment route, so this module does not call either.
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

export async function agentTimeline(sid: string): Promise<TimelineItem[]> {
  const page = await api.timeline(sid, { cats: "agent", limit: PAGE });
  return page.items.filter((item) => item.kind === "agent" && item.evidence === "E3");
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
