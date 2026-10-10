/**
 * Findings endpoints (api-and-cli §3). Requests go through the shared
 * `apiCall` in `src/api/client.ts`.
 */
import { infiniteQueryOptions, queryOptions } from "@tanstack/react-query";
import { api, apiCall } from "@/api/client";
import type { TimelineItem } from "@/api/types";
import type { Lang } from "@/lib/i18n";
import type { Finding, FindingRef, FindingsPage, UserState } from "./types";

const PAGE = 500;

const call = apiCall;

export function listFindings(sid: string, query: { lang: Lang; cursor?: string; limit?: number }): Promise<FindingsPage> {
  const search = new URLSearchParams({ lang: query.lang, limit: String(query.limit ?? PAGE) });
  if (query.cursor) search.set("cursor", query.cursor);
  return call<FindingsPage>("GET", `/sessions/${encodeURIComponent(sid)}/findings?${search.toString()}`);
}

/** `null` clears the mark. The daemon accepts only these three values. */
export function patchFinding(sid: string, id: number, userState: UserState | null) {
  return call<{ id: number; user_state: UserState | null }>(
    "PATCH",
    `/sessions/${encodeURIComponent(sid)}/findings/${id}`,
    { user_state: userState },
  );
}

export const findingsKey = (sid: string, lang: Lang) => ["findings", sid, lang] as const;

export const findingsQueryOptions = (sid: string, lang: Lang) =>
  infiniteQueryOptions({
    queryKey: findingsKey(sid, lang),
    initialPageParam: "",
    queryFn: ({ pageParam }) => listFindings(sid, { lang, cursor: pageParam || undefined }),
    getNextPageParam: (page: FindingsPage) => page.next_cursor ?? undefined,
  });

export function allFindings(pages: FindingsPage[] | undefined): Finding[] {
  return (pages ?? []).flatMap((page) => page.findings);
}

/** Timeline category for each table a ref may name. */
const TABLE_CAT: Record<string, string> = {
  file_access: "file",
  net_flow: "net",
  net_flows: "net",
  dns: "dns",
  http: "http",
  processes: "proc",
  process_images: "proc",
  gaps: "gap",
};

/** Rule records name `net_flow`; `/around` takes the table name `net_flows`. */
const AROUND_TABLE: Record<string, string> = { net_flow: "net_flows" };

export type ResolvedRef =
  | { ref: FindingRef; status: "found"; item: TimelineItem }
  | { ref: FindingRef; status: "missing" }
  | { ref: FindingRef; status: "unsupported" };

type LooseRow = Partial<TimelineItem> & { cat?: string };

/**
 * Looks up the raw record behind one ref through `/around` with a 1 ms
 * window. A row that is gone (purged) is reported as missing, not invented.
 * The response is read as `items` (UI type) or `rows` (current daemon JSON).
 */
export async function resolveRef(sid: string, ref: FindingRef): Promise<ResolvedRef> {
  const cat = TABLE_CAT[ref.table];
  if (!cat) return { ref, status: "unsupported" };
  const table = AROUND_TABLE[ref.table] ?? ref.table;
  const page = (await api.around(sid, `${table}:${ref.id}`, "1ms")) as unknown as {
    items?: LooseRow[];
    rows?: LooseRow[];
  };
  const rows = page.items ?? page.rows ?? [];
  const hit = rows.find((row) => (row.kind ?? row.cat) === cat && row.id === ref.id);
  if (!hit) return { ref, status: "missing" };
  const item: TimelineItem = {
    kind: cat as TimelineItem["kind"],
    id: ref.id,
    ts_ns: hit.ts_ns ?? 0,
    evidence: hit.evidence ?? "NA",
    na_reason: hit.na_reason ?? null,
    source: hit.source ?? null,
    proc_uid: hit.proc_uid ?? null,
    proc: hit.proc ?? null,
    summary: hit.summary ?? "",
    fields: hit.fields ?? {},
  };
  return { ref, status: "found", item };
}

export const refsQueryOptions = (sid: string, refs: FindingRef[]) =>
  queryOptions({
    queryKey: ["finding-refs", sid, refs.map((ref) => `${ref.table}:${ref.id}`).join(",")],
    queryFn: () => Promise.all(refs.map((ref) => resolveRef(sid, ref))),
  });
