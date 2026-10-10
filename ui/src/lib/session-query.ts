import { useRouter, useSearch } from "@tanstack/react-router";

export interface SessionQuery {
  f: string;
  from: string;
  to: string;
  ev: string;
  subtree: string;
  proc: string;
}

export const EMPTY_QUERY: SessionQuery = { f: "", from: "", to: "", ev: "", subtree: "", proc: "" };

const EVIDENCE = ["E1", "E2", "E3", "S", "I"] as const;
export type EvidenceToggle = (typeof EVIDENCE)[number];

/** The evidence switches shared by every in-session page, encoded in `ev`. */
export function selectedEvidence(ev: string): Set<EvidenceToggle> {
  if (!ev) return new Set(EVIDENCE);
  return new Set(ev.split(",").filter((part): part is EvidenceToggle => (EVIDENCE as readonly string[]).includes(part)));
}

/**
 * Composes the filter expression sent to the API from the shared query:
 * the free-text expression plus the evidence switches and the process scope.
 */
export function composedFilter(query: SessionQuery): string {
  const parts: string[] = [];
  if (query.f.trim()) parts.push(`(${query.f.trim()})`);
  const evidence = selectedEvidence(query.ev);
  if (evidence.size > 0 && evidence.size < EVIDENCE.length) {
    parts.push(`evidence:${[...evidence].join(",")}`);
  }
  if (query.subtree) parts.push(`subtree:${query.subtree}`);
  else if (query.proc) parts.push(`proc_uid:${query.proc}`);
  return parts.join(" ");
}

export function useSessionQuery(): {
  query: SessionQuery;
  patch: (next: Partial<SessionQuery>) => void;
} {
  const search = useSearch({ strict: false }) as Partial<SessionQuery>;
  const router = useRouter();
  // validateSearch returns every key, unset ones as `undefined`; a plain spread
  // would overwrite the "" defaults with undefined and crash `.trim()`.
  const query: SessionQuery = { ...EMPTY_QUERY };
  for (const key of Object.keys(EMPTY_QUERY) as (keyof SessionQuery)[]) {
    const value = search[key];
    if (typeof value === "string") query[key] = value;
  }
  const patch = (next: Partial<SessionQuery>) => {
    const merged: Partial<SessionQuery> = { ...query, ...next };
    for (const key of Object.keys(merged) as (keyof SessionQuery)[]) {
      if (!merged[key]) delete merged[key];
    }
    // The shared layout sits above every in-session route, so the search type
    // is the partial schema declared on the session route.
    void router.navigate({ search: merged as never, replace: true });
  };
  return { query, patch };
}

export { EVIDENCE };
