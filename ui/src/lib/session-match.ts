import type { Session } from "@/api/types";
import { sessionTitle } from "@/lib/session-title";

/**
 * The daemon list ignores `q`, so the search box filters the fetched rows
 * here: a case-insensitive substring of the trimmed query against the title,
 * the argv joined with single spaces, and the public id. An empty query
 * matches everything.
 */
export function sessionMatchesQuery(
  session: Pick<Session, "name" | "argv" | "public_id">,
  query: string,
): boolean {
  const needle = query.trim().toLowerCase();
  if (!needle) return true;
  const haystacks = [
    sessionTitle(session),
    (session.argv ?? []).join(" "),
    session.public_id,
  ];
  return haystacks.some((value) => value.toLowerCase().includes(needle));
}
