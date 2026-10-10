import type { Session } from "@/api/types";

type T = (key: string, vars?: Record<string, string | number>) => string;

/** Chinese (or English) name of a capability / timeline category; the raw kind when there is none. */
export function kindLabel(t: T, kind: string): string {
  const key = `timeline.cats.${kind}`;
  const text = t(key);
  return text === key ? kind : text;
}

/**
 * Whether a session's collectors observe `kind`.
 *
 * - `collected`: some collector lists it with evidence other than NA.
 * - `not_collected`: it is listed only as NA (the build does not collect it).
 * - `unknown`: no collector described its capabilities, so the page cannot
 *   say either way.
 *
 * An empty page under `not_collected` means "not recorded", never "nothing
 * happened" (AGENTS.md §1).
 */
export type Coverage = "collected" | "not_collected" | "unknown";

export function coverage(session: Pick<Session, "collectors"> | null | undefined, kind: string): Coverage {
  const caps = (session?.collectors ?? []).flatMap((collector) => collector.capabilities ?? []);
  const matching = caps.filter((cap) => cap.kind === kind);
  if (matching.length === 0) return "unknown";
  return matching.some((cap) => cap.evidence !== "NA") ? "collected" : "not_collected";
}

/** Kinds the session lists as NA only, in a stable order. */
export function uncollectedKinds(session: Pick<Session, "collectors"> | null | undefined): string[] {
  const kinds = new Set((session?.collectors ?? []).flatMap((c) => (c.capabilities ?? []).map((cap) => cap.kind)));
  return [...kinds].filter((kind) => coverage(session, kind) === "not_collected");
}

/** True when no collector on the session described any capability. */
export function capabilitiesUnknown(session: Pick<Session, "collectors"> | null | undefined): boolean {
  return (session?.collectors ?? []).every((collector) => (collector.capabilities ?? []).length === 0);
}
