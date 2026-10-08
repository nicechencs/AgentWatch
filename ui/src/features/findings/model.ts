import type { EvidenceLevel } from "@/api/types";
import type { Finding, FindingCaveat, FindingRef } from "./types";

/** Display groups, in page order (ui §3.8): content match → facts → inferred. */
export type FindingGroup = "content" | "fact" | "inferred";
export const GROUP_ORDER: readonly FindingGroup[] = ["content", "fact", "inferred"];

/**
 * Which group a finding belongs to. An `I` label always lands in "inferred",
 * whatever `kind` says: the UI never shows an inference as something stronger.
 */
export function groupOf(finding: { kind: string; evidence: string }): FindingGroup {
  if (finding.evidence === "I" || finding.kind === "inference") return "inferred";
  if (finding.kind === "content_match") return "content";
  return "fact";
}

const LEVELS: readonly EvidenceLevel[] = ["E1", "E2", "E3", "S", "I", "NA"];

/** `NA(reason)` and unknown labels map to `NA`; nothing maps upward. */
export function evidenceLevel(raw: string): EvidenceLevel {
  return (LEVELS as readonly string[]).includes(raw) ? (raw as EvidenceLevel) : "NA";
}

function parseJson(value: unknown): unknown {
  if (typeof value !== "string") return value;
  try {
    return JSON.parse(value) as unknown;
  } catch {
    return null;
  }
}

export function refsOf(value: unknown): FindingRef[] {
  const parsed = parseJson(value);
  if (!Array.isArray(parsed)) return [];
  return parsed.filter(
    (entry): entry is FindingRef =>
      typeof entry === "object" &&
      entry !== null &&
      typeof (entry as FindingRef).table === "string" &&
      typeof (entry as FindingRef).id === "number",
  );
}

export function caveatsOf(value: unknown): FindingCaveat[] {
  const parsed = parseJson(value);
  if (!Array.isArray(parsed)) return [];
  return parsed.filter(
    (entry): entry is FindingCaveat =>
      typeof entry === "object" &&
      entry !== null &&
      (typeof (entry as { gap_id?: unknown }).gap_id === "number" ||
        typeof (entry as { text_id?: unknown }).text_id === "string"),
  );
}

export function paramsOf(finding: Finding): Record<string, unknown> {
  const parsed = parseJson(finding.params);
  return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : {};
}

const SEVERITY_RANK: Record<string, number> = { warn: 3, notice: 2, info: 1 };

/** Severity first, then most recent activity (ui §3.8). */
export function sortFindings(items: Finding[]): Finding[] {
  return [...items].sort(
    (a, b) => (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0) || b.last_ns - a.last_ns || b.id - a.id,
  );
}
