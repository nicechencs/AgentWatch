/**
 * Shapes returned by `GET /sessions/{sid}/findings` (api-and-cli §3,
 * crates/aw-daemon/src/api/findings.rs `finding_json`). Kept beside the
 * feature: `src/api/types.ts` is outside this task's file scope.
 */

export type FindingKind = "fact" | "fact_conjunction" | "inference" | "content_match";
export type Severity = "info" | "notice" | "warn";
export type UserState = "confirmed" | "ignored";

/** One entry of `findings.refs`: a table name plus that table's row id. */
export interface FindingRef {
  table: string;
  id: number;
}

/** One entry of `findings.caveats` (storage §4): a gap reference or a text id. */
export type FindingCaveat = { gap_id: number } | { text_id: string };

export interface Finding {
  id: number;
  rule_id: string;
  rule_version: number;
  /** `fact` / `fact_conjunction` / `inference` / `content_match`. */
  kind: string;
  /** Stored label: `E1` … `I`, or `NA(reason)`. */
  evidence: string;
  severity: string;
  wording_id: string;
  params: Record<string, unknown> | string | null;
  /** Sentence rendered by `wording::render`. Null when rendering failed. */
  text: string | null;
  error?: string | null;
  first_ns: number;
  last_ns: number;
  count: number;
  dedup_key: string;
  refs: FindingRef[] | string;
  caveats: FindingCaveat[] | string | null;
  user_state: UserState | null;
  user_state_by?: string | null;
  user_state_ns?: number | null;
}

export interface FindingsPage {
  findings: Finding[];
  next_cursor: string | null;
}
