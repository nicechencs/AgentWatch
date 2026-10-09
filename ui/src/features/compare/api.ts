/**
 * Session pair for the compare page.
 *
 * `GET /compare?a=&b=` is not implemented (P5-UI-02 names
 * crates/aw-daemon/src/api/compare.rs, which does not exist). This module
 * only loads the two sessions and their summaries through routes that
 * already exist. It does not compute a diff and does not invent counts.
 */
import { api } from "@/api/client";
import type { Session, SessionSummary } from "@/api/types";

export interface CompareSide {
  session: Session;
  summary: SessionSummary;
}

export async function loadSide(sid: string): Promise<CompareSide> {
  const [session, summary] = await Promise.all([api.session(sid), api.summary(sid)]);
  return { session, summary };
}
