import type { Query } from "@tanstack/react-query";
import { api } from "@/api/client";
import type { Session, SessionSummary } from "@/api/types";

/**
 * How often an open session's header and overview are re-read while it is
 * recording. Without it the header kept 「录制中」 and the Stop button after
 * the program had exited, and the overview kept the 「0 进程」 it read in the
 * first second (before the first sample was written).
 */
export const RECORDING_REFRESH_MS = 3_000;

function recording(session: Pick<Session, "ended_ns" | "purged"> | undefined): boolean {
  return session !== undefined && session.ended_ns == null && !session.purged;
}

/** Re-read while recording; stop once the session has ended. */
export function refreshWhileRecording(query: Query<Session, Error>): number | false {
  return recording(query.state.data) ? RECORDING_REFRESH_MS : false;
}

/** The session list: re-read while any listed session is still recording. */
export function refreshListWhileRecording(query: { state: { data?: { items: Session[] } } }): number | false {
  return (query.state.data?.items ?? []).some((session) => recording(session)) ? RECORDING_REFRESH_MS : false;
}

export function sessionQueryOptions(sid: string) {
  return {
    queryKey: ["session", sid] as const,
    queryFn: () => api.session(sid),
    refetchInterval: refreshWhileRecording,
  };
}

export function summaryQueryOptions(sid: string) {
  return {
    queryKey: ["summary", sid] as const,
    queryFn: () => api.summary(sid),
    refetchInterval: (query: Query<SessionSummary, Error>) =>
      recording(query.state.data?.session) ? RECORDING_REFRESH_MS : false,
  };
}
