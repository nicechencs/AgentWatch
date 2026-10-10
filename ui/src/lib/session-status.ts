import type { Session } from "@/api/types";

export type SessionStatusKind = "recording" | "program_exit" | "user_stop" | "daemon_restart";

type Translate = (key: string) => string;

export interface SessionStatusText {
  kind: SessionStatusKind;
  label: string;
  explanation: string | null;
}

/** The single mapping from the daemon's end reason to user-facing status. */
export function sessionStatus(
  session: Pick<Session, "ended_ns" | "end_reason" | "purged">,
  t: Translate,
): SessionStatusText {
  if (session.ended_ns === null && !session.purged) {
    return { kind: "recording", label: t("session.recording"), explanation: null };
  }
  if (session.end_reason === "stopped" || session.end_reason === "user_stop") {
    return { kind: "user_stop", label: t("session.recordingStopped"), explanation: null };
  }
  if (session.end_reason === "daemon_restart" || session.end_reason === "daemon_shutdown") {
    return {
      kind: "daemon_restart",
      label: t("session.recordingInterrupted"),
      explanation: t("session.recordingInterruptedReason"),
    };
  }
  // `exited` / `program_exit`, null, and unknown legacy/future values all mean the
  // program is no longer running when the daemon has supplied an end time.
  return { kind: "program_exit", label: t("session.stopped"), explanation: null };
}
