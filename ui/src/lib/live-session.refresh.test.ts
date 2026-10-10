/**
 * While a session is recording, the header, the overview and the session
 * list re-read on an interval and stop once it has ended.
 */
import { describe, expect, it } from "vitest";
import type { Query } from "@tanstack/react-query";
import { toSession } from "@/api/client";
import type { Session } from "@/api/types";
import { RECORDING_REFRESH_MS, refreshListWhileRecording, refreshWhileRecording, summaryQueryOptions } from "@/lib/live-session";

describe("refresh while recording", () => {
  it("header and overview re-read while recording and stop once ended", () => {
    const session = (ended: number | null) =>
      ({ state: { data: toSession({ id: "s-1", mode: "launch", started_ns: 1, ended_ns: ended }) } }) as unknown as Query<Session, Error>;
    // Recording: re-read, so 「录制中」 turns into 「已停止」 when the program exits
    // and 「0 进程」 read before the first sample is replaced.
    expect(refreshWhileRecording(session(null))).toBe(RECORDING_REFRESH_MS);
    expect(refreshWhileRecording(session(2))).toBe(false);
    const summary = summaryQueryOptions("s-1");
    expect(summary.queryKey).toEqual(["summary", "s-1"]);
    const summaryOf = (ended: number | null) =>
      ({ state: { data: { session: toSession({ id: "s-1", started_ns: 1, ended_ns: ended }) } } }) as never;
    expect(summary.refetchInterval(summaryOf(null))).toBe(RECORDING_REFRESH_MS);
    expect(summary.refetchInterval(summaryOf(2))).toBe(false);
  });

  it("the session list re-reads while a listed session is recording", () => {
    const recording = refreshListWhileRecording({
      state: { data: { items: [toSession({ id: "a", started_ns: 1, ended_ns: null })] } },
    });
    expect(recording).toBe(RECORDING_REFRESH_MS);
    const ended = refreshListWhileRecording({
      state: { data: { items: [toSession({ id: "a", started_ns: 1, ended_ns: 2 })] } },
    });
    expect(ended).toBe(false);
    expect(refreshListWhileRecording({ state: { data: undefined } })).toBe(false);
  });
});
