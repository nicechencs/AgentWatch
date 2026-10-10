/**
 * Every API request goes through src/api/client.ts. A feature that calls
 * fetch("/api/v1…") itself keeps its own token and error handling, and a
 * transport change (desktop IPC) would silently miss it.
 */
import { describe, expect, it } from "vitest";

const sources = import.meta.glob<string>("/src/**/*.{ts,tsx}", { query: "?raw", import: "default", eager: true });

describe("single request path", () => {
  it("only client.ts (through transport.ts) calls fetch", () => {
    const allowed = new Set(["/src/api/client.ts", "/src/api/transport.ts"]);
    const offenders = Object.entries(sources)
      .filter(([path]) => !allowed.has(path) && !/\.test\.tsx?$/.test(path))
      .filter(([, text]) => /\bfetch\(/.test(text))
      .map(([path]) => path);
    expect(Object.keys(sources).length).toBeGreaterThan(20);
    expect(offenders).toEqual([]);
  });
});

import { toGap, toPage, toSession, toSummary, toTimelineItem } from "./client";

describe("daemon shape adapters", () => {
  // Bodies copied from a running agentwatchd (2026-10-10).
  it("maps the session list body", () => {
    const page = toPage(
      { next_cursor: null, sessions: [{ agent: null, ended_ns: null, id: "daemon-sample", mode: "attach", name: "daemon-wide attach sample", pinned: 0, session_id: 1, started_ns: 5 }] },
      ["sessions"],
      toSession,
    );
    expect(page.items).toHaveLength(1);
    expect(page.items[0]).toMatchObject({ id: 1, public_id: "daemon-sample", pinned: false, mode: "attach", collectors: [] });
  });
  it("maps timeline rows and summary", () => {
    const row = toTimelineItem({ cat: "proc", evidence: "S", id: 9, proc_uid: "u", session_id: 1, ts_ns: 1 });
    expect(row).toMatchObject({ kind: "proc", summary: "", fields: {}, proc: null });
    const summary = toSummary({ id: "daemon-sample", session_id: 1, stats: { process_count: 624, gap_count: 1 } });
    expect(summary.session.public_id).toBe("daemon-sample");
    expect(summary.session.stats?.proc_count).toBe(624);
    expect(summary.gap_count).toBe(1);
    expect(summary.top_dirs).toEqual([]);
  });
  it("maps gap rows", () => {
    const gap = toGap({ affects: '["store"]', collector: "daemon/poll", count: null, detail: "store_failure", from_ns: 1, to_ns: 2, kind: "store" });
    expect(gap).toMatchObject({ affected: ["store"], reason: "store_failure", kinds: ["store"], count: 0 });
  });
});
