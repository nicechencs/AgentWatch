/**
 * Every API request goes through src/api/client.ts. A feature that calls
 * fetch("/api/v1…") itself keeps its own token and error handling, and a
 * transport change (desktop IPC) would silently miss it.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { setToken } from "./client";

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

import { toConfigView } from "./client";

describe("config adapter", () => {
  it("unwraps the daemon config body", () => {
    const view = toConfigView({ config: { retention: { max_age_days: 30, max_db_size_mb: 2048 }, proxy: { on_tls_reject: "fail" }, collectors: { linux: {} } } });
    expect(view.retention.max_age_days).toBe(30);
    expect(view.retention.max_db_bytes).toBe(2048 * 1024 * 1024);
    expect(view.redaction.rules).toEqual([]);
    // `collectors` is an object in the daemon body; the page lists it.
    expect(view.collectors.map((c) => c.name)).toEqual(["linux"]);
    expect(view.rules).toEqual([]);
  });
});

import { groupFlows, toNetFlow } from "./client";

describe("network flow grouping", () => {
  // Rows in the daemon's ungrouped `GET /flows` shape.
  const rows = [
    { id: 1, proc_uid: "a", domain: "api.example.com", remote_ip: "10.0.0.1", remote_port: 443, bytes_up: 100, bytes_down: 1000, start_ns: 1, evidence: "S" },
    { id: 2, proc_uid: "a", domain: "api.example.com", remote_ip: "10.0.0.2", remote_port: 443, bytes_up: 50, bytes_down: 5, start_ns: 2, evidence: "E1" },
    { id: 3, proc_uid: "b", domain: null, remote_ip: "192.0.2.9", remote_port: 53, bytes_up: null, bytes_down: 12, start_ns: 3, evidence: "E1" },
  ].map(toNetFlow);

  it("groups by domain with the flows underneath and IP for a flow with no domain", () => {
    const groups = groupFlows(rows, "domain");
    expect(groups.map((g) => g.key)).toEqual(["api.example.com", "192.0.2.9"]);
    expect(groups[0]).toMatchObject({ connections: 2, bytes_up: 150, bytes_down: 1005, evidence: "S" });
    expect(groups[0].flows.map((f) => f.id)).toEqual([1, 2]);
    // An unobserved byte count is not added as zero.
    expect(groups[1].bytes_up).toBeNull();
  });

  it("groups by port and process", () => {
    expect(groupFlows(rows, "port").map((g) => g.key).sort()).toEqual(["443", "53"]);
    expect(groupFlows(rows, "proc").map((g) => g.connections).sort()).toEqual([1, 2]);
  });
});

import { dispositionName, fetchExport, parseSse, subscribeLive } from "./client";

describe("export and live go through the request layer", () => {
  afterEach(() => {
    delete (window as unknown as { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__;
    vi.restoreAllMocks();
    setToken(null);
  });

  it("browser: export sends the bearer token and keeps zip bytes intact", async () => {
    setToken("k-test");
    const zip = new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0xff, 0x00, 0x80]);
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(zip, { status: 200, headers: { "content-disposition": 'attachment; filename="s1.zip"' } }),
    );
    const file = await fetchExport("s1", "csv");
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/v1/sessions/s1/export?format=csv");
    expect(new Headers((init as RequestInit).headers).get("authorization")).toBe("Bearer k-test");
    expect(file.name).toBe("s1.zip");
    expect(new Uint8Array(await file.blob.arrayBuffer())).toEqual(zip);
  });

  it("desktop: export uses the binary-safe channel command", async () => {
    const invoke = vi.fn().mockResolvedValue({ status: 200, headers: {}, body_base64: btoa("PK\u0003\u0004\u00ff") });
    (window as unknown as { __TAURI_INTERNALS__: unknown }).__TAURI_INTERNALS__ = { invoke };
    const file = await fetchExport("s1", "csv");
    expect(invoke).toHaveBeenCalledWith("aw_request_bytes", expect.objectContaining({ target: "/api/v1/sessions/s1/export?format=csv" }));
    expect(Array.from(new Uint8Array(await file.blob.arrayBuffer()))).toEqual([0x50, 0x4b, 3, 4, 0xff]);
    expect(file.name).toBe("s1.zip");
  });

  it("an export error is thrown, not navigated to", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response('{"error":{"code":"unauthorized","message":"bearer token required"}}', { status: 401 }),
    );
    await expect(fetchExport("s1", "md")).rejects.toMatchObject({ status: 401, code: "unauthorized" });
  });

  it("parses the daemon's SSE frames and filename headers", () => {
    const frames = parseSse('retry: 1000\nid: 7\nevent: record\ndata: {"a":1}\n\n: keepalive\n\n');
    expect(frames).toEqual([{ event: "record", data: '{"a":1}', id: "7" }]);
    expect(dispositionName('attachment; filename="x.md"')).toBe("x.md");
  });

  it("live: polls /live with the token and advances the cursor", async () => {
    vi.useFakeTimers();
    setToken("k-live");
    const fetchMock = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(new Response('id: 3\nevent: record\ndata: {"cat":"proc"}\n\n', { status: 200 }))
      .mockResolvedValue(new Response(": keepalive\n\n", { status: 200 }));
    const records: unknown[] = [];
    const close = subscribeLive("s1", "", { onRecord: (r) => records.push(r), onLagged: () => {}, onError: () => {} });
    await vi.waitFor(() => expect(records).toHaveLength(1));
    await vi.advanceTimersByTimeAsync(1000);
    close();
    vi.useRealTimers();
    expect(new Headers((fetchMock.mock.calls[0][1] as RequestInit).headers).get("authorization")).toBe("Bearer k-live");
    expect(String(fetchMock.mock.calls[1][0])).toContain("cursor=3");
  });
});
