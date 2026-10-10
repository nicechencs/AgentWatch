/**
 * One test per finding in the UI review of #143 tip dbb5670
 * (qa-issues/UI-AW143-dbb5670.md). Each would have failed on that tip.
 * Daemon bodies below were copied from a running agentwatchd on 2026-10-10.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { ApiError, describeError } from "@/api/errors";
import { parseSse, subscribeLive, toDoctor, toProcessNode, toSearchResult, toSession } from "@/api/client";
import { capabilitiesUnknown, coverage, kindLabel, uncollectedKinds } from "@/lib/capabilities";
import { diskUnavailableText, diskUsed } from "@/lib/disk";
import { dayKey, isWallTime } from "@/lib/format";
import { agentEventToItem } from "@/features/self-report/api";
import zh from "@/i18n/zh.json";
import en from "@/i18n/en.json";

const ZH = zh as Record<string, string>;
const t = (key: string, vars?: Record<string, string | number>) =>
  (ZH[key] ?? key).replace(/\{(\w+)\}/gu, (_, name: string) => String(vars?.[name] ?? `{${name}}`));

vi.mock("@/lib/i18n", () => ({ useI18n: () => ({ lang: "zh", t }) }));
vi.mock("@/lib/prefs", () => ({ usePrefs: () => ({ lang: "zh", theme: "system", timeFormat: "utc" }) }));

const pollSession = toSession({
  id: "s1",
  session_id: 1,
  mode: "run",
  started_ns: 5,
  collectors: [
    {
      name: "poll",
      mode: "S",
      capabilities: [
        { kind: "proc", evidence: "S" },
        { kind: "file", evidence: "NA", na_reason: "collector_unavailable" },
        { kind: "net", evidence: "NA", na_reason: "collector_unavailable" },
        { kind: "dns", evidence: "NA", na_reason: "collector_unavailable" },
      ],
    },
  ],
});

describe("#1 new-session page white screen", () => {
  it("maps the daemon's unprobed doctor body without a capability list", () => {
    // The page read `doctor.capabilities.filter(...)` on this body and threw.
    const doctor = toDoctor({
      probed: false,
      reason: "collector probe is not run on the request path",
      collectors: [],
      host: { os: "linux", privileged: false, privileged_note: "poll collector only" },
    });
    expect(doctor.capabilities).toEqual([]);
    expect(doctor.probed).toBe(false);
    expect(doctor.platform).toBe("linux");
    expect(doctor.privileged).toBe(false);
  });
});

describe("#2 search Enter white screen", () => {
  it("groups the daemon's flat hits; time and text stay null", () => {
    // The daemon answers {hits:[...]}; the page read result.groups.map and threw.
    const result = toSearchResult({ hits: [{ src: "process_images", src_id: 7, session_id: 1, public_id: "s1" }] });
    expect(result.groups).toHaveLength(1);
    expect(result.groups[0].hits[0]).toMatchObject({ kind: "proc", id: 7, ts_ns: null, summary: null });
  });
  it("tolerates an empty or odd body", () => {
    expect(toSearchResult({}).groups).toEqual([]);
    expect(toSearchResult(null).groups).toEqual([]);
  });
});

describe("root error text", () => {
  it("a non-JSON or 501 body does not crash ApiError and reads in Chinese", () => {
    const err = new ApiError(501, { not: "error-shaped" } as never, "Not Implemented");
    expect(describeError(err, t)).toBe(ZH["error.notImplemented"]);
    expect(describeError(new ApiError(401, null, ""), t)).toMatch(/aw ui/u);
    expect(describeError(new ApiError(500, null, ""), t)).toContain("500");
  });
});

describe("#4 follow latest un-ticks itself", () => {
  afterEach(() => vi.unstubAllGlobals());
  it("parses the live body and keeps the cursor", () => {
    const events = parseSse("id: 3\nevent: record\ndata: {\"id\":3,\"cat\":\"proc\",\"ts_ns\":1}\n\n: keepalive\n\nevent: lagged\ndata: {}\n\n");
    expect(events.map((e) => e.event)).toEqual(["record", "lagged"]);
    expect(events[0].id).toBe(3);
  });
  it("sends the bearer header and keeps polling after an error", async () => {
    // EventSource could not send the header, got 401 and the page unticked.
    vi.useFakeTimers();
    const calls: RequestInit[] = [];
    let n = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url: string, init: RequestInit) => {
        calls.push(init);
        n += 1;
        if (n === 1) return new Response("{}", { status: 503 });
        return new Response("id: 1\nevent: record\ndata: {\"id\":1,\"cat\":\"proc\",\"ts_ns\":1}\n\n", { status: 200 });
      }),
    );
    const onError = vi.fn();
    const onRecord = vi.fn();
    const stop = subscribeLive("s1", "", { onRecord, onLagged: () => {}, onError }, 10);
    await vi.advanceTimersByTimeAsync(50);
    stop();
    vi.useRealTimers();
    expect(onError).toHaveBeenCalledTimes(1);
    expect(onRecord).toHaveBeenCalled();
    expect(calls.length).toBeGreaterThan(1);
  });
});

describe("#5 not collected is not 'no records'", () => {
  it("files and network on a poll session are not_collected", () => {
    expect(coverage(pollSession, "file")).toBe("not_collected");
    expect(coverage(pollSession, "proc")).toBe("collected");
    expect(uncollectedKinds(pollSession)).toEqual(["file", "net", "dns"]);
  });
  it("a session with no capability list is unknown, not complete", () => {
    const bare = toSession({ id: "s2", session_id: 2, collectors: ["poll"] });
    expect(coverage(bare, "file")).toBe("unknown");
    expect(capabilitiesUnknown(bare)).toBe(true);
  });
  it("renders 没采 and never 没有记录", async () => {
    const { CoverageNote, NotCollected } = await import("@/components/NotCollected");
    render(
      <>
        <CoverageNote kind="file" coverage="not_collected" />
        <NotCollected kind="net" />
      </>,
    );
    expect(document.body.textContent).toContain("没采");
    expect(document.body.textContent).not.toContain("没有记录");
  });
});

describe("#6 process names", () => {
  it("uses exe_name from the daemon, else the image path, and filters by it", async () => {
    const { filterByName, processName } = await import("@/features/processes/ProcessesPage");
    const named = toProcessNode({ proc_uid: "u1", pid: 10, exe_name: "node", children: [] });
    expect(processName(named)).toBe("node");
    const fromImages = toProcessNode({ proc_uid: "u2", pid: 11, images: [{ exe: "/bin/bash" }], children: [] });
    expect(processName(fromImages)).toBe("bash");
    const rows = [named, fromImages].map((node) => ({ node, depth: 0 })) as never;
    expect(filterByName(rows, "BAS")).toHaveLength(1);
    expect(filterByName(rows, "10")).toHaveLength(1);
  });
});

describe("#10 self-report list", () => {
  it("maps an agent event row to a timeline item", () => {
    const item = agentEventToItem({ id: 4, ts_ns: 9, kind: "tool_call", tool: "Bash", summary: "ls" });
    expect(item.id).toBe(4);
    expect(item.ts_ns).toBe(9);
  });
  it("no string claims the list is missing", () => {
    expect(Object.values(ZH).join("\n")).not.toMatch(/没有 agent-events 列表/u);
  });
});

describe("details", () => {
  it("timeline categories read in Chinese", () => {
    expect(kindLabel(t, "proc")).toBe("进程");
    expect(kindLabel(t, "made_up")).toBe("made_up");
  });
  it("cross-day times get a day key", () => {
    const day = 86_400_000_000_000;
    expect(dayKey(0, true)).not.toBe(dayKey(day, true));
    expect(dayKey(0, true)).toBe(dayKey(day - 1, true));
  });
  it("a monotonic tick is not shown as 01/01 08:00", async () => {
    expect(isWallTime(250_000_001)).toBe(false);
    expect(isWallTime(0)).toBe(false);
    expect(isWallTime(1_760_000_000_000_000_000)).toBe(true);
    const { TimelineTime } = await import("@/features/timeline/TimelineTime");
    render(<TimelineTime ns={250_000_001} sessionStart={null} />);
    expect(document.body.textContent).toContain(ZH["timeline.timeNa"]);
    expect(document.body.textContent).not.toContain("01/01");
  });
  it("a process row does not print its name twice", async () => {
    const { redundantSummary } = await import("@/features/timeline/TimelinePage");
    expect(redundantSummary({ summary: "node(280)", proc: { pid: 280, exe_name: "node" } as never })).toBe(true);
    expect(redundantSummary({ summary: "pid 7", proc: { pid: 7, exe_name: null } as never })).toBe(true);
    expect(redundantSummary({ summary: "GET /x", proc: { pid: 7, exe_name: null } as never })).toBe(false);
  });
  it("disk usage unavailable is one sentence, not 不可得 / 不可得", () => {
    const stats = { available: false, reason: "per-user stats are not exported", db_bytes: null, wal_bytes: null } as never;
    expect(diskUsed(stats)).toBeNull();
    expect(diskUnavailableText(stats, t)).toBe(ZH["disk.unavailablePerUser"]);
    expect(diskUsed({ db_bytes: 10, wal_bytes: 2 } as never)).toBe(12);
  });
  it("user-facing Chinese strings carry no 'daemon' developer word", () => {
    const leaks = Object.entries(ZH).filter(([, v]) => /\bdaemon\b(?! (start|stop|status|restart|logs))/u.test(v));
    expect(leaks).toEqual([]);
  });
  it("zh and en have the same keys", () => {
    expect(Object.keys(ZH).sort()).toEqual(Object.keys(en).sort());
  });
  it("every t() key used in source exists in zh", () => {
    const sources = import.meta.glob<string>("/src/**/*.tsx", { query: "?raw", import: "default", eager: true });
    const missing = new Set<string>();
    for (const [path, text] of Object.entries(sources)) {
      if (path.includes(".test.")) continue;
      for (const m of text.matchAll(/\bt\("([a-zA-Z0-9_.]+)"/gu)) if (!(m[1] in ZH)) missing.add(m[1]);
    }
    expect([...missing]).toEqual([]);
  });
  it("the root error page is Chinese, not 'Something went wrong!'", async () => {
    const { AppError } = await import("@/components/AppError");
    render(<AppError error={new Error("boom")} />);
    expect(screen.getByRole("alert").textContent).toContain(ZH["error.page.title"]);
    expect(document.body.textContent).not.toMatch(/Something went wrong/u);
  });
});
