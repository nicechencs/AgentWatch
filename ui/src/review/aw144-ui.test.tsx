/**
 * One test per finding in the UI re-review of #144 tip 5f68f938
 * (qa-issues/UI-AW144-5f68f938.md, 新-1 … 新-6).
 */
import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ApiError, describeError } from "@/api/errors";
import { toDoctor, toSession, toTimelineItem } from "@/api/client";
import { kindInSentence } from "@/lib/capabilities";
import { sessionTitle } from "@/lib/session-title";
import zh from "@/i18n/zh.json";
import en from "@/i18n/en.json";

const ZH = zh as Record<string, string>;
const EN = en as Record<string, string>;
const t = (key: string, vars?: Record<string, string | number>) =>
  (ZH[key] ?? key).replace(/\{(\w+)\}/gu, (_, name: string) => String(vars?.[name] ?? `{${name}}`));
const tEn = (key: string) => EN[key] ?? key;

vi.mock("@/lib/i18n", () => ({ useI18n: () => ({ lang: "zh", t }) }));
vi.mock("@/lib/prefs", () => ({ usePrefs: () => ({ lang: "zh", theme: "system", timeFormat: "utc" }) }));
vi.mock("@/lib/auth", () => ({ useAuth: () => ({ me: { admin: false } }) }));

describe("UI re-review #144", () => {
  it("新-1: a wrong program is worded in Chinese, not the daemon's English", () => {
    const err = new ApiError(400, { error: { code: "program_not_found", message: "the program or the working directory was not found" } }, "x");
    const text = describeError(err, t);
    expect(text).toBe(ZH["error.programNotFound"]);
    expect(text).not.toMatch(/entity|not found/u);
    // Launch refusals are 403s with their own plain Chinese sentence, never
    // the daemon's English and never "open a terminal".
    for (const code of ["launch_other_user", "caller_unidentified", "caller_unknown", "drop_failed"]) {
      const said = describeError(new ApiError(403, { error: { code, message: "the daemon starts programs only as its own user; use `aw run -- <cmd>`" } }, "x"), t);
      expect(said).not.toMatch(/\b[a-z]{4,}\b|终端|aw run/u);
      expect(said).not.toBe(ZH["error.forbidden"]);
    }
  });

  it("新-2: only rows the service marks pre_existing get 「会话开始前已存在」", async () => {
    const { TimelineTime } = await import("@/features/timeline/TimelineTime");
    const start = 1_760_000_000_000_000_000;
    // Launched by the session: start time reads 0.4 s before the session (whole seconds), not tagged.
    const launched = toTimelineItem({ cat: "proc", id: 1, ts_ns: start - 400_000_000, evidence: "S", pre_existing: false });
    const { container, unmount } = render(<TimelineTime ns={launched.ts_ns} sessionStart={start} preExisting={launched.pre_existing} />);
    expect(container.textContent).not.toContain(ZH["timeline.beforeSession"]);
    unmount();
    // Running before an attach session began: tagged.
    const baseline = toTimelineItem({ cat: "proc", id: 2, ts_ns: start - 3_600_000_000_000, evidence: "S", pre_existing: true });
    render(<TimelineTime ns={baseline.ts_ns} sessionStart={start} preExisting={baseline.pre_existing} />);
    expect(screen.getByText(ZH["timeline.beforeSession"])).toBeTruthy();
    // A row without the field (live stream) is not tagged.
    expect(toTimelineItem({ cat: "proc", id: 3, ts_ns: 1 }).pre_existing).toBe(false);
  });

  it("新-3: Settings lists the running collector from the service's runtime state", async () => {
    const { Collectors } = await import("@/features/settings/SettingsPage");
    const client = new QueryClient();
    client.setQueryData(
      ["doctor"],
      toDoctor({
        probed: true,
        collectors: [
          { name: "poll", status: "running", running: true, daemon_sample: true, watched_roots: 1, capabilities: [{ kind: "proc", evidence: "S" }, { kind: "file", evidence: "NA" }] },
          { name: "ebpf", status: "not_built", running: false, capabilities: [] },
        ],
        capabilities: [],
        host: { os: "linux" },
      }),
    );
    const { container } = render(
      <QueryClientProvider client={client}>
        <Collectors />
      </QueryClientProvider>,
    );
    const text = container.textContent ?? "";
    expect(text).toContain(ZH["settings.collectorName.poll"]);
    expect(text).toContain(t("settings.collectorRunningBoth", { count: 1 }));
    expect(text).toContain(ZH["settings.collectorNotBuilt"]);
    expect(text).not.toContain("未启用");
    expect(text).not.toMatch(/tls_uprobe|ipc_payload_peek|sni=/u);
  });

  it("新-4: the new-session page gets the same capability list as the overview", () => {
    const doctor = toDoctor({
      probed: true,
      collectors: [],
      capabilities: [
        { kind: "proc", evidence: "S", available: true },
        { kind: "file", evidence: "NA", na_reason: "collector_unavailable", available: false },
      ],
      host: { os: "linux" },
    });
    expect(doctor.capabilities.map((c) => [c.kind, c.available])).toEqual([["proc", true], ["file", false]]);
    // The fallback no longer repeats the section title.
    expect(ZH["new.capNotProbed"]).not.toContain(ZH["new.capabilities"]);
  });

  it("新-5: an unnamed session is called by its command", () => {
    const row = toSession({ id: "s-31988513fa4a", session_id: 3, started_ns: 1, argv: ["sleep", "90"], name: null });
    expect(sessionTitle(row)).toBe("sleep 90");
    expect(sessionTitle({ name: "重构", argv: ["sleep"], public_id: "s-1" })).toBe("重构");
    expect(sessionTitle({ name: null, argv: null, public_id: "s-1" })).toBe("s-1");
  });

  it("新-6: English sentences use lowercase category words", () => {
    expect(kindInSentence(tEn, "file")).toBe("files");
    const sentence = EN["coverage.notCollected"].replace(/\{kind\}/gu, kindInSentence(tEn, "file"));
    expect(sentence).toContain("does not collect files");
    expect(sentence).not.toMatch(/collect File/u);
  });
});
