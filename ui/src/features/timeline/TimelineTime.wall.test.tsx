/**
 * Timeline times. A monotonic tick is not shown as a calendar date, and only
 * rows the service marks pre-existing get 「会话开始前已存在」.
 */
import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { toTimelineItem } from "@/api/client";
import { isWallTime } from "@/lib/format";
import zh from "@/i18n/zh.json";

const ZH = zh as Record<string, string>;
const t = (key: string, vars?: Record<string, string | number>) =>
  (ZH[key] ?? key).replace(/\{(\w+)\}/gu, (_, name: string) => String(vars?.[name] ?? `{${name}}`));

vi.mock("@/lib/i18n", () => ({ useI18n: () => ({ lang: "zh", t }) }));
vi.mock("@/lib/prefs", () => ({ usePrefs: () => ({ lang: "zh", theme: "system", timeFormat: "utc" }) }));

describe("timeline times", () => {
  it("a monotonic tick is not shown as 01/01 08:00", async () => {
    expect(isWallTime(250_000_001)).toBe(false);
    expect(isWallTime(0)).toBe(false);
    expect(isWallTime(1_760_000_000_000_000_000)).toBe(true);
    const { TimelineTime } = await import("@/features/timeline/TimelineTime");
    render(<TimelineTime ns={250_000_001} sessionStart={null} />);
    expect(document.body.textContent).toContain(ZH["timeline.timeNa"]);
    expect(document.body.textContent).not.toContain("01/01");
  });

  it("only rows the service marks pre-existing get 「会话开始前已存在」", async () => {
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
});
