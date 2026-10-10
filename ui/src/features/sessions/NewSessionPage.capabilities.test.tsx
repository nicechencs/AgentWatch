/**
 * The new-session capability list is the same list the overview shows, and
 * the "not collected" sentence gives the plain reason rather than the NA
 * badge's wording.
 */
import { describe, expect, it, vi } from "vitest";
import { render } from "@testing-library/react";
import { toDoctor } from "@/api/client";
import zh from "@/i18n/zh.json";

const ZH = zh as Record<string, string>;
const t = (key: string, vars?: Record<string, string | number>) =>
  (ZH[key] ?? key).replace(/\{(\w+)\}/gu, (_, name: string) => String(vars?.[name] ?? `{${name}}`));

vi.mock("@/lib/i18n", () => ({ useI18n: () => ({ lang: "zh", t }) }));
vi.mock("@/lib/prefs", () => ({ usePrefs: () => ({ lang: "zh", theme: "system", timeFormat: "utc" }) }));
vi.mock("@/lib/auth", () => ({ useAuth: () => ({ me: { admin: false } }) }));

describe("new-session capabilities", () => {
  it("gets the same capability list as the overview", () => {
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

  it("says 没采 with the plain reason", async () => {
    const { CapabilityList } = await import("@/features/sessions/NewSessionPage");
    const view = render(
      <CapabilityList
        capabilities={[
          { kind: "proc", evidence: "S", available: true, na_reason: null, note: null },
          { kind: "file", evidence: null, available: false, na_reason: "collector_unavailable", note: null },
          { kind: "net", evidence: null, available: false, na_reason: "collector_unavailable", note: null },
          { kind: "dns", evidence: null, available: false, na_reason: "collector_unavailable", note: null },
        ]}
      />,
    );
    const notes = view.container.querySelectorAll("[data-not-collected]");
    expect(notes).toHaveLength(1);
    const expected = t("new.capNotCollected", {
      kinds: [t("coverage.kinds.file"), t("coverage.kinds.net"), t("coverage.kinds.dns")].join(t("common.listSep")),
      reason: t("new.capReasonNotRunning"),
    });
    expect(notes[0]?.textContent).toBe(expected);
    const text = notes[0]?.textContent ?? "";
    expect(text).not.toContain(ZH["na.collector_unavailable"]);
    expect(text).not.toContain("不可得");
  });
});
