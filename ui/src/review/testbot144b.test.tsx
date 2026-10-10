/**
 * Test-bot findings on #144 (capability wording + session-list refresh).
 * One block per finding. The native window is not required: the page side
 * of the capability sentence and the list refetch interval are tested here.
 */
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";
import { render } from "@testing-library/react";
import { toSession } from "@/api/client";
import zh from "@/i18n/zh.json";
import en from "@/i18n/en.json";
import { RECORDING_REFRESH_MS, refreshListWhileRecording } from "@/lib/live-session";

const ZH = zh as Record<string, string>;
const EN = en as Record<string, string>;
const t = (key: string, vars?: Record<string, string | number>) =>
  (ZH[key] ?? key).replace(/\{(\w+)\}/gu, (_, name: string) => String(vars?.[name] ?? `{${name}}`));

vi.mock("@/lib/i18n", () => ({ useI18n: () => ({ lang: "zh", t }) }));
vi.mock("@/lib/prefs", () => ({ usePrefs: () => ({ lang: "zh", theme: "system", timeFormat: "utc" }) }));
vi.mock("@/lib/auth", () => ({ useAuth: () => ({ me: { admin: false } }) }));
vi.mock("@tanstack/react-router", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@tanstack/react-router")>()),
  useNavigate: () => () => undefined,
  Link: ({ children }: { children?: ReactNode }) => <a>{children}</a>,
}));

describe("Test-bot #144 capability wording and list refresh", () => {
  it("1: new-session capabilities say 没采 with the plain reason", async () => {
    const { CapabilityList } = await import("@/features/sessions/NewSessionPage");
    const view = render(
      <CapabilityList
        capabilities={[
          { kind: "proc", evidence: "S", available: true },
          { kind: "file", evidence: null, available: false, na_reason: "collector_unavailable" },
          { kind: "net", evidence: null, available: false, na_reason: "collector_unavailable" },
          { kind: "dns", evidence: null, available: false, na_reason: "collector_unavailable" },
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

  it("2: English strings use ASCII colon and lowercase kinds", () => {
    expect(EN["common.colon"]).toBe(": ");
    expect(EN["new.capNotCollected"]).not.toContain("：");
    expect(EN["coverage.kinds.file"]).toBe("files");
    const fullwidth = Object.entries(EN).filter(([, value]) => value.includes("："));
    expect(fullwidth).toEqual([]);
  });

  it("3: the session list re-reads while a listed session is recording", () => {
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
