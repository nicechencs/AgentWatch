/**
 * Test-bot findings on #144 (capability wording + session-list refresh).
 * One block per finding. The native window is not required: the page side
 * of the capability sentence and the list refetch interval are tested here.
 */
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";
import { render } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { toDoctor, toSession } from "@/api/client";
import zh from "@/i18n/zh.json";
import en from "@/i18n/en.json";
import { RECORDING_REFRESH_MS, refreshListWhileRecording } from "@/lib/live-session";

const ZH = zh as Record<string, string>;
const EN = en as Record<string, string>;
const locale = { lang: "zh" as "zh" | "en" };
const t = (key: string, vars?: Record<string, string | number>) =>
  ((locale.lang === "en" ? EN : ZH)[key] ?? key).replace(/\{(\w+)\}/gu, (_, name: string) => String(vars?.[name] ?? `{${name}}`));

vi.mock("@/lib/i18n", () => ({ useI18n: () => ({ lang: locale.lang, t }) }));
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

  it("2: English strings use ASCII colon and lowercase kinds", () => {
    expect(EN["common.colon"]).toBe(": ");
    expect(EN["new.capNotCollected"]).not.toContain("：");
    expect(EN["coverage.kinds.file"]).toBe("files");
    const fullwidth = Object.entries(EN).filter(([, value]) => value.includes("："));
    expect(fullwidth).toEqual([]);
  });

  it("2: every English catalog (main, proxy, network) is free of 「：」 and has an entry for every key", async () => {
    const { proxyCatalogs } = await import("@/features/settings/proxy/strings");
    const { netCatalogs } = await import("@/features/network/strings");
    const catalogs: [string, Record<string, string>, Record<string, string>][] = [
      ["i18n", ZH, EN],
      ["proxy", proxyCatalogs.zh, proxyCatalogs.en],
      ["network", netCatalogs.zh, netCatalogs.en],
    ];
    for (const [name, zhCat, enCat] of catalogs) {
      const fullwidth = Object.entries(enCat).filter(([, value]) => value.includes("："));
      expect(fullwidth, name).toEqual([]);
      const missing = Object.keys(zhCat).filter((key) => !(key in enCat) || enCat[key] === "");
      expect(missing, name).toEqual([]);
    }
    expect(proxyCatalogs.en.colon).toBe(": ");
    expect(netCatalogs.en.colon).toBe(": ");
    expect(proxyCatalogs.zh.colon).toBe("：");
  });

  it("2: no component hard-codes 「：」 next to a label", async () => {
    // Labels and values are joined with the locale colon; a literal 「：」 in a
    // component would show up in the English UI.
    const files = import.meta.glob("/src/**/*.tsx", { query: "?raw", import: "default", eager: true }) as Record<string, string>;
    expect(Object.keys(files).length).toBeGreaterThan(20);
    const offenders = Object.entries(files)
      .filter(([path]) => !path.includes(".test.") && !path.includes("/review/"))
      .flatMap(([path, text]) =>
        text
          .split("\n")
          .map((line, index) => ({ path, line: index + 1, text: line.trim() }))
          .filter((row) => row.text.includes("：") && !row.text.startsWith("//") && !row.text.startsWith("*") && !row.text.startsWith("/*")),
      );
    expect(offenders).toEqual([]);
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

  it("4: English uses one term for purge and lowercase kinds mid-sentence in Settings", async () => {
    expect(EN["settings.purgeNeedsAdmin"]).toContain(`"${EN["settings.purgeNow"]}"`);
    expect(ZH["settings.purgeNeedsAdmin"]).toContain(`「${ZH["settings.purgeNow"]}」`);
    const { Collectors } = await import("@/features/settings/SettingsPage");
    const client = new QueryClient();
    client.setQueryData(
      ["doctor"],
      toDoctor({
        probed: true,
        collectors: [
          {
            name: "poll",
            status: "running",
            running: true,
            daemon_sample: true,
            watched_roots: 0,
            capabilities: [
              { kind: "proc", evidence: "S" },
              { kind: "file", evidence: "NA" },
              { kind: "net", evidence: "NA" },
              { kind: "dns", evidence: "NA" },
            ],
          },
        ],
        capabilities: [],
        host: { os: "linux" },
      }),
    );
    locale.lang = "en";
    try {
      const { container } = render(
        <QueryClientProvider client={client}>
          <Collectors />
        </QueryClientProvider>,
      );
      const text = container.textContent ?? "";
      expect(text).toContain("processes collected, files not collected, network traffic not collected, DNS not collected");
      expect(text).not.toMatch(/\bFile\b/u);
      expect(text).not.toContain("：");
    } finally {
      locale.lang = "zh";
    }
  });
});
