/**
 * The Settings collector list reads the service's runtime state, and the
 * English wording uses lowercase category words mid-sentence.
 */
import { describe, expect, it, vi } from "vitest";
import { render } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { toDoctor } from "@/api/client";
import zh from "@/i18n/zh.json";
import en from "@/i18n/en.json";

const ZH = zh as Record<string, string>;
const EN = en as Record<string, string>;
const locale = { lang: "zh" as "zh" | "en" };
const t = (key: string, vars?: Record<string, string | number>) =>
  ((locale.lang === "en" ? EN : ZH)[key] ?? key).replace(/\{(\w+)\}/gu, (_, name: string) => String(vars?.[name] ?? `{${name}}`));

vi.mock("@/lib/i18n", () => ({ useI18n: () => ({ lang: locale.lang, t }) }));
vi.mock("@/lib/prefs", () => ({ usePrefs: () => ({ lang: "zh", theme: "system", timeFormat: "utc" }) }));
vi.mock("@/lib/auth", () => ({ useAuth: () => ({ me: { admin: false } }) }));

describe("settings collectors", () => {
  it("lists the running collector from the service's runtime state", async () => {
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

  it("uses one term for purge and lowercase kinds mid-sentence in English", async () => {
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
