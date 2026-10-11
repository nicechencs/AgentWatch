/**
 * Search copy from the UI review: the box searches collected records only
 * (processes in this version), and finding a session by name or command
 * happens on the session list — linked from the hint and the empty result.
 */
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import zh from "@/i18n/zh.json";
import en from "@/i18n/en.json";

const ZH = zh as Record<string, string>;
const EN = en as Record<string, string>;
const t = (key: string, vars?: Record<string, string | number>) =>
  (ZH[key] ?? key).replace(/\{(\w+)\}/gu, (_, name: string) => String(vars?.[name] ?? `{${name}}`));

const search = vi.hoisted(() => vi.fn());

vi.mock("@/api/client", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/api/client")>()),
  api: { search },
}));
vi.mock("@/lib/i18n", () => ({ useI18n: () => ({ lang: "zh", t }) }));
vi.mock("@tanstack/react-router", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@tanstack/react-router")>()),
  useNavigate: () => () => undefined,
  useSearch: () => ({ q: "zzqq", kind: "" }),
  Link: ({ to, children }: { to: string; children?: ReactNode }) => <a href={to}>{children}</a>,
}));

const EXAMPLE = "sleep 或 /usr/bin/python3";

describe("search page wording", () => {
  beforeEach(() => {
    search.mockReset();
    search.mockResolvedValue({ groups: [], fts_enabled: true });
  });

  it("points the hint and the empty result at the session list, with the query in the empty note", async () => {
    const { SearchPage } = await import("@/features/search/SearchPage");
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const { container } = render(
      <QueryClientProvider client={client}><SearchPage /></QueryClientProvider>,
    );

    const hint = `只搜各会话里已采到的记录（这一版只采进程）。要按会话名或命令找，请到会话列表里搜。`;
    expect(container.textContent).toContain(hint);
    expect(ZH["search.hint.before"] + ZH["search.hint.link"] + ZH["search.hint.after"]).toBe(hint);
    expect(EN["search.hint.before"] + EN["search.hint.link"] + EN["search.hint.after"]).toBe(
      "Searches only what was collected in each session (this version collects processes only). To find a session by name or command, search the session list.",
    );

    const empty = await screen.findByText(/已采到的记录里没有/);
    expect(empty.textContent).toBe(`已采到的记录里没有「zzqq」。会话名和命令不在这里搜，请到会话列表里搜。`);
    expect(EN["search.empty.before"] + "zzqq" + EN["search.empty.mid"] + EN["search.empty.link"] + EN["search.empty.after"]).toBe(
      'Nothing collected matches "zzqq". Session names and commands are not searched here; use the session list.',
    );

    const links = empty.ownerDocument.querySelectorAll<HTMLAnchorElement>("a[href='/']");
    expect([...links].map((link) => link.textContent)).toEqual(["会话列表", "会话列表"]);
    expect(EN["search.hint.link"]).toBe("session list");
    expect(EN["search.empty.link"]).toBe("session list");
  });

  it("uses a process example, not a credentials path", () => {
    expect(ZH["search.placeholder"]).toBe(`例如：${EXAMPLE}`);
    expect(ZH["search.hint.before"]).not.toContain("credentials");
    expect(EN["search.placeholder"]).toBe("e.g. sleep or /usr/bin/python3");
    for (const catalog of [ZH, EN]) {
      for (const key of Object.keys(catalog).filter((name) => name.startsWith("search."))) {
        expect(catalog[key], key).not.toContain(".aws");
      }
    }
  });
});
