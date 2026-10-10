/**
 * The session header links back to the session list: 「会话 / <title>」.
 */
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";
import { render } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { toSession } from "@/api/client";
import zh from "@/i18n/zh.json";

const ZH = zh as Record<string, string>;
const t = (key: string, vars?: Record<string, string | number>) =>
  (ZH[key] ?? key).replace(/\{(\w+)\}/gu, (_, name: string) => String(vars?.[name] ?? `{${name}}`));

vi.mock("@/lib/i18n", () => ({ useI18n: () => ({ lang: "zh", t }) }));
vi.mock("@/lib/prefs", () => ({ usePrefs: () => ({ lang: "zh", theme: "system", timeFormat: "utc" }) }));
vi.mock("@/lib/auth", () => ({ useAuth: () => ({ me: { admin: false } }) }));
vi.mock("@/lib/session-query", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/lib/session-query")>()),
  useSessionQuery: () => ({ query: { f: "", from: "", to: "", ev: "", subtree: "", proc: "" }, patch: () => undefined }),
  composedFilter: () => "",
}));
vi.mock("@/lib/use-export", () => ({ useExport: () => ({ pending: null, error: null, notice: null, run: () => undefined }) }));
vi.mock("@tanstack/react-router", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@tanstack/react-router")>()),
  useNavigate: () => () => undefined,
  useParams: () => ({ sid: "s-1" }),
  Outlet: () => null,
  Link: ({ to, children, ...rest }: { to: string; children?: ReactNode }) => (
    <a href={to} {...rest}>{children}</a>
  ),
}));

describe("session breadcrumb", () => {
  it("links 「会话」 to the session list", async () => {
    const { SessionLayout } = await import("@/features/shell/SessionLayout");
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    client.setQueryData(["session", "s-1"], toSession({ id: "s-1", session_id: 1, name: "sleep 60", mode: "launch", started_ns: 1, ended_ns: 2, collectors: [] }));
    const { container } = render(
      <QueryClientProvider client={client}>
        <SessionLayout />
      </QueryClientProvider>,
    );
    const link = container.querySelector<HTMLAnchorElement>("[data-breadcrumb='sessions']");
    expect(link?.textContent).toBe(ZH["nav.sessions"]);
    expect(link?.getAttribute("href")).toBe("/");
    expect(container.textContent).toContain("sleep 60");
  });
});
