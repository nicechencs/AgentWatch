import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { api, toSession } from "@/api/client";
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
  useParams: () => ({ sid: "s-1" }),
  Outlet: () => null,
  Link: ({ children }: { children?: ReactNode }) => <a>{children}</a>,
}));

function view(session: ReturnType<typeof toSession>, client = new QueryClient({ defaultOptions: { queries: { retry: false } } })) {
  client.setQueryData(["session", "s-1"], session);
  return {
    client,
    ...render(<QueryClientProvider client={client}><SessionLayout /></QueryClientProvider>),
  };
}

const base = { id: "s-1", session_id: 1, name: "sleep", mode: "launch", started_ns: 1, collectors: [] };
const { SessionLayout } = await import("@/features/shell/SessionLayout");

describe("session header stop action", () => {
  it("shows an interrupted reason in the header and title", () => {
    view(toSession({ ...base, ended_ns: 2, end_reason: "daemon_restart" }));
    const status = screen.getByText(/记录已中断/u);
    expect(status).toHaveTextContent("记录已中断 · 后台重启，记录已中断");
    expect(status).toHaveAttribute("title", "后台重启，记录已中断");
  });

  it("uses Stop recording wording and shows the success notice", async () => {
    const active = toSession({ ...base, ended_ns: null, end_reason: null });
    const stopped = toSession({ ...base, ended_ns: 2, end_reason: "user_stop" });
    const stop = vi.spyOn(api, "stopSession").mockResolvedValue(stopped);
    const session = vi.spyOn(api, "session").mockResolvedValue(stopped);
    view(active);

    fireEvent.click(screen.getByRole("button", { name: "停止记录" }));
    await waitFor(() => expect(stop).toHaveBeenCalledWith("s-1"));
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("程序还在运行，只是不再记录"));
    expect(session).toHaveBeenCalledWith("s-1");
    expect(screen.getByText("○ 已停止记录")).toBeInTheDocument();
  });
});
