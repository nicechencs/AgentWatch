import type { ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
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
vi.mock("@/lib/use-export", () => ({ useExport: () => ({ pending: null, error: null, notice: null, run: () => undefined }) }));
vi.mock("@tanstack/react-router", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@tanstack/react-router")>()),
  useNavigate: () => () => undefined,
  Link: ({ children }: { children?: ReactNode }) => <a>{children}</a>,
}));

const base = { id: "s-1", session_id: 1, name: "sleep", mode: "launch", started_ns: 1, collectors: [] };

describe("session list stop action", () => {
  afterEach(() => vi.restoreAllMocks());

  it("stops recording and keeps the program-running notice in the row", async () => {
    const active = toSession({ ...base, ended_ns: null, end_reason: null });
    const stopped = toSession({ ...base, ended_ns: 2, end_reason: "user_stop" });
    vi.spyOn(api, "sessions").mockResolvedValue({ items: [active], next_cursor: null });
    vi.spyOn(api, "dbStats").mockResolvedValue({ available: false } as never);
    const stop = vi.spyOn(api, "stopSession").mockResolvedValue(stopped);
    const { SessionsPage } = await import("@/features/sessions/SessionsPage");
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={client}><SessionsPage /></QueryClientProvider>);

    const button = await screen.findByRole("button", { name: "停止记录" });
    fireEvent.click(button);
    await waitFor(() => expect(stop).toHaveBeenCalledWith("s-1"));
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("程序还在运行，只是不再记录"));
  });
});
