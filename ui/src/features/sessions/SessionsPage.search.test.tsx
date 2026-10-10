/**
 * The session search box filters the rows already fetched. The daemon list
 * ignores `q`, so typing must not refetch, and a re-render while typing must
 * not write old text back into the field.
 */
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";
import { fireEvent, render } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { toSession } from "@/api/client";
import zh from "@/i18n/zh.json";
import en from "@/i18n/en.json";

const ZH = zh as Record<string, string>;
const EN = en as Record<string, string>;
const t = (key: string, vars?: Record<string, string | number>) =>
  (ZH[key] ?? key).replace(/\{(\w+)\}/gu, (_, name: string) => String(vars?.[name] ?? `{${name}}`));

const sessions = vi.hoisted(() => vi.fn());

vi.mock("@/api/client", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/api/client")>()),
  api: { sessions, dbStats: vi.fn(async () => ({ available: false })) },
}));
vi.mock("@/lib/i18n", () => ({ useI18n: () => ({ lang: "zh", t }) }));
vi.mock("@/lib/prefs", () => ({ usePrefs: () => ({ lang: "zh", theme: "system", timeFormat: "utc" }) }));
vi.mock("@/lib/auth", () => ({ useAuth: () => ({ me: { admin: false } }) }));
vi.mock("@tanstack/react-router", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@tanstack/react-router")>()),
  useNavigate: () => () => undefined,
  Link: ({ children }: { children?: ReactNode }) => <a>{children}</a>,
}));

const row = (id: string, argv: string[]) =>
  toSession({ id, session_id: 1, mode: "launch", started_ns: 1, ended_ns: 2, argv });

describe("session list search", () => {
  it("filters the fetched rows and never refetches while typing", async () => {
    sessions.mockResolvedValue({ items: [row("s-exit", ["sh", "-c", "exit 3"]), row("s-sleep", ["sleep", "5"])], next_cursor: null });
    const { SessionsPage } = await import("@/features/sessions/SessionsPage");
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const page = (
      <QueryClientProvider client={client}>
        <SessionsPage />
      </QueryClientProvider>
    );
    const { container, rerender } = render(page);
    const input = container.querySelector<HTMLInputElement>('form[role="search"] input[name="q"]');
    if (!input) throw new Error("no search input");
    await vi.waitFor(() => expect(container.textContent).toContain("exit 3"));
    expect(container.textContent).toContain("sleep 5");
    expect(sessions).toHaveBeenCalledTimes(1);
    expect(sessions.mock.calls[0]?.[0]).not.toHaveProperty("q");

    const user = userEvent.setup();
    await user.type(input, "exit 3");
    expect(container.textContent).toContain("sh -c exit 3");
    expect(container.textContent).not.toContain("sleep 5");
    expect(sessions).toHaveBeenCalledTimes(1);

    // A re-render while typing (the desktop window re-renders on channel
    // replies) must not write old text back, including text the field holds
    // that React has not seen as a change yet.
    input.value = "exit 3!";
    rerender(page);
    expect(input.value).toBe("exit 3!");

    await user.clear(input);
    await user.type(input, "zzqq");
    expect(container.textContent).toContain(t("sessions.noMatch", { q: "zzqq" }));
    expect(container.textContent).not.toContain(ZH["sessions.empty"]);
    expect(container.textContent).not.toContain("sleep 5");
    // Typing never refetches, and `q` is never sent.
    expect(sessions).toHaveBeenCalledTimes(1);
    for (const call of sessions.mock.calls) expect(call[0]).not.toHaveProperty("q");

    fireEvent.submit(input.form as HTMLFormElement);
    expect(sessions).toHaveBeenCalledTimes(1);
    expect(EN["sessions.noMatch"]).toBe('No session matches "{q}"');
    expect(EN["sessions.noMatch"]).not.toContain("：");
  });
});
