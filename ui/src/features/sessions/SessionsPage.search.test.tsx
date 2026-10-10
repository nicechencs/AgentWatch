/**
 * The session search box sends `q` to the daemon list, debounced. The clear
 * regression test guards that no re-render, refetch, or debounce writes stale
 * text back after select-all + one Backspace.
 */
import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render } from "@testing-library/react";
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

const EXIT = row("s-exit", ["sh", "-c", "exit 3"]);
const SLEEP = row("s-sleep", ["sleep", "5"]);

function callsWithQ(): unknown[] {
  return sessions.mock.calls.map((call) => (call[0] as { q?: string }).q).filter((q) => q !== undefined);
}

describe("session list search", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    sessions.mockReset();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("sends q once, after typing pauses, and keeps the previous rows until the answer arrives", async () => {
    let resolveSearch: ((value: { items: ReturnType<typeof row>[]; next_cursor: null }) => void) | undefined;
    sessions.mockImplementation((query: { q?: string }) => {
      if (query.q === undefined) return Promise.resolve({ items: [EXIT, SLEEP], next_cursor: null });
      return new Promise((resolve) => {
        resolveSearch = resolve;
      });
    });
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
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(container.textContent).toContain("exit 3");
    expect(container.textContent).toContain("sleep 5");
    expect(sessions).toHaveBeenCalledTimes(1);
    expect((sessions.mock.calls[0]?.[0] as { q?: string }).q).toBeUndefined();

    // Fast typing is one request, not one per keystroke, and the rows stay.
    fireEvent.change(input, { target: { value: " e" } });
    fireEvent.change(input, { target: { value: " exit" } });
    fireEvent.change(input, { target: { value: "  exit 3  " } });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(249);
    });
    expect(callsWithQ()).toEqual([]);
    // The debounce fires here. React Query then notifies on its own timer, so
    // that one is flushed separately: running everything in one act swallows it.
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1);
    });
    expect(callsWithQ()).toEqual(["exit 3"]);
    expect(container.textContent).toContain("sleep 5");
    expect(container.textContent).not.toContain(ZH["common.loading"]);
    await act(async () => {
      resolveSearch?.({ items: [EXIT], next_cursor: null });
      await vi.runOnlyPendingTimersAsync();
    });
    expect(container.textContent).toContain("sh -c exit 3");
    expect(container.textContent).not.toContain("sleep 5");

    // A re-render while the field holds text React has not seen as a change
    // must not write old text back.
    input.value = "exit 3!";
    rerender(page);
    expect(input.value).toBe("exit 3!");
  });

  it("shows the empty state for the term that was actually searched", async () => {
    sessions.mockImplementation(async (query: { q?: string }) => ({
      items: query.q ? [] : [EXIT, SLEEP],
      next_cursor: null,
    }));
    const { SessionsPage } = await import("@/features/sessions/SessionsPage");
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const { container } = render(
      <QueryClientProvider client={client}>
        <SessionsPage />
      </QueryClientProvider>,
    );
    const input = container.querySelector<HTMLInputElement>('form[role="search"] input[name="q"]');
    if (!input) throw new Error("no search input");
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });

    fireEvent.change(input, { target: { value: "zzqq" } });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(250);
    });
    await act(async () => {
      await vi.runOnlyPendingTimersAsync();
    });
    expect(callsWithQ()).toEqual(["zzqq"]);
    expect(container.textContent).toContain(t("sessions.noMatch", { q: "zzqq" }));
    expect(container.textContent).not.toContain(ZH["sessions.empty"]);
    expect(EN["sessions.noMatch"]).toBe('No session matches "{q}"');
    expect(EN["sessions.noMatch"]).not.toContain("：");
  });

  it("stays empty after select-all and one clear, even when a refetch resolves afterwards", async () => {
    const pending: ((value: { items: ReturnType<typeof row>[]; next_cursor: null }) => void)[] = [];
    sessions.mockImplementation((query: { q?: string }) => {
      if (query.q === undefined) return Promise.resolve({ items: [EXIT, SLEEP], next_cursor: null });
      // Every request for the old term waits on the same answer, so one that
      // starts after the clear still lands once that answer arrives.
      return new Promise((resolve) => {
        pending.push(resolve);
      });
    });
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
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });

    fireEvent.change(input, { target: { value: "exit 3" } });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(250);
    });

    // Clear the DOM in one step, then resolve the old request before the browser
    // delivers its input event. The intervening render must leave it empty.
    input.select();
    fireEvent.keyDown(input, { key: "Backspace" });
    input.value = "";
    await act(async () => {
      for (const resolve of pending.splice(0)) resolve({ items: [EXIT], next_cursor: null });
      await vi.runOnlyPendingTimersAsync();
    });
    rerender(page);
    expect(input.value).toBe("");

    // Now deliver the browser event for that one Backspace. The debounced
    // clear must issue an unfiltered request, with `q` omitted.
    fireEvent.input(input);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(250);
    });
    await act(async () => {
      await vi.runOnlyPendingTimersAsync();
    });
    expect(input.value).toBe("");
    // The cleared query is sent once the old term's answer has landed.
    const sent = sessions.mock.calls.map((call) => (call[0] as { q?: string }).q);
    expect(sent).toEqual([undefined, "exit 3", undefined]);
  });
});
