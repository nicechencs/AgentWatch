/**
 * Test-bot real-window findings on #144 (normal user daemon + desktop app),
 * one block per finding. The native "Save As" dialog itself needs a real
 * window; here the page side of `aw_save_export` is tested, and the shell
 * side in app/src-tauri/src/export.rs.
 */
import type { ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider, type Query } from "@tanstack/react-query";
import { exportToFile, toSession, toSummary } from "@/api/client";
import { isApiError } from "@/api/errors";
import type { Session } from "@/api/types";
import { RECORDING_REFRESH_MS, refreshWhileRecording, summaryQueryOptions } from "@/lib/live-session";
import zh from "@/i18n/zh.json";
import en from "@/i18n/en.json";

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

type W = { __TAURI_INTERNALS__?: { invoke: (cmd: string, args?: Record<string, unknown>) => Promise<unknown> } };

afterEach(() => {
  delete (window as unknown as W).__TAURI_INTERNALS__;
  vi.restoreAllMocks();
});

describe("Test-bot #144 real-window findings", () => {
  it("1: in the app, export goes through the shell's Save As and reports the path", async () => {
    const invoke = vi.fn(async (cmd: string, args?: Record<string, unknown>) => {
      expect(cmd).toBe("aw_save_export");
      expect(args).toEqual({ sid: "s-1", format: "md" });
      return { status: 200, path: "/home/u/Documents/s-1.md", cancelled: false, error_body: null, bytes: 10 };
    });
    (window as unknown as W).__TAURI_INTERNALS__ = { invoke };
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    await expect(exportToFile("s-1", "md")).resolves.toEqual({ kind: "saved", path: "/home/u/Documents/s-1.md" });
    // No webview download link, so nothing lands in the launch directory.
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(t("export.savedTo", { path: "/home/u/Documents/s-1.md" })).toBe("已保存到 /home/u/Documents/s-1.md");
  });

  it("1: a cancelled dialog is silent; a daemon error is the daemon's error", async () => {
    let answer: unknown = { status: 200, path: null, cancelled: true, error_body: null, bytes: 0 };
    (window as unknown as W).__TAURI_INTERNALS__ = { invoke: async () => answer };
    await expect(exportToFile("s-1", "csv")).resolves.toEqual({ kind: "cancelled" });
    answer = { status: 404, path: null, cancelled: false, error_body: '{"error":{"code":"not_found","message":"session not found"}}', bytes: 0 };
    const caught = await exportToFile("s-1", "md").catch((err: unknown) => err);
    expect(isApiError(caught) && caught.status === 404 && caught.code === "not_found").toBe(true);
  });

  it("1: in a browser it stays a normal download; CSV is named and labelled as a zip", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(new Uint8Array([0x50, 0x4b]), { status: 200 }));
    URL.createObjectURL = vi.fn(() => "blob:x");
    URL.revokeObjectURL = vi.fn();
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
    await expect(exportToFile("s-1", "csv")).resolves.toEqual({ kind: "downloaded", name: "s-1.csv.zip" });
    expect(click).toHaveBeenCalledOnce();
    expect(ZH["session.export.csv"]).toBe("CSV（压缩包）");
    expect(EN["session.export.csv"]).toBe("CSV (zip)");
  });

  it("2 + 3: header and overview are re-read while recording and stop once ended", () => {
    const session = (ended: number | null) =>
      ({ state: { data: toSession({ id: "s-1", mode: "launch", started_ns: 1, ended_ns: ended }) } }) as unknown as Query<Session, Error>;
    // Recording: re-read, so 「录制中」 turns into 「已停止」 when the program exits
    // and 「0 进程」 read before the first sample is replaced.
    expect(refreshWhileRecording(session(null))).toBe(RECORDING_REFRESH_MS);
    expect(refreshWhileRecording(session(2))).toBe(false);
    const summary = summaryQueryOptions("s-1");
    expect(summary.queryKey).toEqual(["summary", "s-1"]);
    const summaryOf = (ended: number | null) =>
      ({ state: { data: { session: toSession({ id: "s-1", started_ns: 1, ended_ns: ended }) } } }) as never;
    expect(summary.refetchInterval(summaryOf(null))).toBe(RECORDING_REFRESH_MS);
    expect(summary.refetchInterval(summaryOf(2))).toBe(false);
  });

  it("4: a re-render while typing never writes old text back into the command box", async () => {
    const { LaunchForm } = await import("@/features/sessions/NewSessionPage");
    const onStart = vi.fn();
    const { container, rerender } = render(<LaunchForm pending={false} onStart={onStart} />);
    const input = container.querySelector<HTMLInputElement>('input[name="command"]');
    if (!input) throw new Error("no command input");
    const user = userEvent.setup();
    await user.type(input, "s");
    // The desktop window re-renders on channel replies. Text the field holds
    // that React has not seen as a change yet (input-method pending text)
    // must survive it: a controlled input reset it, dropping the first letter.
    input.value = "sl";
    rerender(<LaunchForm pending onStart={onStart} />);
    expect(input.value).toBe("sl");
    rerender(<LaunchForm pending={false} onStart={() => undefined} />);
    expect(input.value).toBe("sl");
    await user.type(input, "eep 60");
    expect(input.value).toBe("sleep 60");
    rerender(<LaunchForm pending={false} onStart={onStart} />);
    fireEvent.submit(input.form as HTMLFormElement);
    expect(onStart).toHaveBeenCalledWith(expect.objectContaining({ mode: "launch", argv: ["sleep", "60"] }));
  });

  it("2: before the first sample the overview says it is waiting, not 「0 进程」", async () => {
    const { Overview } = await import("@/features/overview/OverviewPage");
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response('{"findings":[]}', { status: 200 }));
    const summary = (ended: number | null, procs: number) =>
      toSummary({
        id: "s-1",
        mode: "launch",
        started_ns: 1,
        ended_ns: ended,
        argv: ["sleep", "60"],
        collectors: [{ name: "poll", mode: "poll", capabilities: [{ kind: "proc", evidence: "S" }, { kind: "file", evidence: "NA", na_reason: "collector_unavailable" }] }],
        stats: { process_count: procs, gap_count: 0, flow_count: 0, dns_count: 0 },
        gap_count: 0,
      });
    const view = (s: ReturnType<typeof toSummary>) =>
      render(
        <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
          <Overview summary={s} filter="" />
        </QueryClientProvider>,
      );
    const waiting = view(summary(null, 0));
    expect(waiting.container.querySelector("[data-waiting-sample]")?.textContent).toBe(ZH["overview.procsWaiting"]);
    expect(waiting.container.querySelector("[data-gaps-line]")?.textContent).toContain(ZH["overview.noRecordedGapsYet"]);
    waiting.unmount();
    // Sampled: the real count (the same session_counts number the list shows).
    const sampled = view(summary(null, 1));
    expect(sampled.container.querySelector("[data-waiting-sample]")).toBeNull();
    sampled.unmount();
    // Ended with nothing recorded: 0 is the answer, and no "so far".
    const ended = view(summary(5, 0));
    expect(ended.container.querySelector("[data-waiting-sample]")).toBeNull();
    expect(ended.container.querySelector("[data-gaps-line]")?.textContent).toContain(ZH["overview.noRecordedGaps"]);
    expect(ended.container.querySelector("[data-gaps-line]")?.textContent).not.toContain(ZH["overview.noRecordedGapsYet"]);
  });

  it("10: 「立即清理」 is really disabled for a non-admin (no request) and works for an admin", async () => {
    const { Storage } = await import("@/features/settings/SettingsPage");
    const { toConfigView } = await import("@/api/client");
    const config = toConfigView({ retention: { max_age_days: 30, max_db_bytes: 1 } });
    const calls: { url: string; body: string }[] = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const body = typeof init?.body === "string" ? init.body : "";
      calls.push({ url: String(input), body });
      const dry = body.includes('"dry_run":true');
      return new Response(dry ? '{"would_purge":[{"public_id":"s-old","session_id":9}]}' : '{"purged":[{"public_id":"s-old"}]}', { status: 200 });
    });
    const view = (admin: boolean) =>
      render(
        <QueryClientProvider client={new QueryClient()}>
          <Storage config={config} used={null} usedNa="" admin={admin} />
        </QueryClientProvider>,
      );
    const user = userEvent.setup();

    const plain = view(false);
    const button = plain.container.querySelector<HTMLButtonElement>("button[data-purge]");
    expect(button?.disabled).toBe(true);
    expect(button?.getAttribute("aria-disabled")).toBe("true");
    expect(plain.container.querySelector("[data-purge-locked]")?.textContent).toBe(ZH["settings.purgeNeedsAdmin"]);
    expect(ZH["settings.purgeNeedsAdmin"]).toContain("需要管理员权限");
    // Even a click forced past the disabled attribute sends nothing.
    if (button) {
      button.disabled = false;
      fireEvent.click(button);
    }
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(calls.filter((c) => c.url.includes("/db/purge"))).toEqual([]);
    plain.unmount();

    // Administrator: dry run first, then delete only after confirming.
    const admin = view(true);
    const enabled = admin.container.querySelector<HTMLButtonElement>("button[data-purge]");
    expect(enabled?.disabled).toBe(false);
    expect(admin.container.querySelector("[data-purge-locked]")).toBeNull();
    if (enabled) await user.click(enabled);
    await vi.waitFor(() => expect(calls.some((c) => c.url.includes("/db/purge") && c.body.includes('"dry_run":true'))).toBe(true));
    expect(calls.some((c) => c.url.includes("/db/purge") && !c.body.includes('"dry_run":true'))).toBe(false);
    const confirm = await vi.waitFor(() => {
      const found = [...document.querySelectorAll<HTMLButtonElement>("[role=dialog] button, [role=alertdialog] button")].find(
        (b) => b.textContent?.trim() !== ZH["common.cancel"],
      );
      if (!found) throw new Error("no confirm button");
      return found;
    });
    await user.click(confirm);
    await vi.waitFor(() => expect(calls.some((c) => c.url.includes("/db/purge") && !c.body.includes('"dry_run":true'))).toBe(true));
    const real = calls.find((c) => c.url.includes("/db/purge") && !c.body.includes('"dry_run":true'));
    expect(real?.body).toContain('"older_than":"30d"');
  });
});
