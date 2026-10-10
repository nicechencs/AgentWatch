/**
 * Before the first sample the overview says it is waiting, not 「0 进程」.
 * Once the session has ended, 0 is the answer.
 */
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";
import { render } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { toSummary } from "@/api/client";
import zh from "@/i18n/zh.json";

const ZH = zh as Record<string, string>;
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

describe("overview before the first sample", () => {
  it("says it is waiting, not 「0 进程」", async () => {
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
});
