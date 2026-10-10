/**
 * Exit codes. A code the sampler did not observe is 「没采」, never 0 or blank;
 * a real 0 is 0.
 */
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";
import { render } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
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
  useParams: () => ({ sid: "s-1" }),
  Link: ({ children }: { children?: ReactNode }) => <a>{children}</a>,
}));

const node = (procUid: string, exitCode: number | null) => ({
  proc_uid: procUid,
  pid: 10,
  exe_name: "sleep",
  exit_code: exitCode,
  images: [],
  children: [],
});

describe("process exit code", () => {
  it("shows 7, 0, and 没采 for null", async () => {
    const { ProcessesPage } = await import("@/features/processes/ProcessesPage");
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    client.setQueryData(["processes", "s-1"], { roots: [node("a", 7), node("b", 0), node("c", null)] });
    client.setQueryData(["session", "s-1"], { public_id: "s-1", collectors: [], ended_ns: 1 });
    const { container } = render(
      <QueryClientProvider client={client}>
        <ProcessesPage />
      </QueryClientProvider>,
    );
    const cells = [...container.querySelectorAll("[data-exit-code]")].map((cell) => cell.textContent);
    expect(cells).toEqual(["7", "0", ZH["coverage.notCollectedShort"]]);
    expect(container.textContent).toContain(ZH["procs.col.exitCode"]);
  });
});
