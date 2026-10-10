/**
 * The command box belongs to the whole new-session page, not just LaunchForm.
 * Doctor capabilities and the process picker can both finish while the user is
 * typing; neither page update may remount the field or write an old value back.
 */
import type { ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { api } from "@/api/client";
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

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

describe("new-session command box", () => {
  afterEach(() => vi.restoreAllMocks());

  it("keeps typed text while doctor and process queries resolve", async () => {
    const doctor = deferred<Awaited<ReturnType<typeof api.doctor>>>();
    const processes = deferred<Awaited<ReturnType<typeof api.systemProcesses>>>();
    vi.spyOn(api, "doctor").mockReturnValue(doctor.promise);
    vi.spyOn(api, "systemProcesses").mockReturnValue(processes.promise);

    const { NewSessionPage } = await import("@/features/sessions/NewSessionPage");
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const { container } = render(
      <QueryClientProvider client={client}>
        <NewSessionPage />
      </QueryClientProvider>,
    );
    const command = container.querySelector<HTMLInputElement>('input[name="command"]');
    if (!command) throw new Error("no command input");
    const user = userEvent.setup();

    await user.type(command, "s");
    doctor.resolve({
      probed: true,
      capabilities: [{ kind: "proc", evidence: "S", available: true, na_reason: null, note: null }],
      collectors: [],
      platform: "linux",
      os_version: null,
      mode: null,
      reason: null,
      privileged: null,
      privileged_note: null,
    });
    await waitFor(() => expect(container.querySelector("[data-capability-list]")).toBeTruthy());
    const afterDoctor = container.querySelector<HTMLInputElement>('input[name="command"]');
    expect(afterDoctor).toBe(command);
    expect(afterDoctor).toHaveValue("s");

    await user.type(command, "leep 60");
    processes.resolve({
      available: true,
      reason: null,
      scope: "own",
      roots: [
        {
          pid: 42,
          ppid: 1,
          name: "claude",
          exe: null,
          argv: ["claude"],
          user_id: "1000",
          agent: "claude",
          children: [],
        },
      ],
    });
    await screen.findByRole("button", { name: /claude/u });
    const afterProcesses = container.querySelector<HTMLInputElement>('input[name="command"]');
    expect(afterProcesses).toBe(command);
    expect(afterProcesses).toHaveValue("sleep 60");
  });
});
