/**
 * A failed launch stays on screen until the user changes the attempt: editing
 * the command or directory, or picking a process to attach, clears it. The
 * command and directory boxes stay uncontrolled.
 */
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
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

describe("launch error clears on a new attempt", () => {
  beforeEach(() => {
    vi.spyOn(api, "createSession").mockRejectedValue(new Error("program_not_found"));
    vi.spyOn(api, "doctor").mockResolvedValue({
      probed: true, capabilities: [], collectors: [], platform: "linux", os_version: null,
      mode: null, reason: null, privileged: null, privileged_note: null,
    });
    vi.spyOn(api, "systemProcesses").mockResolvedValue({
      available: true, reason: null, scope: "own",
      roots: [{ pid: 11, ppid: 1, name: "sleep", exe: null, argv: ["sleep", "60"], user_id: "1000", agent: null, children: [] }],
    });
  });

  it("goes away when the command or directory is edited, or a process is picked", async () => {
    const { NewSessionPage } = await import("@/features/sessions/NewSessionPage");
    const { container } = render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <NewSessionPage />
      </QueryClientProvider>,
    );
    const command = container.querySelector<HTMLInputElement>('input[name="command"]');
    if (!command) throw new Error("no command input");
    fireEvent.change(command, { target: { value: "missing" } });
    fireEvent.submit(command.form as HTMLFormElement);
    expect(await screen.findByText(/program_not_found/u)).toBeTruthy();
    // Uncontrolled: the handler reads the field, it does not own its value.
    expect(command.value).toBe("missing");

    fireEvent.input(command, { target: { value: "sleep 60" } });
    expect(screen.queryByText(/program_not_found/u)).toBeNull();
    expect(command.value).toBe("sleep 60");

    fireEvent.change(command, { target: { value: "missing" } });
    fireEvent.submit(command.form as HTMLFormElement);
    expect(await screen.findByText(/program_not_found/u)).toBeTruthy();
    const cwd = container.querySelector<HTMLInputElement>('input[name="cwd"]');
    if (!cwd) throw new Error("no cwd input");
    fireEvent.input(cwd, { target: { value: "/tmp" } });
    expect(screen.queryByText(/program_not_found/u)).toBeNull();

    fireEvent.submit(command.form as HTMLFormElement);
    expect(await screen.findByText(/program_not_found/u)).toBeTruthy();
    fireEvent.click(await screen.findByRole("button", { name: /sleep/u }));
    expect(screen.queryByText(/program_not_found/u)).toBeNull();
  });
});
