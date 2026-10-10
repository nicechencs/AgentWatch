/**
 * The launch form. A re-render while typing (the desktop window re-renders on
 * channel replies) must not write old text back into the command box.
 */
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";
import { fireEvent, render } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
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

describe("launch command box", () => {
  it("a re-render while typing never writes old text back", async () => {
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
});
