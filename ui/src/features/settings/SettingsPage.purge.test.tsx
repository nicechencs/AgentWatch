/**
 * 「立即清理」 is disabled for a non-admin and sends no request; an admin
 * dry-runs first and deletes only after confirming.
 */
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";
import { fireEvent, render } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { toConfigView } from "@/api/client";
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

describe("purge now", () => {
  it("is disabled for a non-admin and works for an admin", async () => {
    const { Storage } = await import("@/features/settings/SettingsPage");
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
