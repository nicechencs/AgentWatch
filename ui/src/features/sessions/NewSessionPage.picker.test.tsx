/**
 * The attach picker. The process table was not wired, so a running
 * `sleep 900` read as 「没有记录」; a table that was not collected is never
 * shown as an empty table.
 */
import { describe, expect, it, vi } from "vitest";
import { render } from "@testing-library/react";
import { toSystemProcessTable } from "@/api/client";
import { ApiError } from "@/api/errors";
import zh from "@/i18n/zh.json";

const ZH = zh as Record<string, string>;
const t = (key: string, vars?: Record<string, string | number>) =>
  (ZH[key] ?? key).replace(/\{(\w+)\}/gu, (_, name: string) => String(vars?.[name] ?? `{${name}}`));

vi.mock("@/lib/i18n", () => ({ useI18n: () => ({ lang: "zh", t }) }));
vi.mock("@/lib/prefs", () => ({ usePrefs: () => ({ lang: "zh", theme: "system", timeFormat: "utc" }) }));
vi.mock("@/lib/auth", () => ({ useAuth: () => ({ me: { admin: false } }) }));

describe("attach picker process table", () => {
  it("maps the service's live table, nested, with owner and redacted argv", () => {
    const table = toSystemProcessTable({
      available: true,
      scope: "own",
      roots: [
        {
          pid: 10,
          ppid: 1,
          name: "bash",
          user_id: "1000",
          children: [{ pid: 11, ppid: 10, name: "sleep", user_id: "1000", argv: ["sleep", "900"], children: [] }],
        },
      ],
    });
    expect(table.available).toBe(true);
    expect(table.scope).toBe("own");
    expect(table.roots[0].children[0]).toMatchObject({ pid: 11, name: "sleep", user_id: "1000", argv: ["sleep", "900"] });
  });

  it("a table that was not collected is never an empty table", () => {
    const missing = toSystemProcessTable({ available: false, reason: "no table", roots: [{ pid: 1, name: "x" }] });
    expect(missing.available).toBe(false);
    expect(missing.roots).toEqual([]);
    // An old daemon without the flag is also "not collected".
    expect(toSystemProcessTable({ roots: [] }).available).toBe(false);
  });

  it("says 没采 when not collected or failed, and a plain no-match otherwise", async () => {
    const { PickerStatus } = await import("@/features/sessions/NewSessionPage");
    const text = (node: React.ReactElement) => {
      const { container, unmount } = render(node);
      const out = container.textContent ?? "";
      unmount();
      return out;
    };
    const notCollected = text(
      <PickerStatus data={{ available: false, reason: "no_process_table", scope: "own", roots: [] }} error={null} loading={false} agentsOnly={false} />,
    );
    expect(notCollected).toContain("没采");
    // The reason is a code worded in Chinese, never the daemon's English.
    expect(notCollected).toContain(ZH["new.procReason.noProcessTable"]);
    expect(notCollected).not.toMatch(/[A-Za-z]{3,}/u);
    const unknown = text(
      <PickerStatus data={{ available: false, reason: "some new english reason", scope: "own", roots: [] }} error={null} loading={false} agentsOnly={false} />,
    );
    expect(unknown).toContain(ZH["new.procReasonUnknown"]);
    expect(unknown).not.toContain("english");
    expect(notCollected).not.toContain(ZH["common.empty"]);

    const failed = text(
      <PickerStatus data={undefined} error={new ApiError(503, { error: { code: "x", message: "y" } }, "y")} loading={false} agentsOnly={false} />,
    );
    expect(failed).toContain("没采");
    expect(failed).not.toContain(ZH["common.empty"]);

    const empty = { available: true, reason: null, scope: "own", roots: [] };
    expect(text(<PickerStatus data={empty} error={null} loading={false} agentsOnly={false} />)).toBe(ZH["new.procNoMatch"]);
    expect(text(<PickerStatus data={empty} error={null} loading={false} agentsOnly />)).toBe(ZH["new.procNoAgent"]);
  });
});
