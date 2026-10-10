/**
 * The root error page. It reads in Chinese, not the router's English fallback.
 */
import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import zh from "@/i18n/zh.json";

const ZH = zh as Record<string, string>;
const t = (key: string, vars?: Record<string, string | number>) =>
  (ZH[key] ?? key).replace(/\{(\w+)\}/gu, (_, name: string) => String(vars?.[name] ?? `{${name}}`));

vi.mock("@/lib/i18n", () => ({ useI18n: () => ({ lang: "zh", t }) }));

describe("root error page", () => {
  it("is Chinese, not 'Something went wrong!'", async () => {
    const { AppError } = await import("@/components/AppError");
    render(<AppError error={new Error("boom")} />);
    expect(screen.getByRole("alert").textContent).toContain(ZH["error.page.title"]);
    expect(document.body.textContent).not.toMatch(/Something went wrong/u);
  });
});
