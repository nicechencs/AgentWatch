/**
 * The "not collected" note. It must say 没采 and never look like an empty list.
 */
import { describe, expect, it, vi } from "vitest";
import { render } from "@testing-library/react";
import zh from "@/i18n/zh.json";

const ZH = zh as Record<string, string>;
const t = (key: string, vars?: Record<string, string | number>) =>
  (ZH[key] ?? key).replace(/\{(\w+)\}/gu, (_, name: string) => String(vars?.[name] ?? `{${name}}`));

vi.mock("@/lib/i18n", () => ({ useI18n: () => ({ lang: "zh", t }) }));

describe("not-collected note", () => {
  it("renders 没采 and never 没有记录", async () => {
    const { CoverageNote, NotCollected } = await import("@/components/NotCollected");
    render(
      <>
        <CoverageNote kind="file" coverage="not_collected" />
        <NotCollected kind="net" />
      </>,
    );
    expect(document.body.textContent).toContain("没采");
    expect(document.body.textContent).not.toContain("没有记录");
  });
});
