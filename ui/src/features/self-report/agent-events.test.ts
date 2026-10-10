/**
 * The self-report list maps agent events onto timeline items. Nothing in the
 * copy may claim the list itself is missing.
 */
import { describe, expect, it } from "vitest";
import { agentEventToItem } from "@/features/self-report/api";
import zh from "@/i18n/zh.json";

const ZH = zh as Record<string, string>;

describe("self-report list", () => {
  it("maps an agent event row to a timeline item", () => {
    const item = agentEventToItem({ id: 4, ts_ns: 9, kind: "tool_call", tool: "Bash", summary: "ls" });
    expect(item.id).toBe(4);
    expect(item.ts_ns).toBe(9);
  });

  it("no string claims the list is missing", () => {
    expect(Object.values(ZH).join("\n")).not.toMatch(/没有 agent-events 列表/u);
  });
});
