/**
 * The compare card. Platform is a field of the session row, not the list item,
 * so an empty one reads 「不可得」. Capabilities read like Settings: collected
 * kinds, then the kinds listed only as NA as 「没采」.
 */
import { describe, expect, it } from "vitest";
import { toSession } from "@/api/client";
import zh from "@/i18n/zh.json";
import en from "@/i18n/en.json";
import { agentText, capabilityText, platformText } from "@/features/compare/ComparePage";

const ZH = zh as Record<string, string>;
const EN = en as Record<string, string>;
const t = (catalog: Record<string, string>) => (key: string) => catalog[key] ?? key;

const poll = toSession({
  id: "s1",
  session_id: 1,
  platform: "",
  collectors: [
    {
      name: "poll",
      mode: "poll",
      capabilities: [
        { kind: "proc", evidence: "S" },
        { kind: "file", evidence: "NA" },
        { kind: "net", evidence: "NA" },
        { kind: "dns", evidence: "NA" },
      ],
    },
  ],
});

describe("compare wording", () => {
  it("says 不可得 for a platform the session row did not carry", () => {
    expect(platformText(poll, ZH["common.unavailable"])).toBe("不可得");
    expect(platformText({ ...poll, platform: "linux", os_version: "6.8" }, ZH["common.unavailable"])).toBe("Linux 6.8");
    expect(platformText({ ...poll, platform: "darwin", os_version: null }, ZH["common.unavailable"])).toBe("macOS");
    expect(platformText({ ...poll, platform: "win32", os_version: null }, ZH["common.unavailable"])).toBe("Windows");
  });

  it("labels agents 智能体 in Chinese and Agent in English", () => {
    expect(ZH["sessions.col.agent"]).toBe("智能体");
    expect(ZH["compare.agent"]).toBe("智能体");
    expect(EN["sessions.col.agent"]).toBe("Agent");
    expect(EN["compare.agent"]).toBe("Agent");

    const zhLabel = agentText("claude", t(ZH));
    expect(zhLabel).toBe("智能体：claude");
    expect(zhLabel.startsWith("Agent")).toBe(false);
    expect(agentText("claude", t(EN))).toBe("Agent: claude");
  });

  it("words capabilities like Settings, in Chinese and English", () => {
    expect(capabilityText(poll, t(ZH))).toBe("进程 可采、文件 / 网络 / DNS 没采");
    expect(capabilityText(poll, t(EN))).toBe("processes collected, files / network traffic / DNS not collected");
    expect(capabilityText(toSession({ id: "s2", collectors: ["poll"] }), t(ZH))).toBe("不可得");
  });
});
