/**
 * Gap collectors. `poll` reads as 「进程轮询」, and a source that is the same
 * collector is not repeated (it used to read 「poll poll」).
 */
import { describe, expect, it } from "vitest";
import { toGap } from "@/api/client";
import zh from "@/i18n/zh.json";
import en from "@/i18n/en.json";
import { collectorLabel, collectorName } from "@/features/gaps/GapsPage";

const ZH = zh as Record<string, string>;
const EN = en as Record<string, string>;

describe("gap collector names", () => {
  it("names poll once, and names a different source too", () => {
    expect(collectorName((key) => ZH[key] ?? key, "poll")).toBe("进程轮询");
    expect(collectorName((key) => EN[key] ?? key, "poll")).toBe("process polling");
    const same = toGap({ id: 1, collector: "poll", source: "poll", kind: "proc" });
    expect(collectorLabel((key) => ZH[key] ?? key, same)).toBe("进程轮询");
    expect(collectorLabel((key) => ZH[key] ?? key, same)).not.toContain("poll");
    const other = toGap({ id: 2, collector: "poll", source: "ebpf", kind: "proc" });
    expect(collectorLabel((key) => ZH[key] ?? key, other)).toBe("进程轮询 (eBPF（内核）)");
  });
});
