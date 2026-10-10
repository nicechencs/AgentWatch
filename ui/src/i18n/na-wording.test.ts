/**
 * Text beside an NA badge. The badge already says 不可得 / unavailable, so
 * the sentence next to it must not start by repeating that.
 */
import { describe, expect, it } from "vitest";
import zh from "@/i18n/zh.json";
import en from "@/i18n/en.json";

const ZH = zh as Record<string, string>;

describe("text beside an NA badge", () => {
  it("does not repeat 不可得", () => {
    // These keys render right after <EvidenceBadge level="NA" />.
    for (const key of ["compare.apiNa", "overview.capabilitiesUnknown", "selfReport.httpNa", "selfReport.unmatchedNa"]) {
      expect(ZH[key]).not.toMatch(/^不可得/u);
      expect((en as Record<string, string>)[key]).not.toMatch(/^unavailable/iu);
    }
  });
});
