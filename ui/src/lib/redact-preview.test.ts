/**
 * The redaction rule preview uses the same regex the daemon uses.
 */
import { describe, expect, it } from "vitest";
import { redactPreview } from "@/lib/redact-preview";
import zh from "@/i18n/zh.json";

const ZH = zh as Record<string, string>;

describe("redaction rule preview", () => {
  it("uses the regex the daemon uses", () => {
    expect(redactPreview("tok=\\w+", "a tok=abc1 b").text).toBe("a «redacted:custom» b");
    expect(redactPreview("(", "x").invalid).toBe(true);
    expect(ZH["settings.customRule"]).toBe("自定义");
  });
});
