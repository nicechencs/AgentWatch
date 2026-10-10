/**
 * Settings lists the built-in redaction rules ahead of the user's own.
 */
import { describe, expect, it } from "vitest";
import { toConfigView } from "@/api/client";
import zh from "@/i18n/zh.json";

const ZH = zh as Record<string, string>;

describe("built-in redaction rules", () => {
  it("lists the built-in rules before the custom one", () => {
    const view = toConfigView({
      config: { redaction: { rules: [{ id: "custom-1", builtin: false, pattern: "x+", description: null }] } },
      builtin_redaction_rules: [{ id: "tok.github", scope: "text", pattern: "gh" }, { id: "env.secret_name", scope: "env", pattern: null }],
    });
    expect(view.redaction.rules.map((r) => [r.id, r.builtin])).toEqual([["tok.github", true], ["env.secret_name", true], ["custom-1", false]]);
    expect(ZH["redact.rule.tok.github"]).toBeTruthy();
    expect(ZH["redact.rule.env.secret_name"]).toBeTruthy();
  });
});
