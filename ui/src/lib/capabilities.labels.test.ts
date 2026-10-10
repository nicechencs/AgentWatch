/**
 * Category words. The timeline shows them as labels; English sentences use
 * the lowercase form so they read mid-sentence.
 */
import { describe, expect, it } from "vitest";
import { kindInSentence, kindLabel } from "@/lib/capabilities";
import zh from "@/i18n/zh.json";
import en from "@/i18n/en.json";

const ZH = zh as Record<string, string>;
const EN = en as Record<string, string>;
const t = (key: string, vars?: Record<string, string | number>) =>
  (ZH[key] ?? key).replace(/\{(\w+)\}/gu, (_, name: string) => String(vars?.[name] ?? `{${name}}`));
const tEn = (key: string) => EN[key] ?? key;

describe("category labels", () => {
  it("timeline categories read in Chinese", () => {
    expect(kindLabel(t, "proc")).toBe("进程");
    expect(kindLabel(t, "made_up")).toBe("made_up");
  });

  it("English sentences use lowercase category words", () => {
    expect(kindInSentence(tEn, "file")).toBe("files");
    const sentence = EN["coverage.notCollected"].replace(/\{kind\}/gu, kindInSentence(tEn, "file"));
    expect(sentence).toContain("does not collect files");
    expect(sentence).not.toMatch(/collect File/u);
  });
});
