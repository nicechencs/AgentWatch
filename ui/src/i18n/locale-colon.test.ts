/**
 * English catalogs use an ASCII colon. A fullwidth 「：」 belongs to Chinese
 * only, and every catalog has an entry for every key.
 */
import { describe, expect, it } from "vitest";
import zh from "@/i18n/zh.json";
import en from "@/i18n/en.json";
import { proxyCatalogs } from "@/features/settings/proxy/strings";
import { netCatalogs } from "@/features/network/strings";

const ZH = zh as Record<string, string>;
const EN = en as Record<string, string>;

describe("locale colons", () => {
  it("English strings use an ASCII colon and lowercase kinds", () => {
    expect(EN["common.colon"]).toBe(": ");
    expect(EN["new.capNotCollected"]).not.toContain("：");
    expect(EN["coverage.kinds.file"]).toBe("files");
    const fullwidth = Object.entries(EN).filter(([, value]) => value.includes("："));
    expect(fullwidth).toEqual([]);
  });

  it("every English catalog is free of 「：」 and has an entry for every key", () => {
    const catalogs: [string, Record<string, string>, Record<string, string>][] = [
      ["i18n", ZH, EN],
      ["proxy", proxyCatalogs.zh, proxyCatalogs.en],
      ["network", netCatalogs.zh, netCatalogs.en],
    ];
    for (const [name, zhCat, enCat] of catalogs) {
      const fullwidth = Object.entries(enCat).filter(([, value]) => value.includes("："));
      expect(fullwidth, name).toEqual([]);
      const missing = Object.keys(zhCat).filter((key) => !(key in enCat) || enCat[key] === "");
      expect(missing, name).toEqual([]);
    }
    expect(proxyCatalogs.en.colon).toBe(": ");
    expect(netCatalogs.en.colon).toBe(": ");
    expect(proxyCatalogs.zh.colon).toBe("：");
  });

  it("no component hard-codes 「：」 next to a label", () => {
    // Labels and values are joined with the locale colon; a literal 「：」 in a
    // component would show up in the English UI.
    const files = import.meta.glob("/src/**/*.tsx", { query: "?raw", import: "default", eager: true }) as Record<string, string>;
    expect(Object.keys(files).length).toBeGreaterThan(20);
    const offenders = Object.entries(files)
      .filter(([path]) => !path.includes(".test."))
      .flatMap(([path, text]) =>
        text
          .split("\n")
          .map((line, index) => ({ path, line: index + 1, text: line.trim() }))
          .filter((row) => row.text.includes("：") && !row.text.startsWith("//") && !row.text.startsWith("*") && !row.text.startsWith("/*")),
      );
    expect(offenders).toEqual([]);
  });
});