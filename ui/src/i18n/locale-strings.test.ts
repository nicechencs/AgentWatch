/**
 * The catalogs. User-facing Chinese carries no developer word, zh and en
 * share keys, and every t() key used in source exists.
 */
import { describe, expect, it } from "vitest";
import zh from "@/i18n/zh.json";
import en from "@/i18n/en.json";

const ZH = zh as Record<string, string>;

describe("locale catalogs", () => {
  it("user-facing Chinese strings carry no 'daemon' developer word", () => {
    const leaks = Object.entries(ZH).filter(([, v]) => /\bdaemon\b(?! (start|stop|status|restart|logs))/u.test(v));
    expect(leaks).toEqual([]);
  });

  it("zh and en have the same keys", () => {
    expect(Object.keys(ZH).sort()).toEqual(Object.keys(en).sort());
  });

  it("every t() key used in source exists in zh", () => {
    const sources = import.meta.glob<string>("/src/**/*.tsx", { query: "?raw", import: "default", eager: true });
    const missing = new Set<string>();
    for (const [path, text] of Object.entries(sources)) {
      if (path.includes(".test.")) continue;
      for (const m of text.matchAll(/\bt\("([a-zA-Z0-9_.]+)"/gu)) if (!(m[1] in ZH)) missing.add(m[1]);
    }
    expect([...missing]).toEqual([]);
  });
});
