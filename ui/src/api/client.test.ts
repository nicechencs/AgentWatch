/**
 * Every API request goes through src/api/client.ts. A feature that calls
 * fetch("/api/v1…") itself keeps its own token and error handling, and a
 * transport change (desktop IPC) would silently miss it.
 */
import { describe, expect, it } from "vitest";

const sources = import.meta.glob<string>("/src/**/*.{ts,tsx}", { query: "?raw", import: "default", eager: true });

describe("single request path", () => {
  it("only client.ts calls fetch", () => {
    const offenders = Object.entries(sources)
      .filter(([path]) => path !== "/src/api/client.ts" && !/\.test\.tsx?$/.test(path))
      .filter(([, text]) => /\bfetch\(/.test(text))
      .map(([path]) => path);
    expect(Object.keys(sources).length).toBeGreaterThan(20);
    expect(offenders).toEqual([]);
  });
});
