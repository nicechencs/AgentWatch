/**
 * The list search is client-side: the daemon ignores `q`.
 */
import { describe, expect, it } from "vitest";
import { sessionMatchesQuery } from "@/lib/session-match";

const sh = { name: null, argv: ["sh", "-c", "exit 3"], public_id: "s-abc" };

describe("session search match", () => {
  it("matches argv joined with single spaces, case-insensitively", () => {
    expect(sessionMatchesQuery(sh, "sh -c exit 3")).toBe(true);
    expect(sessionMatchesQuery(sh, "EXIT 3")).toBe(true);
  });

  it("matches the session name", () => {
    expect(sessionMatchesQuery({ name: "重构", argv: ["sleep"], public_id: "s-1" }, "重构")).toBe(true);
  });

  it("matches the public id", () => {
    expect(sessionMatchesQuery(sh, "s-abc")).toBe(true);
  });

  it("does not match an unrelated query", () => {
    expect(sessionMatchesQuery(sh, "python")).toBe(false);
  });

  it("an empty query shows every session", () => {
    expect(sessionMatchesQuery(sh, "   ")).toBe(true);
  });
});
