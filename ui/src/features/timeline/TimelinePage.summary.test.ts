/**
 * Timeline rows. A process row already shows its name, so the summary must
 * not print it a second time.
 */
import { describe, expect, it } from "vitest";
import { redundantSummary } from "@/features/timeline/TimelinePage";

describe("timeline row summary", () => {
  it("a process row does not print its name twice", () => {
    expect(redundantSummary({ summary: "node(280)", proc: { pid: 280, exe_name: "node" } as never })).toBe(true);
    expect(redundantSummary({ summary: "pid 7", proc: { pid: 7, exe_name: null } as never })).toBe(true);
    expect(redundantSummary({ summary: "GET /x", proc: { pid: 7, exe_name: null } as never })).toBe(false);
  });
});
