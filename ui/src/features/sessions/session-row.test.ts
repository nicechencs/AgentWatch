/**
 * A session list row carries the same counts and coverage the overview shows.
 */
import { describe, expect, it } from "vitest";
import { toSession } from "@/api/client";
import { coverage } from "@/lib/capabilities";

describe("session list row", () => {
  it("carries the overview counts and coverage", () => {
    const row = toSession({
      id: "s1",
      session_id: 1,
      started_ns: 5,
      collectors: [{ name: "poll", capabilities: [{ kind: "proc", evidence: "S" }, { kind: "net", evidence: "NA" }] }],
      stats: { process_count: 640, gap_count: 0, finding_count: 2, bytes_up: null, bytes_down: null },
    });
    expect(row.stats?.proc_count).toBe(640);
    expect(row.stats?.finding_count).toBe(2);
    expect(coverage(row, "net")).toBe("not_collected");
  });
});
