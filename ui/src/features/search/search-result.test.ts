/**
 * Search groups the daemon's flat hits. The page used to read
 * `result.groups` on `{hits:[...]}` and white-screen.
 */
import { describe, expect, it } from "vitest";
import { toSearchResult } from "@/api/client";

describe("search result grouping", () => {
  it("groups flat hits and leaves time and text null when absent", () => {
    const result = toSearchResult({ hits: [{ src: "process_images", src_id: 7, session_id: 1, public_id: "s1" }] });
    expect(result.groups).toHaveLength(1);
    expect(result.groups[0].hits[0]).toMatchObject({ kind: "proc", id: 7, ts_ns: null, summary: null });
  });

  it("shows the daemon's text and time instead of a bare record id", () => {
    const result = toSearchResult({
      hits: [{ src: "file_access", src_id: 3, session_id: 1, public_id: "s1", text: "/home/u/.aws/credentials", ts_ns: 1_760_000_000_000_000_000, evidence: "E1" }],
    });
    expect(result.groups[0].hits[0]).toMatchObject({ kind: "file", summary: "/home/u/.aws/credentials", ts_ns: 1_760_000_000_000_000_000, evidence: "E1" });
  });

  it("tolerates an empty or odd body", () => {
    expect(toSearchResult({}).groups).toEqual([]);
    expect(toSearchResult(null).groups).toEqual([]);
  });
});
