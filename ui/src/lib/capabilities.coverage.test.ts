/**
 * Coverage of a session's collectors. "Not collected" is distinct from
 * "no records", and a session with no capability list is unknown, not complete.
 */
import { describe, expect, it } from "vitest";
import { toSession } from "@/api/client";
import { capabilitiesUnknown, coverage, uncollectedKinds } from "@/lib/capabilities";

const pollSession = toSession({
  id: "s1",
  session_id: 1,
  mode: "run",
  started_ns: 5,
  collectors: [
    {
      name: "poll",
      mode: "S",
      capabilities: [
        { kind: "proc", evidence: "S" },
        { kind: "file", evidence: "NA", na_reason: "collector_unavailable" },
        { kind: "net", evidence: "NA", na_reason: "collector_unavailable" },
        { kind: "dns", evidence: "NA", na_reason: "collector_unavailable" },
      ],
    },
  ],
});

describe("session coverage", () => {
  it("files and network on a poll session are not collected", () => {
    expect(coverage(pollSession, "file")).toBe("not_collected");
    expect(coverage(pollSession, "proc")).toBe("collected");
    expect(uncollectedKinds(pollSession)).toEqual(["file", "net", "dns"]);
  });

  it("a session with no capability list is unknown, not complete", () => {
    const bare = toSession({ id: "s2", session_id: 2, collectors: ["poll"] });
    expect(coverage(bare, "file")).toBe("unknown");
    expect(capabilitiesUnknown(bare)).toBe(true);
  });
});
