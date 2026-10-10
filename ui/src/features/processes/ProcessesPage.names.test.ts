/**
 * Process names. The table uses the daemon's exe_name, else the image path,
 * and the name filter matches either.
 */
import { describe, expect, it } from "vitest";
import { toProcessNode } from "@/api/client";
import { filterByName, processName } from "@/features/processes/ProcessesPage";

describe("process names", () => {
  it("uses exe_name from the daemon, else the image path, and filters by it", () => {
    const named = toProcessNode({ proc_uid: "u1", pid: 10, exe_name: "node", children: [] });
    expect(processName(named)).toBe("node");
    const fromImages = toProcessNode({ proc_uid: "u2", pid: 11, images: [{ exe: "/bin/bash" }], children: [] });
    expect(processName(fromImages)).toBe("bash");
    const rows = [named, fromImages].map((node) => ({ node, depth: 0 })) as never;
    expect(filterByName(rows, "BAS")).toHaveLength(1);
    expect(filterByName(rows, "10")).toHaveLength(1);
  });
});
