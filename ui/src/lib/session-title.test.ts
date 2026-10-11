/**
 * An unnamed session is called by its command, then by its public id.
 */
import { describe, expect, it } from "vitest";
import { toSession } from "@/api/client";
import { sessionTitle } from "@/lib/session-title";

describe("session title", () => {
  it("an unnamed session is called by its command", () => {
    const row = toSession({ id: "s-31988513fa4a", session_id: 3, started_ns: 1, argv: ["sleep", "90"], name: null });
    expect(sessionTitle(row)).toBe("sleep 90");
    expect(sessionTitle({ name: "重构", argv: ["sleep"], public_id: "s-1" })).toBe("重构");
    expect(sessionTitle({ name: null, argv: null, public_id: "s-1" })).toBe("s-1");
    expect(sessionTitle({ name: null, argv: ["tool", "«redacted:argv.flag_secret_eq»"], public_id: "s-1" })).toBe("tool （已隐藏）");
    expect(sessionTitle({ name: null, argv: ["tool", "«redacted:argv.flag_secret_eq»"], public_id: "s-1" }, "en")).toBe("tool (hidden)");
  });
});
