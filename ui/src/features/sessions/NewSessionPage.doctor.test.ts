/**
 * The new-session page reads the doctor probe. An unprobed body has no
 * capability list; the page used to call `.filter` on it and white-screen.
 * Daemon bodies below were copied from a running agentwatchd on 2026-10-10.
 */
import { describe, expect, it } from "vitest";
import { toDoctor } from "@/api/client";

describe("new-session doctor probe", () => {
  it("maps an unprobed doctor body to an empty capability list", () => {
    const doctor = toDoctor({
      probed: false,
      reason: "collector probe is not run on the request path",
      collectors: [],
      host: { os: "linux", privileged: false, privileged_note: "poll collector only" },
    });
    expect(doctor.capabilities).toEqual([]);
    expect(doctor.probed).toBe(false);
    expect(doctor.platform).toBe("linux");
    expect(doctor.privileged).toBe(false);
  });
});
