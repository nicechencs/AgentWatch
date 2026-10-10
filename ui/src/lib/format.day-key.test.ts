/**
 * Day keys for cross-day times. A monotonic tick is not a wall clock, so it
 * must not render as a calendar date.
 */
import { describe, expect, it } from "vitest";
import { dayKey } from "@/lib/format";

describe("day keys", () => {
  it("cross-day times get a day key", () => {
    const day = 86_400_000_000_000;
    expect(dayKey(0, true)).not.toBe(dayKey(day, true));
    expect(dayKey(0, true)).toBe(dayKey(day - 1, true));
  });
});
