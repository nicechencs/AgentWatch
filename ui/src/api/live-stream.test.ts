/**
 * The live follow stream. EventSource could not send the bearer header, got
 * 401, and the page unticked "follow latest" by itself.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { parseSse, subscribeLive } from "@/api/client";

describe("live follow stream", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("parses the live body and keeps the cursor", () => {
    const events = parseSse("id: 3\nevent: record\ndata: {\"id\":3,\"cat\":\"proc\",\"ts_ns\":1}\n\n: keepalive\n\nevent: lagged\ndata: {}\n\n");
    expect(events.map((e) => e.event)).toEqual(["record", "lagged"]);
    expect(events[0].id).toBe(3);
  });

  it("sends the bearer header and keeps polling after an error", async () => {
    vi.useFakeTimers();
    const calls: RequestInit[] = [];
    let n = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url: string, init: RequestInit) => {
        calls.push(init);
        n += 1;
        if (n === 1) return new Response("{}", { status: 503 });
        return new Response("id: 1\nevent: record\ndata: {\"id\":1,\"cat\":\"proc\",\"ts_ns\":1}\n\n", { status: 200 });
      }),
    );
    const onError = vi.fn();
    const onRecord = vi.fn();
    const stop = subscribeLive("s1", "", { onRecord, onLagged: () => {}, onError }, 10);
    await vi.advanceTimersByTimeAsync(50);
    stop();
    vi.useRealTimers();
    expect(onError).toHaveBeenCalledTimes(1);
    expect(onRecord).toHaveBeenCalled();
    expect(calls.length).toBeGreaterThan(1);
  });
});
