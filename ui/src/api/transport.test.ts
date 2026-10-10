import { afterEach, describe, expect, it, vi } from "vitest";
import { isDesktop, send } from "./transport";

type W = { __TAURI_INTERNALS__?: { invoke: (cmd: string, args?: Record<string, unknown>) => Promise<unknown> } };

afterEach(() => {
  delete (window as unknown as W).__TAURI_INTERNALS__;
  vi.restoreAllMocks();
});

describe("transport", () => {
  it("uses fetch in a browser", async () => {
    const fetchMock = vi.fn(async () => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    expect(isDesktop()).toBe(false);
    const res = await send("/api/v1/me", { method: "GET" });
    expect(res.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledWith("/api/v1/me", { method: "GET" });
    vi.unstubAllGlobals();
  });

  it("goes through aw_request in the desktop app, with no fetch and no token", async () => {
    const invoke = vi.fn(async () => ({ status: 200, body: '{"user_id":"1000"}' }));
    (window as unknown as W).__TAURI_INTERNALS__ = { invoke };
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    expect(isDesktop()).toBe(true);
    const res = await send("/api/v1/sessions?limit=5", { method: "POST", body: "{}" });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ user_id: "1000" });
    expect(invoke).toHaveBeenCalledWith("aw_request", {
      method: "POST",
      target: "/api/v1/sessions?limit=5",
      body: "{}",
    });
    expect(fetchMock).not.toHaveBeenCalled();
    vi.unstubAllGlobals();
  });

  it("reports a stopped daemon as 503 daemon_unreachable", async () => {
    (window as unknown as W).__TAURI_INTERNALS__ = {
      invoke: async () => {
        throw "daemon_unreachable: /run/agentwatch/api.sock: NotFound";
      },
    };
    const res = await send("/api/v1/me", { method: "GET" });
    expect(res.status).toBe(503);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe("daemon_unreachable");
  });

  it("keeps the plain message and the technical detail apart", async () => {
    (window as unknown as W).__TAURI_INTERNALS__ = {
      invoke: async () => {
        throw {
          code: "daemon_unreachable",
          message: "AgentWatch 服务没有运行。",
          detail: "/run/agentwatch/api.sock: connection refused",
        };
      },
    };
    const res = await send("/api/v1/me", { method: "GET" });
    const body = (await res.json()) as { error: { code: string; message: string; detail?: string } };
    expect(body.error.message).toBe("AgentWatch 服务没有运行。");
    expect(body.error.message).not.toContain("/run/");
    expect(body.error.detail).toContain("connection refused");
  });
});
