/**
 * Preview ticket entry: the link the daemon hands out is
 * `/index.html#ticket=...`. It must land on the app at `/`, spend the ticket
 * once, and survive a reload in the same tab.
 */
import { render, screen, waitFor } from "@testing-library/react";
import { StrictMode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import indexHtml from "../../index.html?raw";
import { api, getToken, setToken } from "@/api/client";
import { AuthProvider, resetAuthForTests, takeTicketFromLocation, useAuth } from "./auth";
import { I18nProvider } from "./i18n";
import { SignIn } from "@/features/shell/SignIn";

function Status() {
  const { status } = useAuth();
  return <p>{status}</p>;
}

afterEach(() => {
  vi.restoreAllMocks();
  resetAuthForTests();
  setToken(null);
  window.history.replaceState(null, "", "/");
});

describe("preview ticket entry", () => {
  it("rewrites /index.html#ticket= to / and returns the ticket once", () => {
    window.history.replaceState(null, "", "/index.html#ticket=abc");
    expect(takeTicketFromLocation()).toBe("abc");
    expect(window.location.pathname).toBe("/");
    expect(window.location.hash).toBe("");
    expect(takeTicketFromLocation()).toBeNull();
  });

  it("spends the ticket once under StrictMode and keeps the token for a reload", async () => {
    window.history.replaceState(null, "", "/index.html#ticket=abc");
    const exchange = vi.spyOn(api, "exchangeTicket").mockResolvedValue({ token: "tok" });
    vi.spyOn(api, "me").mockResolvedValue({ user_id: "u", admin: false });
    render(
      <StrictMode>
        <AuthProvider>
          <Status />
        </AuthProvider>
      </StrictMode>,
    );
    await waitFor(() => expect(screen.getByText("signed-in")).toBeInTheDocument());
    expect(exchange).toHaveBeenCalledTimes(1);
    expect(getToken()).toBe("tok");
    expect(window.sessionStorage.getItem("aw.ui_token")).toBe("tok");
  });

  it("does not put frame-ancestors in a meta CSP", () => {
    expect(indexHtml).not.toMatch(/frame-ancestors/);
    expect(indexHtml).not.toMatch(/http-equiv="Content-Security-Policy"/i);
  });
});

describe("desktop app entry", () => {
  afterEach(() => {
    delete (window as unknown as { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__;
  });

  it("skips sign-in: me() over the channel, no ticket, no token", async () => {
    const invoke = vi.fn().mockResolvedValue({ status: 200, body: '{"user_id":"1000","admin":false}' });
    (window as unknown as { __TAURI_INTERNALS__: unknown }).__TAURI_INTERNALS__ = { invoke };
    const exchange = vi.spyOn(api, "exchangeTicket");
    render(
      <AuthProvider>
        <Status />
      </AuthProvider>,
    );
    await waitFor(() => expect(screen.getByText("signed-in")).toBeInTheDocument());
    expect(exchange).not.toHaveBeenCalled();
    expect(invoke).toHaveBeenCalledWith("aw_request", expect.objectContaining({ target: "/api/v1/me" }));
    expect(getToken()).toBeNull();
  });

  it("a stopped daemon is 'service not running', with retry", async () => {
    const invoke = vi.fn().mockRejectedValue({ code: "daemon_unreachable", message: "connect failed" });
    (window as unknown as { __TAURI_INTERNALS__: unknown }).__TAURI_INTERNALS__ = { invoke };
    render(
      <I18nProvider lang="en">
        <AuthProvider>
          <Status />
          <SignIn />
        </AuthProvider>
      </I18nProvider>,
    );
    await waitFor(() => expect(screen.getByText("unreachable")).toBeInTheDocument());
    expect(screen.getByText("The AgentWatch service is not running")).toBeInTheDocument();
    expect(screen.queryByText(/ticket/i)).toBeNull();
    invoke.mockResolvedValue({ status: 200, body: '{"user_id":"1000","admin":false}' });
    screen.getByRole("button", { name: "Retry" }).click();
    await waitFor(() => expect(screen.getByText("signed-in")).toBeInTheDocument());
  });

  const renderDesktop = (invoke: ReturnType<typeof vi.fn>) => {
    (window as unknown as { __TAURI_INTERNALS__: unknown }).__TAURI_INTERNALS__ = { invoke };
    render(
      <I18nProvider lang="en">
        <AuthProvider>
          <Status />
          <SignIn />
        </AuthProvider>
      </I18nProvider>,
    );
  };

  it("a refused channel is a permission message, not 'not running'", async () => {
    const invoke = vi.fn().mockRejectedValue({ code: "daemon_forbidden", message: "permission denied" });
    renderDesktop(invoke);
    await waitFor(() => expect(screen.getByText("forbidden")).toBeInTheDocument());
    expect(screen.getByText("Not allowed to connect to the AgentWatch service")).toBeInTheDocument();
    expect(screen.queryByText("The AgentWatch service is not running")).toBeNull();
  });

  it("busy / timeout / broken channel are errors, not 'not running'", async () => {
    const invoke = vi.fn().mockRejectedValue({ code: "daemon_busy", message: "every pipe instance is busy" });
    renderDesktop(invoke);
    await waitFor(() => expect(screen.getByText("failed")).toBeInTheDocument());
    expect(screen.queryByText("The AgentWatch service is not running")).toBeNull();
  });

  it("a daemon that answers with an error says so, and retry asks again", async () => {
    const invoke = vi
      .fn()
      .mockResolvedValue({ status: 500, body: '{"error":{"code":"store","message":"disk I/O error"}}' });
    renderDesktop(invoke);
    await waitFor(() => expect(screen.getByText("failed")).toBeInTheDocument());
    expect(screen.getByText("The service is running but returned an error: disk I/O error")).toBeInTheDocument();
    expect(screen.queryByText("The AgentWatch service is not running")).toBeNull();
    const calls = invoke.mock.calls.length;
    invoke.mockResolvedValue({ status: 200, body: '{"user_id":"1000","admin":false}' });
    screen.getByRole("button", { name: "Retry" }).click();
    await waitFor(() => expect(screen.getByText("signed-in")).toBeInTheDocument());
    expect(invoke.mock.calls.length).toBeGreaterThan(calls);
  });
});
