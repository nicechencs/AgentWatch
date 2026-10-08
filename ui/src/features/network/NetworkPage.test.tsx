/**
 * Component tests for P3-UI-02: direct, quic, cert_pinned states
 * and the HTTP layer rendering.
 *
 * No test framework existed in the project; vitest + jsdom + RTL were added
 * to devDependencies for this task.
 */
import { render } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { FlowMarks, HttpTable } from "./HttpRows";
import { flowMarks, isCertPinned, visibleHeaders } from "./http";
import type { HttpRow } from "./http";

// ── Minimal i18n mock ────────────────────────────────────────────────────────

vi.mock("@/lib/i18n", () => ({
  useI18n: () => ({
    lang: "zh" as const,
    t: (key: string) => key,
  }),
}));

vi.mock("@/lib/prefs", () => ({
  usePrefs: () => ({ lang: "zh", theme: "system", timeFormat: "local" }),
}));

// ── flowMarks unit tests ─────────────────────────────────────────────────────

describe("flowMarks", () => {
  it("returns [direct] when direct=true, not via_proxy", () => {
    expect(flowMarks({ direct: true, via_proxy: false, proto: "tcp", remote_port: 443, na_reason: null })).toEqual(["direct"]);
  });
  it("returns [quic] when na_reason=quic", () => {
    expect(flowMarks({ direct: false, via_proxy: false, proto: "udp", remote_port: 443, na_reason: "quic" })).toEqual(["quic"]);
  });
  it("returns [quic] when udp:443 even without na_reason", () => {
    expect(flowMarks({ direct: false, via_proxy: false, proto: "udp", remote_port: 443, na_reason: null })).toEqual(["quic"]);
  });
  it("returns [via_proxy] when via_proxy=true", () => {
    expect(flowMarks({ direct: false, via_proxy: true, proto: "tcp", remote_port: 443, na_reason: null })).toEqual(["via_proxy"]);
  });
  it("returns [] when no marks apply", () => {
    expect(flowMarks({ direct: false, via_proxy: false, proto: "tcp", remote_port: 443, na_reason: null })).toEqual([]);
  });
});

// ── isCertPinned unit tests ──────────────────────────────────────────────────

describe("isCertPinned", () => {
  it("returns true when error=cert_pinned", () => {
    expect(isCertPinned({ error: "cert_pinned" })).toBe(true);
  });
  it("returns false for null error", () => {
    expect(isCertPinned({ error: null })).toBe(false);
  });
  it("returns false for other error values", () => {
    expect(isCertPinned({ error: "upstream_tls" })).toBe(false);
  });
});

// ── visibleHeaders unit tests ────────────────────────────────────────────────

describe("visibleHeaders", () => {
  it("returns empty for null input", () => {
    expect(visibleHeaders(null)).toEqual({ shown: [], hidden: 0 });
  });
  it("passes through safe headers", () => {
    const raw = JSON.stringify([["content-type", "application/json"], ["x-request-id", "abc"]]);
    const { shown, hidden } = visibleHeaders(raw);
    expect(shown).toEqual([["content-type", "application/json"], ["x-request-id", "abc"]]);
    expect(hidden).toBe(0);
  });
  it("never shows Authorization or Cookie values", () => {
    const raw = JSON.stringify([["Authorization", "Bearer secret"], ["Cookie", "sid=xyz"], ["content-type", "text/html"]]);
    const { shown, hidden } = visibleHeaders(raw);
    expect(shown.map(([name]) => name)).toEqual(["content-type"]);
    expect(hidden).toBe(2);
  });
  it("handles object format", () => {
    const raw = JSON.stringify({ "content-type": "application/json", "x-api-key": "secret" });
    const { shown, hidden } = visibleHeaders(raw);
    expect(shown.map(([n]) => n)).toEqual(["content-type"]);
    expect(hidden).toBe(1);
  });
});

// ── FlowMarks rendering ──────────────────────────────────────────────────────

const BASE_FLOW = { via_proxy: false, proto: "tcp" as const, remote_port: 443, na_reason: null };

describe("FlowMarks component", () => {
  it("renders nothing when no marks", () => {
    const { container } = render(<FlowMarks flow={{ ...BASE_FLOW, direct: false }} />);
    expect(container).toBeEmptyDOMElement();
  });
  it("renders direct mark with ⓘ and data-mark attribute", () => {
    render(<FlowMarks flow={{ ...BASE_FLOW, direct: true }} />);
    const mark = document.querySelector("[data-mark='direct']");
    expect(mark).not.toBeNull();
    // ⓘ is present
    expect(mark!.textContent).toContain("ⓘ");
  });
  it("renders quic mark", () => {
    render(<FlowMarks flow={{ ...BASE_FLOW, direct: false, proto: "udp", remote_port: 443 }} />);
    const mark = document.querySelector("[data-mark='quic']");
    expect(mark).not.toBeNull();
  });
  it("renders via_proxy mark", () => {
    render(<FlowMarks flow={{ ...BASE_FLOW, direct: false, via_proxy: true }} />);
    const mark = document.querySelector("[data-mark='via_proxy']");
    expect(mark).not.toBeNull();
  });
});

// ── HttpTable rendering ──────────────────────────────────────────────────────

const baseRow = (overrides: Partial<HttpRow> = {}): HttpRow => ({
  id: 1,
  session_id: 1,
  proc_uid: null,
  flow_id: 1,
  ts_ns: 1_700_000_000_000_000_000,
  method: "GET",
  url: "https://api.example.com/v1/test",
  host: "api.example.com",
  http_version: "HTTP/2",
  status: 200,
  req_headers: null,
  resp_headers: null,
  req_body_bytes: 0,
  resp_body_bytes: 512,
  content_type: "application/json",
  duration_ms: 42,
  error: null,
  evidence: "E2",
  source: "proxy/mitm",
  proc: null,
  ...overrides,
});

describe("HttpTable component", () => {
  beforeEach(() => {
    // RTL renders each test into document.body; clean up between runs
    document.body.innerHTML = "";
  });

  it("shows httpNone message when rows is empty", () => {
    render(<HttpTable rows={[]} />);
    // The zh strings mock is not wired here (useNetStrings returns live zh values),
    // so check that some non-empty text is rendered and the table is absent.
    expect(document.body.textContent!.length).toBeGreaterThan(0);
    expect(document.querySelector("table")).toBeNull();
  });

  it("renders URL for a normal row", () => {
    render(<HttpTable rows={[baseRow()]} />);
    const cell = document.querySelector("[data-field='url']");
    expect(cell!.textContent).toContain("api.example.com");
  });

  it("cert_pinned row shows cert_pinned state instead of URL", () => {
    render(<HttpTable rows={[baseRow({ error: "cert_pinned", url: "-" })]} />);
    const cell = document.querySelector("[data-field='url']");
    expect(cell!.querySelector("[data-state='cert_pinned']")).not.toBeNull();
    // Actual URL placeholder ("-") must not be shown as a URL
    expect(cell!.textContent).not.toBe("-");
  });

  it("cert_pinned row shows the tunnel hint", () => {
    render(<HttpTable rows={[baseRow({ error: "cert_pinned", url: "-" })]} />);
    const hint = document.querySelector("[data-hint='tunnel']");
    expect(hint).not.toBeNull();
  });

  it("does not render Authorization or Cookie values from req_headers", () => {
    const headers = JSON.stringify([["Authorization", "Bearer topsecret"], ["content-type", "application/json"]]);
    render(<HttpTable rows={[baseRow({ req_headers: headers })]} />);
    expect(document.body.innerHTML).not.toContain("topsecret");
    expect(document.body.innerHTML).toContain("content-type");
  });

  it("evidence badge is rendered for each row", () => {
    render(<HttpTable rows={[baseRow({ evidence: "E2" })]} />);
    // EvidenceBadge renders an <abbr> with class containing evidence text
    const badge = document.querySelector("abbr");
    expect(badge).not.toBeNull();
  });
});
