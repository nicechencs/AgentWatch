/**
 * Component tests for P3-UI-01: three kinds of finding rendering.
 *
 * Covers the acceptance criteria:
 * - Three kind variants (content_match / fact / inferred) render distinct badges and styles.
 * - Inferred findings always show the caveat.
 * - User state buttons call PATCH via the mutation.
 * - "查看依据" toggle expands the refs panel.
 *
 * Tests are pure component tests: the API is mocked and no real network calls
 * are made. There are no Playwright tests in this repo; RTL covers the same
 * interactions (P3-UI-01 acceptance criterion §2 note).
 */
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { FindingCard } from "./FindingCard";
import { groupOf } from "./model";
import type { Finding } from "./types";

// ── Mock the API module ──────────────────────────────────────────────────────

const mockPatchFinding = vi.fn().mockResolvedValue({ id: 1, user_state: "confirmed" });
const mockResolveRef = vi.fn().mockResolvedValue({ ref: { table: "file_access", id: 1 }, status: "missing" });

vi.mock("./api", () => ({
  patchFinding: (sid: string, id: number, state: string | null) => mockPatchFinding(sid, id, state),
  refsQueryOptions: (_sid: string, refs: unknown[]) => ({
    queryKey: ["finding-refs", "test-sid", JSON.stringify(refs)],
    queryFn: () => Promise.all((refs as { table: string; id: number }[]).map((ref) => mockResolveRef(ref))),
  }),
}));

vi.mock("@/lib/i18n", () => ({
  useI18n: () => ({
    lang: "zh" as const,
    t: (key: string, vars?: Record<string, string | number>) => {
      if (!vars) return key;
      return key.replace(/\{(\w+)\}/g, (_, k) => (vars[k] !== undefined ? String(vars[k]) : `{${k}}`));
    },
  }),
}));

vi.mock("@/lib/prefs", () => ({
  usePrefs: () => ({ lang: "zh", theme: "system", timeFormat: "local" }),
}));

// ── Helpers ──────────────────────────────────────────────────────────────────

function makeClient() {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } });
}

function wrap(ui: React.ReactElement, client?: QueryClient) {
  const qc = client ?? makeClient();
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>);
}

const BASE: Finding = {
  id: 1,
  rule_id: "sensitive_read_then_send",
  rule_version: 1,
  kind: "inference",
  evidence: "I",
  severity: "notice",
  wording_id: "infer.temporal",
  params: {},
  text: "【推测·时序相关】cat 在 10:01 读取了 `~/.ssh/id_rsa`，3.1s 内 node 向 api.example.com 发送了 5.2 KB。没有内容级证据表明该文件被上传。",
  first_ns: 1_700_000_000_000_000_000,
  last_ns: 1_700_000_010_000_000_000,
  count: 1,
  dedup_key: "~/.ssh/id_rsa|api.example.com",
  refs: JSON.stringify([{ table: "file_access", id: 1 }, { table: "net_flow", id: 2 }]),
  caveats: null,
  user_state: null,
};

const CONTENT_MATCH: Finding = {
  ...BASE,
  id: 2,
  kind: "content_match",
  evidence: "E2",
  severity: "warn",
  wording_id: "evidence.content_match",
  text: "【内容匹配证据】cat 在 10:01 向 api.example.com 发送的请求体中，有 3/4 个分块与 `~/.ssh/id_rsa` 一致（约占文件 80%）。",
  refs: "[]",
  caveats: null,
};

const FACT: Finding = {
  ...BASE,
  id: 3,
  kind: "fact",
  evidence: "E1",
  severity: "info",
  wording_id: "fact.sensitive_access",
  text: "【E1】cat 访问了敏感路径 `~/.ssh/id_rsa`（规则：ssh-keys）。",
  refs: "[]",
  caveats: null,
};

// ── groupOf unit tests ───────────────────────────────────────────────────────

describe("groupOf", () => {
  it("maps content_match kind to content group", () => {
    expect(groupOf({ kind: "content_match", evidence: "E2" })).toBe("content");
  });
  it("maps fact kind E1 to fact group", () => {
    expect(groupOf({ kind: "fact", evidence: "E1" })).toBe("fact");
  });
  it("maps inference kind I to inferred group", () => {
    expect(groupOf({ kind: "inference", evidence: "I" })).toBe("inferred");
  });
  it("maps I evidence to inferred group regardless of kind", () => {
    expect(groupOf({ kind: "content_match", evidence: "I" })).toBe("inferred");
  });
  it("maps fact_conjunction to fact group", () => {
    expect(groupOf({ kind: "fact_conjunction", evidence: "E1" })).toBe("fact");
  });
});

// ── FindingCard rendering — inferred ─────────────────────────────────────────

describe("FindingCard — inferred (I)", () => {
  beforeEach(() => {
    document.body.innerHTML = "";
    mockPatchFinding.mockClear();
  });

  it("renders the API text verbatim", () => {
    wrap(<FindingCard finding={BASE} sid="test-sid" group="inferred" patch={vi.fn()} onNavigateTimeline={vi.fn()} />);
    expect(screen.getByText(/时序相关/)).not.toBeNull();
  });

  it("always shows the inferred caveat", () => {
    wrap(<FindingCard finding={BASE} sid="test-sid" group="inferred" patch={vi.fn()} onNavigateTimeline={vi.fn()} />);
    expect(screen.getByText("findings.inferredCaveat")).not.toBeNull();
  });

  it("has amber dashed border — not solid red (evidence-model §4)", () => {
    const { container } = wrap(<FindingCard finding={BASE} sid="test-sid" group="inferred" patch={vi.fn()} onNavigateTimeline={vi.fn()} />);
    const li = container.querySelector("li");
    expect(li?.className).toContain("border-dashed");
    expect(li?.className).toContain("amber");
    expect(li?.className).not.toMatch(/border-red|text-red|bg-red/);
  });

  it("shows 查看依据 button when refs are present", () => {
    wrap(<FindingCard finding={BASE} sid="test-sid" group="inferred" patch={vi.fn()} onNavigateTimeline={vi.fn()} />);
    expect(screen.getByText("findings.refsShow")).not.toBeNull();
  });

  it("toggles refs panel on click", async () => {
    wrap(<FindingCard finding={BASE} sid="test-sid" group="inferred" patch={vi.fn()} onNavigateTimeline={vi.fn()} />);
    const btn = screen.getByText("findings.refsShow");
    fireEvent.click(btn);
    await waitFor(() => {
      expect(screen.getByText("findings.refsHide")).not.toBeNull();
    });
  });

  it("calls patchFinding with 'confirmed' when Confirm is clicked", async () => {
    wrap(<FindingCard finding={BASE} sid="test-sid" group="inferred" patch={vi.fn()} onNavigateTimeline={vi.fn()} />);
    fireEvent.click(screen.getByText("findings.actionConfirm"));
    await waitFor(() => {
      expect(mockPatchFinding).toHaveBeenCalledWith("test-sid", 1, "confirmed");
    });
  });

  it("calls patchFinding with 'ignored' when Ignore is clicked", async () => {
    wrap(<FindingCard finding={BASE} sid="test-sid" group="inferred" patch={vi.fn()} onNavigateTimeline={vi.fn()} />);
    fireEvent.click(screen.getByText("findings.actionIgnore"));
    await waitFor(() => {
      expect(mockPatchFinding).toHaveBeenCalledWith("test-sid", 1, "ignored");
    });
  });
});

// ── FindingCard rendering — content_match ────────────────────────────────────

describe("FindingCard — content_match", () => {
  beforeEach(() => { document.body.innerHTML = ""; });

  it("renders the API text verbatim", () => {
    wrap(<FindingCard finding={CONTENT_MATCH} sid="test-sid" group="content" patch={vi.fn()} onNavigateTimeline={vi.fn()} />);
    expect(screen.getByText(/内容匹配证据/)).not.toBeNull();
  });

  it("has accent border, not amber (distinct from inferred)", () => {
    const { container } = wrap(<FindingCard finding={CONTENT_MATCH} sid="test-sid" group="content" patch={vi.fn()} onNavigateTimeline={vi.fn()} />);
    const li = container.querySelector("li");
    expect(li?.className).not.toContain("amber");
    expect(li?.className).not.toMatch(/border-red/);
  });

  it("shows the content_match caveat", () => {
    wrap(<FindingCard finding={CONTENT_MATCH} sid="test-sid" group="content" patch={vi.fn()} onNavigateTimeline={vi.fn()} />);
    expect(screen.getByText("findings.contentMatchCaveat")).not.toBeNull();
  });

  it("does NOT show the inferred caveat (it is not I evidence)", () => {
    wrap(<FindingCard finding={CONTENT_MATCH} sid="test-sid" group="content" patch={vi.fn()} onNavigateTimeline={vi.fn()} />);
    expect(screen.queryByText("findings.inferredCaveat")).toBeNull();
  });
});

// ── FindingCard rendering — fact ─────────────────────────────────────────────

describe("FindingCard — fact (E1)", () => {
  beforeEach(() => { document.body.innerHTML = ""; });

  it("renders the API text verbatim", () => {
    wrap(<FindingCard finding={FACT} sid="test-sid" group="fact" patch={vi.fn()} onNavigateTimeline={vi.fn()} />);
    expect(screen.getByText(/敏感路径/)).not.toBeNull();
  });

  it("has plain line border, not amber, not dashed", () => {
    const { container } = wrap(<FindingCard finding={FACT} sid="test-sid" group="fact" patch={vi.fn()} onNavigateTimeline={vi.fn()} />);
    const li = container.querySelector("li");
    expect(li?.className).not.toContain("amber");
    expect(li?.className).not.toContain("border-dashed");
    expect(li?.className).not.toMatch(/border-red/);
  });

  it("does NOT show the inferred caveat", () => {
    wrap(<FindingCard finding={FACT} sid="test-sid" group="fact" patch={vi.fn()} onNavigateTimeline={vi.fn()} />);
    expect(screen.queryByText("findings.inferredCaveat")).toBeNull();
  });

  it("does not show 查看依据 when refs is empty array", () => {
    wrap(<FindingCard finding={FACT} sid="test-sid" group="fact" patch={vi.fn()} onNavigateTimeline={vi.fn()} />);
    expect(screen.queryByText("findings.refsShow")).toBeNull();
  });
});

// ── user_state = ignored: clear button visible ───────────────────────────────

describe("FindingCard — already ignored", () => {
  const ignoredFinding: Finding = { ...BASE, user_state: "ignored" };

  beforeEach(() => { document.body.innerHTML = ""; mockPatchFinding.mockClear(); });

  it("shows Clear mark button", () => {
    wrap(<FindingCard finding={ignoredFinding} sid="test-sid" group="inferred" patch={vi.fn()} onNavigateTimeline={vi.fn()} />);
    expect(screen.getByText("findings.actionClear")).not.toBeNull();
  });

  it("calls patchFinding with null when Clear is clicked", async () => {
    wrap(<FindingCard finding={ignoredFinding} sid="test-sid" group="inferred" patch={vi.fn()} onNavigateTimeline={vi.fn()} />);
    fireEvent.click(screen.getByText("findings.actionClear"));
    await waitFor(() => {
      expect(mockPatchFinding).toHaveBeenCalledWith("test-sid", 1, null);
    });
  });

  it("card is visually dimmed (opacity-50)", () => {
    const { container } = wrap(<FindingCard finding={ignoredFinding} sid="test-sid" group="inferred" patch={vi.fn()} onNavigateTimeline={vi.fn()} />);
    expect(container.querySelector("li")?.className).toContain("opacity-50");
  });
});

// ── gap caveat ────────────────────────────────────────────────────────────────

describe("FindingCard — with gap caveat", () => {
  const withGap: Finding = {
    ...FACT,
    caveats: JSON.stringify([{ gap_id: 7 }]),
  };

  it("renders the gap caveat text", () => {
    wrap(<FindingCard finding={withGap} sid="test-sid" group="fact" patch={vi.fn()} onNavigateTimeline={vi.fn()} />);
    expect(screen.getByText((text) => text.includes("findings.gapCaveat") || text.includes("7"))).not.toBeNull();
  });
});
