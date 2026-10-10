/**
 * The proxy settings section. The CA routes are not served yet, so the page
 * must not request /proxy/ca (that was a console 404).
 */
import { describe, expect, it, vi } from "vitest";
import { render } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { toConfigView } from "@/api/client";
import { CA_ROUTES_SERVED, ProxySection } from "@/features/settings/proxy/ProxySection";
import zh from "@/i18n/zh.json";

const ZH = zh as Record<string, string>;
const t = (key: string, vars?: Record<string, string | number>) =>
  (ZH[key] ?? key).replace(/\{(\w+)\}/gu, (_, name: string) => String(vars?.[name] ?? `{${name}}`));

vi.mock("@/lib/i18n", () => ({ useI18n: () => ({ lang: "zh", t }) }));
vi.mock("@/lib/prefs", () => ({ usePrefs: () => ({ lang: "zh", theme: "system", timeFormat: "utc" }) }));

describe("proxy CA routes", () => {
  it("does not request the unrouted /proxy/ca", async () => {
    expect(CA_ROUTES_SERVED).toBe(false);
    const calls: string[] = [];
    vi.stubGlobal("fetch", vi.fn(async (url: string) => { calls.push(String(url)); return new Response("{}", { status: 200 }); }));
    const view = toConfigView({ config: { proxy: { on_tls_reject: "fail" } } });
    render(
      <QueryClientProvider client={new QueryClient()}>
        <ProxySection config={view} admin={false} />
      </QueryClientProvider>,
    );
    await new Promise((resolve) => setTimeout(resolve, 20));
    vi.unstubAllGlobals();
    expect(calls.filter((url) => url.includes("/proxy/"))).toEqual([]);
  });
});
