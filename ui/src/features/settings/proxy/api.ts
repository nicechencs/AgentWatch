/**
 * Proxy CA routes (crates/aw-daemon/src/api/proxy.rs), sent through the shared
 * `apiCall` in src/api/client.ts. The body carries the
 * fingerprint and times only; no key material.
 */
import { apiCall } from "@/api/client";
import { ApiError } from "@/api/errors";

export interface CaInfo {
  fingerprint: string;
  not_before_unix: number;
  not_after_unix: number;
  protected: boolean;
  unprotected_reason: string | null;
  retired_in_use: number;
}

export type TlsReject = "fail" | "tunnel";

const call = apiCall;

export const proxyApi = {
  caInfo: () => call<CaInfo | null>("GET", "/proxy/ca"),
  rotateCa: () => call<CaInfo>("POST", "/proxy/rotate-ca", { confirm: true }),
  setOnTlsReject: (value: TlsReject) => call<unknown>("PUT", "/config", { proxy: { on_tls_reject: value } }),
};

/** The route is not wired in this daemon build (404/501), not "no CA". */
export function routeMissing(caught: unknown): boolean {
  return caught instanceof ApiError && (caught.status === 404 || caught.status === 501);
}
