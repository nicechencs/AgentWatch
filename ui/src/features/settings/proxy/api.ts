/**
 * Proxy CA routes (crates/aw-daemon/src/api/proxy.rs). Not in src/api/client.ts
 * because that file is outside P3-UI-02's file range. The body carries the
 * fingerprint and times only; no key material.
 */
import { getToken } from "@/api/client";
import { ApiError } from "@/api/errors";
import type { ApiErrorBody } from "@/api/types";

export interface CaInfo {
  fingerprint: string;
  not_before_unix: number;
  not_after_unix: number;
  protected: boolean;
  unprotected_reason: string | null;
  retired_in_use: number;
}

export type TlsReject = "fail" | "tunnel";

async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers = new Headers();
  const token = getToken();
  if (token) headers.set("authorization", `Bearer ${token}`);
  if (body !== undefined) headers.set("content-type", "application/json");
  const response = await fetch(`/api/v1${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await response.text();
  const parsed = text ? (JSON.parse(text) as unknown) : null;
  if (!response.ok) throw new ApiError(response.status, parsed as ApiErrorBody | null, response.statusText);
  return parsed as T;
}

export const proxyApi = {
  caInfo: () => call<CaInfo | null>("GET", "/proxy/ca"),
  rotateCa: () => call<CaInfo>("POST", "/proxy/rotate-ca", { confirm: true }),
  setOnTlsReject: (value: TlsReject) => call<unknown>("PUT", "/config", { proxy: { on_tls_reject: value } }),
};

/** The route is not wired in this daemon build (404/501), not "no CA". */
export function routeMissing(caught: unknown): boolean {
  return caught instanceof ApiError && (caught.status === 404 || caught.status === 501);
}
