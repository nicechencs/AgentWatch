/**
 * Copy for P3-UI-02 (HTTP layer and connection marks).
 *
 * Kept next to the feature because ui/src/i18n/ belongs to another task in
 * this phase. Move into ui/src/i18n/{zh,en}.json when that task lands; the
 * wording below follows evidence-model templates (no definitive verbs).
 */
import { useI18n, type Lang } from "@/lib/i18n";

const zh = {
  markDirect: "直连",
  markDirectTip: "此连接未经过代理，URL 不可得",
  markQuic: "QUIC",
  markQuicTip: "QUIC/HTTP3 不经过 HTTP 代理，URL 不可得",
  markViaProxy: "经代理",
  markViaProxyTip: "经会话代理转发；字节数取自内核观测到的回环连接（E1），URL 来自代理（E2）",
  colMethod: "方法",
  colUrl: "URL",
  colStatus: "状态码",
  colReq: "请求 body",
  colResp: "响应 body",
  colDuration: "耗时",
  colEvidence: "证据",
  headers: "白名单请求头",
  headersHidden: "已隐藏 {count} 个不展示的请求头",
  certPinned: "客户端拒绝了会话证书",
  certPinnedHint:
    "默认行为（fail）不会静默降级，所以这次连接失败。若改用 --proxy-on-reject tunnel，该连接会作为 CONNECT 隧道放行：连接可以继续，但只记录域名和字节数，URL 不可得。",
  httpNone: "代理没有记录到与此连接对应的 HTTP 请求",
  httpLoading: "正在读取 HTTP 请求…",
  httpTruncated: "只读取了前 {count} 条 HTTP 请求，其余未显示",
  httpUnlinked: "{count} 条 HTTP 请求没有关联到连接，未在此表显示",
  quickDirectTip: "只看未经过代理的连接",
} as const;

export type NetStrings = { [K in keyof typeof zh]: string };

const en: NetStrings = {
  markDirect: "direct",
  markDirectTip: "This connection did not go through the proxy; the URL is unavailable",
  markQuic: "QUIC",
  markQuicTip: "QUIC/HTTP3 does not pass through the HTTP proxy; the URL is unavailable",
  markViaProxy: "via proxy",
  markViaProxyTip: "Forwarded by the session proxy. Bytes come from the kernel-observed loopback connection (E1); the URL comes from the proxy (E2)",
  colMethod: "Method",
  colUrl: "URL",
  colStatus: "Status",
  colReq: "Request body",
  colResp: "Response body",
  colDuration: "Duration",
  colEvidence: "Evidence",
  headers: "Whitelisted request headers",
  headersHidden: "{count} headers not shown",
  certPinned: "The client rejected the session certificate",
  certPinnedHint:
    "The default (fail) does not downgrade silently, so this connection failed. With --proxy-on-reject tunnel the connection passes as a CONNECT tunnel: it can proceed, but only the domain and byte counts are kept and the URL is unavailable.",
  httpNone: "The proxy recorded no HTTP request for this connection",
  httpLoading: "Loading HTTP requests…",
  httpTruncated: "Only the first {count} HTTP requests were loaded",
  httpUnlinked: "{count} HTTP requests are not linked to a connection and are not shown here",
  quickDirectTip: "Only connections that did not go through the proxy",
};

const catalogs: Record<Lang, NetStrings> = { zh, en };

export function netStrings(lang: Lang): NetStrings {
  return catalogs[lang] ?? zh;
}

export function useNetStrings(): NetStrings {
  return netStrings(useI18n().lang);
}

export function fill(template: string, vars: Record<string, string | number>): string {
  return template.replace(/\{(\w+)\}/g, (_, name: string) => (vars[name] === undefined ? `{${name}}` : String(vars[name])));
}
