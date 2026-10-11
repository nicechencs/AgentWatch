/**
 * Copy for the proxy settings section (P3-UI-02).
 *
 * Lives next to the feature because ui/src/i18n/ belongs to another task in
 * this phase. Move into ui/src/i18n/{zh,en}.json when that task lands.
 */
import { useI18n, type Lang } from "@/lib/i18n";

const zh = {
  title: "代理",
  colon: "：",
  caFingerprint: "CA 指纹",
  caCreated: "创建时间",
  caExpires: "到期时间",
  caUnprotected: "CA 私钥未加密保存：{reason}",
  caRetired: "{count} 个会话仍在使用已轮换的旧 CA",
  caUnavailable: "后台服务还没有提供 CA 状态，CA 信息不可得",
  caNone: "尚未生成 CA（首次启用代理的会话会生成）",
  rotate: "轮换 CA",
  rotateConfirmTitle: "轮换代理 CA",
  rotateConfirmBody:
    "将生成新的会话 CA。正在进行的代理会话继续使用旧 CA，结束后旧 CA 被删除。之后新会话的进程需要信任新 CA（通过环境变量注入，无需操作）。",
  rotateDone: "已轮换，新指纹见上方",
  rotateUnavailable: "后台服务还没有提供轮换功能。可以在终端运行：aw proxy rotate-ca",
  onReject: "客户端拒绝会话证书时",
  onRejectFail: "fail：连接失败并记录 cert_pinned（默认，不会静默降级）",
  onRejectTunnel: "tunnel：放行为 CONNECT 隧道，只记录域名和字节数，URL 不可得",
  trustTitle: "信任到用户证书库",
  trustUnavailable: "`aw proxy trust` 本版本未接入",
} as const;

export type ProxyStrings = { [K in keyof typeof zh]: string };

const en: ProxyStrings = {
  title: "Proxy",
  colon: ": ",
  caFingerprint: "CA fingerprint",
  caCreated: "Created",
  caExpires: "Expires",
  caUnprotected: "The CA private key is stored unencrypted: {reason}",
  caRetired: "{count} sessions still use a rotated CA",
  caUnavailable: "The background service does not report CA status yet; CA details are unavailable",
  caNone: "No CA yet (the first proxied session creates one)",
  rotate: "Rotate CA",
  rotateConfirmTitle: "Rotate proxy CA",
  rotateConfirmBody:
    "A new session CA will be generated. Running proxied sessions keep the old CA, which is deleted after they end. New sessions receive the new CA through environment variables.",
  rotateDone: "Rotated. The new fingerprint is shown above",
  rotateUnavailable: "The background service cannot rotate the CA yet. Run in a terminal: aw proxy rotate-ca",
  onReject: "When a client rejects the session certificate",
  onRejectFail: "fail: the connection fails and cert_pinned is recorded (default, no silent downgrade)",
  onRejectTunnel: "tunnel: pass through as a CONNECT tunnel; only domain and byte counts are kept, the URL is unavailable",
  trustTitle: "Trust in the user certificate store",
  trustUnavailable: "`aw proxy trust` is not wired in this version",
};

/** Both catalogs, for the locale tests. */
export const proxyCatalogs: Record<Lang, ProxyStrings> = { zh, en };
const catalogs = proxyCatalogs;

export function useProxyStrings(): ProxyStrings {
  return catalogs[useI18n().lang] ?? zh;
}

export function fill(template: string, vars: Record<string, string | number>): string {
  return template.replace(/\{(\w+)\}/g, (_, name: string) => (vars[name] === undefined ? `{${name}}` : String(vars[name])));
}
