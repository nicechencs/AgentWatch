import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { isApiError } from "@/api/errors";
import type { ConfigView } from "@/api/types";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { RelTime } from "@/components/RelTime";
import { copyText } from "@/lib/format";
import { useI18n } from "@/lib/i18n";
import { proxyApi, routeMissing, type CaInfo, type TlsReject } from "./api";
import { fill, useProxyStrings } from "./strings";

export const TRUST_COMMAND = "aw proxy trust --user";
export const UNTRUST_COMMAND = "aw proxy untrust";
export const ROTATE_COMMAND = "aw proxy rotate-ca";

/** `ConfigView.proxy` may carry `on_tls_reject` once the daemon returns it. */
type ProxyConfig = ConfigView["proxy"] & { on_tls_reject?: TlsReject };

export type CaState =
  | { kind: "loading" }
  | { kind: "ok"; info: CaInfo }
  | { kind: "none" }
  | { kind: "unavailable" }
  | { kind: "error"; message: string };

export interface ProxyViewProps {
  admin: boolean;
  config: ProxyConfig;
  ca: CaState;
  onTlsReject: TlsReject;
  notice: string | null;
  busy: boolean;
  onRotate: () => void;
  onChangeTlsReject: (value: TlsReject) => void;
}

/** Proxy section of /settings (ui §3.10). Stateless so it can be rendered in tests. */
export function ProxyView({ admin, config, ca, onTlsReject, notice, busy, onRotate, onChangeTlsReject }: ProxyViewProps) {
  const s = useProxyStrings();
  const { t } = useI18n();
  const [confirm, setConfirm] = useState(false);
  // Fallback to config values when /proxy/ca is not served; never invent a value.
  const fingerprint = ca.kind === "ok" ? ca.info.fingerprint : config.ca_fingerprint;
  const createdNs = ca.kind === "ok" ? ca.info.not_before_unix * 1_000_000_000 : config.ca_created_ns;
  const expiresNs = ca.kind === "ok" ? ca.info.not_after_unix * 1_000_000_000 : null;
  const unavailable = <span className="text-ink-faint">{t("common.unavailable")}</span>;

  return (
    <section className="mt-4 rounded border border-line p-3" aria-labelledby="settings-proxy">
      <h2 id="settings-proxy" className="text-sm font-medium">{s.title}</h2>
      <div className="mt-2 space-y-2 text-xs">
        {!admin ? <p className="text-ink-faint">{t("common.adminOnly")}</p> : null}
        {ca.kind === "unavailable" ? <p className="text-ink-faint" data-ca="unavailable">{s.caUnavailable}</p> : null}
        {ca.kind === "none" ? <p className="text-ink-faint" data-ca="none">{s.caNone}</p> : null}
        {ca.kind === "error" ? <p className="text-ink-soft">{ca.message}</p> : null}
        <p>{s.caFingerprint}{s.colon}<span className="break-all font-mono" data-field="fingerprint">{fingerprint ?? unavailable}</span></p>
        <p>{s.caCreated}{s.colon}{createdNs ? <RelTime ns={createdNs} /> : unavailable}</p>
        <p>{s.caExpires}{s.colon}{expiresNs ? <RelTime ns={expiresNs} /> : unavailable}</p>
        {ca.kind === "ok" && !ca.info.protected ? (
          <p className="text-ink-soft">{fill(s.caUnprotected, { reason: ca.info.unprotected_reason ?? "–" })}</p>
        ) : null}
        {ca.kind === "ok" && ca.info.retired_in_use > 0 ? (
          <p className="text-ink-faint">{fill(s.caRetired, { count: ca.info.retired_in_use })}</p>
        ) : null}
        <button
          type="button"
          disabled={!admin || busy}
          onClick={() => setConfirm(true)}
          className="rounded border border-line px-2 py-1 disabled:text-ink-faint"
        >
          {s.rotate}
        </button>

        <fieldset className="space-y-1" disabled={!admin || busy}>
          <legend>{s.onReject}</legend>
          {(["fail", "tunnel"] as const).map((value) => (
            <label key={value} className="flex items-start gap-1">
              <input
                type="radio"
                name="on_tls_reject"
                value={value}
                checked={onTlsReject === value}
                onChange={() => onChangeTlsReject(value)}
              />
              <span>{value === "fail" ? s.onRejectFail : s.onRejectTunnel}</span>
            </label>
          ))}
        </fieldset>

        {notice ? <p className="text-ink-soft" role="status">{notice}</p> : null}

        <div className="rounded border border-dashed border-line p-2" data-section="trust">
          <h3 className="font-medium">{s.trustTitle}</h3>
          <p className="mt-1 text-ink-soft">{s.trustBody}</p>
          <CommandLine command={TRUST_COMMAND} />
          <CommandLine command={UNTRUST_COMMAND} />
          <p className="mt-1 text-ink-soft">{s.trustRisk}</p>
        </div>
      </div>
      <ConfirmDialog
        open={confirm}
        title={s.rotateConfirmTitle}
        body={s.rotateConfirmBody}
        confirmLabel={s.rotate}
        onCancel={() => setConfirm(false)}
        onConfirm={() => {
          setConfirm(false);
          onRotate();
        }}
      />
    </section>
  );
}

/** A command the operator runs themselves. Copy only; nothing is executed. */
function CommandLine({ command }: { command: string }) {
  const s = useProxyStrings();
  const [copied, setCopied] = useState(false);
  return (
    <div className="mt-1 flex items-center gap-2">
      <code className="rounded bg-paper-sunken px-1 font-mono">{command}</code>
      <button
        type="button"
        onClick={() => void copyText(command).then((ok) => setCopied(ok))}
        className="text-ink-faint underline"
      >
        {copied ? s.copied : s.copy}
      </button>
    </div>
  );
}

/**
 * Whether this daemon build routes `/proxy/ca` and `/proxy/rotate-ca`. It does
 * not: the handlers in `crates/aw-daemon/src/api/proxy.rs` are not in the
 * route table or `openapi.rs`. Asking anyway put a 404 in the console on every
 * Settings visit. Flip this when the routes are wired.
 */
export const CA_ROUTES_SERVED = false;

/** Container: loads /proxy/ca, wires rotate and on_tls_reject. */
export function ProxySection({ config, admin }: { config: ConfigView; admin: boolean }) {
  const s = useProxyStrings();
  const { t } = useI18n();
  const client = useQueryClient();
  const proxy = config.proxy as ProxyConfig;
  const [onTlsReject, setOnTlsReject] = useState<TlsReject>(proxy.on_tls_reject ?? "fail");
  const [notice, setNotice] = useState<string | null>(null);

  const caQuery = useQuery({ queryKey: ["proxy-ca"], queryFn: () => proxyApi.caInfo(), retry: false, enabled: CA_ROUTES_SERVED });
  const ca: CaState = !CA_ROUTES_SERVED
    ? { kind: "unavailable" }
    : caQuery.isLoading
    ? { kind: "loading" }
    : caQuery.isError
      ? routeMissing(caQuery.error)
        ? { kind: "unavailable" }
        : { kind: "error", message: caQuery.error instanceof Error ? caQuery.error.message : "" }
      : caQuery.data
        ? { kind: "ok", info: caQuery.data }
        : { kind: "none" };

  const failMessage = (caught: Error) =>
    isApiError(caught) && caught.status === 403 ? t("settings.forbidden") : caught.message;

  const rotate = useMutation({
    mutationFn: () => proxyApi.rotateCa(),
    onSuccess: () => {
      setNotice(s.rotateDone);
      void client.invalidateQueries({ queryKey: ["proxy-ca"] });
      void client.invalidateQueries({ queryKey: ["config"] });
    },
    onError: (caught) => setNotice(routeMissing(caught) ? s.rotateUnavailable : failMessage(caught)),
  });
  const save = useMutation({
    mutationFn: (value: TlsReject) => proxyApi.setOnTlsReject(value),
    onSuccess: (_, value) => {
      setOnTlsReject(value);
      setNotice(t("settings.saved"));
      void client.invalidateQueries({ queryKey: ["config"] });
    },
    onError: (caught) => setNotice(failMessage(caught)),
  });

  return (
    <ProxyView
      admin={admin}
      config={proxy}
      ca={ca}
      onTlsReject={onTlsReject}
      notice={notice}
      busy={rotate.isPending || save.isPending}
      onRotate={() => (CA_ROUTES_SERVED ? rotate.mutate() : setNotice(s.rotateUnavailable))}
      onChangeTlsReject={(value) => save.mutate(value)}
    />
  );
}
