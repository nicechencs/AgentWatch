import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api } from "@/api/client";
import { isApiError } from "@/api/errors";
import type { ConfigView, DoctorReport, RedactionRule } from "@/api/types";
import { Bytes } from "@/components/Bytes";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { ErrorNote, Loading } from "@/components/QueryState";
import { useAuth } from "@/lib/auth";
import { kindInSentence } from "@/lib/capabilities";
import { diskUnavailableText, diskUsed } from "@/lib/disk";
import { useI18n } from "@/lib/i18n";
import { redactPreview } from "@/lib/redact-preview";
import { usePrefs, type Theme, type TimeFormat } from "@/lib/prefs";
import type { Lang } from "@/lib/i18n";
import { ProxySection } from "@/features/settings/proxy/ProxySection";

export function SettingsPage() {
  const { t } = useI18n();
  const { me } = useAuth();
  const admin = me?.admin ?? false;
  const config = useQuery({ queryKey: ["config"], queryFn: () => api.config() });
  const stats = useQuery({ queryKey: ["db-stats"], queryFn: () => api.dbStats() });

  if (config.isLoading) return <Loading />;
  if (config.isError || !config.data) {
    return <ErrorNote error={config.error} onRetry={() => void config.refetch()} />;
  }

  return (
    <main className="mx-auto max-w-3xl px-4 py-3">
      <h1 className="text-base font-semibold">{t("settings.title")}</h1>
      <Storage config={config.data} used={diskUsed(stats.data)} usedNa={diskUnavailableText(stats.data, t)} admin={admin} />
      <Privacy config={config.data} admin={admin} />
      <ProxySection config={config.data} admin={admin} />
      <Collectors />
      <Rules config={config.data} />
      <Appearance />
    </main>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="mt-4 rounded border border-line p-3">
      <h2 className="text-sm font-medium">{title}</h2>
      <div className="mt-2 space-y-2 text-xs">{children}</div>
    </section>
  );
}

function Locked({ admin }: { admin: boolean }) {
  const { t } = useI18n();
  if (admin) return null;
  return <p className="text-ink-faint">{t("common.adminOnly")}</p>;
}

export function Storage({ config, used, usedNa, admin }: { config: ConfigView; used: number | null; usedNa: string; admin: boolean }) {
  const { t } = useI18n();
  const client = useQueryClient();
  const [days, setDays] = useState(String(config.retention.max_age_days));
  const [confirm, setConfirm] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  const save = useMutation({
    mutationFn: () => api.putConfig({ retention: { max_age_days: Number(days) } }),
    onSuccess: () => {
      setNotice(t("settings.saved"));
      void client.invalidateQueries({ queryKey: ["config"] });
    },
    onError: (caught) => setNotice(isApiError(caught) && caught.status === 403 ? t("settings.forbidden") : caught.message),
  });
  // "Current retention policy": sessions that ended more than max_age_days ago.
  // The daemon deletes only after a dry run and an explicit confirm; pinned and
  // running sessions are never deleted.
  const maxAge = config.retention.max_age_days;
  const scope = typeof maxAge === "number" && maxAge > 0 ? { older_than: `${maxAge}d` } : null;
  const [candidates, setCandidates] = useState<number | null>(null);
  const failed = (caught: Error) =>
    setNotice(isApiError(caught) && caught.status === 403 ? t("settings.forbidden") : caught.message);
  // Purging deletes every user's old sessions: administrators only. For anyone
  // else the button is disabled (attribute, not just styling) and no request
  // is ever sent, even if a click gets through.
  const canPurge = admin && scope !== null;
  const preview = useMutation({
    mutationFn: () => {
      if (!canPurge || !scope) return Promise.reject(new Error(t("settings.purgeNeedsAdmin")));
      return api.purgePreview(scope);
    },
    onSuccess: (result) => {
      setCandidates(result.would_purge.length);
      setConfirm(true);
    },
    onError: failed,
  });
  const purge = useMutation({
    mutationFn: () => {
      if (!canPurge || !scope) return Promise.reject(new Error(t("settings.purgeNeedsAdmin")));
      return api.purge(scope);
    },
    onSuccess: (result) => {
      setNotice(t("settings.purged", { count: result?.purged?.length ?? 0 }));
      void client.invalidateQueries({ queryKey: ["db-stats"] });
      void client.invalidateQueries({ queryKey: ["sessions"] });
    },
    onError: failed,
  });

  return (
    <Section title={t("settings.storage")}>
      <Locked admin={admin} />
      <p>{t("settings.used")}{t("common.colon")}{used === null ? <span className="text-ink-faint">{usedNa}</span> : <Bytes value={used} />}</p>
      <label className="flex items-center gap-2">
        {t("settings.maxBytes")}
        <span className="font-mono"><Bytes value={config.retention.max_db_bytes} /></span>
      </label>
      <label className="flex items-center gap-2">
        {t("settings.maxAge")}
        <input
          type="number"
          min={1}
          value={days}
          disabled={!admin}
          onChange={(event) => setDays(event.target.value)}
          className="w-20 rounded border border-line bg-paper px-1 py-0.5 disabled:text-ink-faint"
        />
      </label>
      <div className="flex gap-2">
        <button type="button" disabled={!admin || save.isPending} onClick={() => save.mutate()} className="rounded border border-line px-2 py-1 disabled:text-ink-faint">
          {t("common.save")}
        </button>
        <button
          type="button"
          data-purge=""
          disabled={!canPurge || preview.isPending || purge.isPending}
          aria-disabled={!canPurge || preview.isPending || purge.isPending}
          aria-describedby={admin ? undefined : "purge-needs-admin"}
          title={admin ? undefined : t("settings.purgeNeedsAdmin")}
          onClick={() => {
            if (canPurge) preview.mutate();
          }}
          className="rounded border border-line px-2 py-1 disabled:cursor-not-allowed disabled:text-ink-faint disabled:opacity-60"
        >
          {t("settings.purgeNow")}
        </button>
      </div>
      {admin ? null : (
        <p id="purge-needs-admin" className="text-ink-faint" data-purge-locked="">
          {t("settings.purgeNeedsAdmin")}
        </p>
      )}
      {notice ? <p className="text-ink-soft">{notice}</p> : null}
      <ConfirmDialog
        open={confirm && canPurge}
        title={t("settings.purgeNow")}
        body={`${t("settings.purgeConfirm")} ${t("settings.purgeCount", { count: candidates ?? 0, days: maxAge ?? "" })}`}
        onCancel={() => setConfirm(false)}
        onConfirm={() => {
          setConfirm(false);
          purge.mutate();
        }}
      />
    </Section>
  );
}

function Privacy({ config, admin }: { config: ConfigView; admin: boolean }) {
  const { t } = useI18n();
  const client = useQueryClient();
  const [pattern, setPattern] = useState("");
  const [sample, setSample] = useState(t("settings.ruleSampleDefault"));
  const [notice, setNotice] = useState<string | null>(null);

  const add = useMutation({
    mutationFn: (rule: RedactionRule) =>
      api.putConfig({ redaction: { rules: [...config.redaction.rules, rule] } }),
    onSuccess: () => {
      setPattern("");
      setNotice(t("settings.saved"));
      void client.invalidateQueries({ queryKey: ["config"] });
    },
    onError: (caught) => setNotice(isApiError(caught) && caught.status === 403 ? t("settings.forbidden") : caught.message),
  });

  const preview = redactPreview(pattern, sample);

  return (
    <Section title={t("settings.privacy")}>
      <p className="text-ink-faint">{t("settings.builtinReadonly")}</p>
      {config.redaction.rules.length === 0 ? <p className="text-ink-faint" data-empty="redaction">{t("settings.rulesNotListed")}</p> : null}
      <ul>
        {config.redaction.rules.map((rule) => (
          <li key={rule.id} className="flex items-baseline gap-2 border-b border-line/60 py-1">
            <span className="font-mono">{rule.id}</span>
            <span className="truncate text-ink-faint" title={rule.pattern || undefined}>
              {rule.builtin ? builtinRuleText(t, rule) : rule.pattern}
            </span>
            {rule.builtin ? null : <span className="text-ink-faint">{t("settings.customRule")}</span>}
          </li>
        ))}
      </ul>
      <Locked admin={admin} />
      <label className="block">
        {t("settings.rulePattern")}
        <input value={pattern} disabled={!admin} onChange={(event) => setPattern(event.target.value)} className="mt-1 w-full rounded border border-line bg-paper px-2 py-1 font-mono disabled:text-ink-faint" />
      </label>
      <label className="block">
        {t("settings.ruleSample")}
        <input value={sample} onChange={(event) => setSample(event.target.value)} className="mt-1 w-full rounded border border-line bg-paper px-2 py-1" />
      </label>
      <p>
        {t("settings.previewResult")}{t("common.colon")}<span className="font-mono">{preview.text}</span>
        {preview.invalid ? <span className="ml-2 text-amber-700 dark:text-amber-400">{t("settings.patternInvalid")}</span> : null}
      </p>
      <button
        type="button"
        disabled={!admin || pattern.trim() === "" || preview.invalid}
        onClick={() => add.mutate({ id: `custom-${Date.now()}`, builtin: false, pattern, description: null })}
        className="rounded border border-line px-2 py-1 disabled:text-ink-faint"
      >
        {t("settings.addRule")}
      </button>
      {notice ? <p className="text-ink-soft">{notice}</p> : null}
    </Section>
  );
}

/**
 * What the collectors are doing now, from the service's runtime state
 * (`GET /doctor` → `collectors`). Not the config: its per-platform switch
 * table (`linux: tls_uprobe=off …`) read as 「linux 未启用」 while process
 * sampling was running.
 */
export function Collectors() {
  const { t } = useI18n();
  const doctor = useQuery({ queryKey: ["doctor"], queryFn: () => api.doctor(), refetchInterval: 10_000 });
  return (
    <Section title={t("settings.collectors")}>
      {doctor.isLoading ? <p className="text-ink-faint">{t("common.loading")}</p> : null}
      {doctor.isError ? <ErrorNote error={doctor.error} onRetry={() => void doctor.refetch()} /> : null}
      {doctor.data && doctor.data.collectors.length === 0 ? (
        <p className="text-ink-faint" data-empty="collectors">{t("settings.collectorsNotListed")}</p>
      ) : null}
      <ul>
        {(doctor.data?.collectors ?? []).map((collector) => (
          <li key={collector.name} className="flex flex-wrap items-baseline gap-2 border-b border-line/60 py-1" data-collector={collector.name} data-status={collector.status}>
            <span>{collectorName(t, collector.name)}</span>
            <span className={collector.status === "running" ? "" : "text-ink-faint"}>{collectorStatus(t, collector)}</span>
            {collector.capabilities && collector.capabilities.length > 0 ? (
              <span className="text-ink-faint">
                {collector.capabilities
                  .map((cap) => `${kindInSentence(t, cap.kind)} ${cap.evidence && cap.evidence !== "NA" ? t("settings.capYes") : t("settings.capNo")}`)
                  .join(t("common.listSep"))}
              </span>
            ) : null}
          </li>
        ))}
      </ul>
    </Section>
  );
}

function collectorName(t: (key: string) => string, name: string): string {
  const key = `settings.collectorName.${name}`;
  const text = t(key);
  return text === key ? name : text;
}

function collectorStatus(
  t: (key: string, vars?: Record<string, string | number>) => string,
  collector: DoctorReport["collectors"][number],
): string {
  switch (collector.status) {
    case "running":
      if (collector.daemon_sample && collector.watched_roots) return t("settings.collectorRunningBoth", { count: collector.watched_roots });
      if (collector.watched_roots) return t("settings.collectorRunningSessions", { count: collector.watched_roots });
      return t("settings.collectorRunning");
    case "stopped":
      return t("settings.collectorStopped");
    case "not_built":
      return t("settings.collectorNotBuilt");
    default:
      return t("settings.collectorUnknown");
  }
}

function Rules({ config }: { config: ConfigView }) {
  const { t } = useI18n();
  return (
    <Section title={t("settings.rules")}>
      <p className="text-ink-faint">{t("settings.rulesReadonly")}</p>
      {config.rules.length === 0 ? <p className="text-ink-faint" data-empty="rules">{t("settings.detectRulesNotListed")}</p> : null}
      <ul>
        {config.rules.map((rule) => (
          <li key={rule.id} className="flex items-center gap-2 border-b border-line/60 py-1">
            <input type="checkbox" checked={rule.enabled} disabled readOnly />
            <span className="font-mono">{rule.id}</span>
          </li>
        ))}
      </ul>
    </Section>
  );
}

function Appearance() {
  const { t } = useI18n();
  const { lang, theme, timeFormat, setLang, setTheme, setTimeFormat } = usePrefs();
  return (
    <Section title={t("settings.appearance")}>
      <label className="flex items-center gap-2">
        {t("settings.lang")}
        <select value={lang} onChange={(event) => setLang(event.target.value as Lang)} className="rounded border border-line bg-paper px-1 py-0.5">
          <option value="zh">中文</option>
          <option value="en">English</option>
        </select>
      </label>
      <label className="flex items-center gap-2">
        {t("settings.theme")}
        <select value={theme} onChange={(event) => setTheme(event.target.value as Theme)} className="rounded border border-line bg-paper px-1 py-0.5">
          {(["system", "light", "dark"] as const).map((item) => (
            <option key={item} value={item}>{t(`settings.theme.${item}`)}</option>
          ))}
        </select>
      </label>
      <label className="flex items-center gap-2">
        {t("settings.timeFormat")}
        <select value={timeFormat} onChange={(event) => setTimeFormat(event.target.value as TimeFormat)} className="rounded border border-line bg-paper px-1 py-0.5">
          <option value="local">{t("settings.time.local")}</option>
          <option value="utc">{t("settings.time.utc")}</option>
        </select>
      </label>
    </Section>
  );
}

/** Chinese (or English) sentence for a built-in rule; the regex when there is none. */
function builtinRuleText(t: (key: string) => string, rule: { id: string; description: string | null; pattern: string }): string {
  const key = `redact.rule.${rule.id}`;
  const text = t(key);
  if (text !== key) return text;
  return rule.description ?? rule.pattern;
}
