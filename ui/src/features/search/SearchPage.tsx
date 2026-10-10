import { useNavigate, useSearch } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { api } from "@/api/client";
import type { SearchHit } from "@/api/types";
import { EvidenceBadge } from "@/components/EvidenceBadge";
import { EmptyNote, ErrorNote } from "@/components/QueryState";
import { RelTime } from "@/components/RelTime";
import { nsToRfc3339 } from "@/lib/format";
import { kindLabel } from "@/lib/capabilities";
import { useI18n } from "@/lib/i18n";

const KINDS = ["", "file", "proc", "url"] as const;

export function SearchPage() {
  const { t } = useI18n();
  const navigate = useNavigate();
  const params = useSearch({ strict: false }) as { q?: string; kind?: string };
  const [draft, setDraft] = useState(params.q ?? "");
  const q = params.q ?? "";
  const kind = params.kind ?? "";

  const result = useQuery({
    queryKey: ["search", q, kind],
    queryFn: () => api.search({ q, kind: kind || undefined, limit: 50 }),
    enabled: q.trim().length > 0,
  });

  const submit = (event: React.FormEvent) => {
    event.preventDefault();
    void navigate({ to: "/search", search: { q: draft, kind } });
  };

  const open = (hit: SearchHit) => {
    const tenSeconds = 10_000_000_000;
    const kindFilter = ["file", "proc", "url"].includes(hit.kind) ? `kind:${hit.kind}` : undefined;
    // The daemon's hit names the row but not its time: open the session's
    // timeline unbounded rather than around an invented instant.
    void navigate({
      to: "/s/$sid/timeline",
      params: { sid: hit.session_id },
      search:
        hit.ts_ns === null
          ? { f: kindFilter }
          : { from: nsToRfc3339(hit.ts_ns - tenSeconds), to: nsToRfc3339(hit.ts_ns + tenSeconds), f: kindFilter },
    });
  };

  return (
    <main className="mx-auto max-w-3xl px-4 py-3">
      <h1 className="text-base font-semibold">{t("search.title")}</h1>
      <p className="mt-1 text-xs text-ink-faint">{t("search.hint")}</p>
      <form onSubmit={submit} className="mt-3 flex gap-2">
        <input
          value={draft}
          onChange={(event) => setDraft(event.target.value)}
          placeholder={t("search.placeholder")}
          className="flex-1 rounded border border-line bg-paper px-2 py-1 font-mono text-xs"
        />
        <select
          value={kind}
          onChange={(event) => void navigate({ to: "/search", search: { q, kind: event.target.value } })}
          className="rounded border border-line bg-paper px-2 py-1 text-xs"
        >
          {KINDS.map((item) => (
            <option key={item} value={item}>{t(item ? `search.kind.${item}` : "search.kind.all")}</option>
          ))}
        </select>
        <button type="submit" className="rounded bg-ink px-3 py-1 text-xs text-paper">{t("search.submit")}</button>
      </form>

      {result.data && !result.data.fts_enabled ? (
        <p className="mt-2 text-xs text-amber-700 dark:text-amber-400">{t("search.slow")}</p>
      ) : null}
      {result.isError ? <ErrorNote error={result.error} onRetry={() => void result.refetch()} /> : null}
      {result.data && result.data.groups.length === 0 ? <EmptyNote>{t("search.empty")}</EmptyNote> : null}

      <div className="mt-3 space-y-4">
        {result.data?.groups.map((group) => (
          <section key={group.session_id}>
            <h2 className="flex items-baseline gap-2 text-sm">
              <button type="button" onClick={() => void navigate({ to: "/s/$sid", params: { sid: group.session_id }, search: {} })} className="hover:underline">
                {group.session_name ?? group.session_id}
              </button>
              {group.session_name ? <span className="font-mono text-[11px] text-ink-faint">{group.session_id}</span> : null}
              <span className="text-xs text-ink-soft">{t("search.hits", { count: group.count })}</span>
              {group.count > group.hits.length ? <span className="text-[11px] text-ink-faint">{t("search.more", { count: group.hits.length })}</span> : null}
            </h2>
            <ul className="mt-1 text-xs">
              {group.hits.map((hit) => (
                <li key={`${hit.kind}:${hit.id}`} className="border-b border-line/60">
                  <button type="button" onClick={() => open(hit)} className="flex w-full items-baseline gap-2 py-1 text-left hover:bg-paper-sunken">
                    {hit.ts_ns === null ? <span className="text-ink-faint" title={t("search.noTime")}>–</span> : <RelTime ns={hit.ts_ns} precise />}
                    <span className="w-12 text-ink-faint">{kindLabel(t, hit.kind)}</span>
                    {hit.evidence ? <EvidenceBadge level={hit.evidence} /> : null}
                    <span className="truncate font-mono">{hit.summary ?? t("search.record", { id: hit.id })}</span>
                  </button>
                </li>
              ))}
            </ul>
          </section>
        ))}
      </div>
    </main>
  );
}
