import type { ReactNode } from "react";
import { Link, useNavigate, useParams } from "@tanstack/react-router";
import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { api } from "@/api/client";
import type { SessionSummary, TopEntry } from "@/api/types";
import { allFindings, findingsQueryOptions } from "@/features/findings/api";
import type { Finding } from "@/features/findings/types";
import { Bytes } from "@/components/Bytes";
import { Count } from "@/components/Count";
import { EvidenceBadge } from "@/components/EvidenceBadge";
import { ErrorNote, Loading } from "@/components/QueryState";
import { useI18n } from "@/lib/i18n";
import { usePrefs } from "@/lib/prefs";
import { useSessionQuery } from "@/lib/session-query";

export function OverviewPage() {
  const { sid } = useParams({ strict: false }) as { sid: string };
  const { query } = useSessionQuery();
  const summary = useQuery({
    queryKey: ["summary", sid],
    queryFn: () => api.summary(sid),
  });

  if (summary.isLoading) return <Loading />;
  if (summary.isError || !summary.data) {
    return <ErrorNote message={summary.error instanceof Error ? summary.error.message : ""} onRetry={() => void summary.refetch()} />;
  }
  return <Overview summary={summary.data} filter={query.f} />;
}

function Overview({ summary, filter }: { summary: SessionSummary; filter: string }) {
  const { t } = useI18n();
  const { lang } = usePrefs();
  const navigate = useNavigate();
  const findings = useInfiniteQuery(findingsQueryOptions(summary.session.public_id, lang));
  const { session } = summary;
  const approx = summary.approximate;
  const reason = summary.approximate_reason;
  const stats = session.stats;

  const jump = (page: "files" | "network", expression: string) => {
    const f = [filter, expression].filter(Boolean).join(" ");
    void navigate({ to: page === "files" ? "/s/$sid/files" : "/s/$sid/network", params: { sid: session.public_id }, search: { f } });
  };

  const kpis: { label: string; value: ReactNode }[] = [
    { label: t("overview.procs"), value: <Count value={stats?.proc_count} approximate={approx} approximateReason={reason} /> },
    { label: t("overview.commands"), value: <Count value={summary.top_commands.reduce((sum, item) => sum + item.count, 0)} approximate={approx} approximateReason={reason} /> },
    { label: t("overview.files"), value: <Count value={stats?.file_count} approximate={approx} approximateReason={reason} /> },
    {
      label: t("overview.writeDelete"),
      value: (
        <span>
          <Count value={stats?.write_count} approximate={approx} approximateReason={reason} /> /{" "}
          <Count value={stats?.delete_count} approximate={approx} approximateReason={reason} />
        </span>
      ),
    },
    { label: t("overview.domains"), value: <Count value={stats?.domain_count} approximate={approx} approximateReason={reason} /> },
    { label: t("overview.up"), value: <Bytes value={stats?.bytes_up} approximate={approx} approximateReason={reason} /> },
    { label: t("overview.down"), value: <Bytes value={stats?.bytes_down} approximate={approx} approximateReason={reason} /> },
  ];

  return (
    <div className="h-full overflow-auto px-4 py-3">
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4 lg:grid-cols-7">
        {kpis.map((kpi) => (
          <div key={kpi.label} className="rounded border border-line px-3 py-2">
            <div className="text-lg">{kpi.value}</div>
            <div className="text-[11px] text-ink-faint">{kpi.label}</div>
          </div>
        ))}
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
        <span className="text-ink-faint">{t("overview.capabilities")}</span>
        {session.collectors.flatMap((collector) =>
          collector.capabilities.map((capability) => (
            <span key={`${collector.name}-${capability.kind}`} className="flex items-center gap-1">
              {capability.kind}
              <EvidenceBadge level={capability.evidence} source={collector.name} naReason={capability.na_reason} />
            </span>
          )),
        )}
      </div>
      <p className="mt-1 text-xs text-ink-soft">
        {summary.gap_count > 0 ? (
          <span className="text-gap">{t("overview.gaps", { count: summary.gap_count })}</span>
        ) : (
          t("overview.noGaps")
        )}
        {summary.direct_count > 0 ? <span> · {t("overview.direct", { count: summary.direct_count })}</span> : null}
      </p>

      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <section className="rounded border border-line p-3">
          <h2 className="text-sm font-medium">{t("overview.findings")}</h2>
          <FindingsPreview
            loading={findings.isLoading}
            failed={findings.isError}
            message={findings.error instanceof Error ? findings.error.message : ""}
            onRetry={() => void findings.refetch()}
            items={allFindings(findings.data?.pages)}
            sid={session.public_id}
            gapCount={summary.gap_count}
          />
        </section>

        <TopTable
          title={t("overview.topDomains")}
          rows={summary.top_domains}
          onPick={(row) => jump("network", `domain:${quote(row.label)}`)}
          render={(row) => (
            <span className="tabular-nums">
              <Bytes value={row.bytes_up} /> / <Bytes value={row.bytes_down} />
            </span>
          )}
        />
        <TopTable
          title={t("overview.topDirs")}
          rows={summary.top_dirs}
          onPick={(row) => jump("files", `dir:${quote(row.label)}`)}
          render={(row) => <span className="text-ink-faint">{t("overview.writes", { count: row.writes ?? 0 })}</span>}
        />
        <TopTable
          title={t("overview.topCommands")}
          rows={summary.top_commands}
          onPick={(row) => jump("files", `proc:${quote(row.label)}`)}
          render={(row) => <Count value={row.count} />}
        />
      </div>
    </div>
  );
}

const PREVIEW = 5;

function FindingsPreview({
  loading, failed, message, onRetry, items, sid, gapCount,
}: {
  loading: boolean;
  failed: boolean;
  message: string;
  onRetry: () => void;
  items: Finding[];
  sid: string;
  gapCount: number;
}) {
  const { t } = useI18n();
  if (loading) return <p className="mt-2 text-xs text-ink-faint">{t("common.loading")}</p>;
  if (failed) return <ErrorNote message={message} onRetry={onRetry} />;
  if (items.length === 0) {
    return (
      <p className="mt-2 text-xs">
        {t("overview.findingsEmpty")}
        {gapCount > 0 ? <span className="text-ink-faint"> · {t("overview.findingsEmptyGaps", { count: gapCount })}</span> : null}
      </p>
    );
  }
  const shown = items.slice(0, PREVIEW);
  return (
    <div className="mt-2">
      <ul className="space-y-1 text-xs">
        {shown.map((finding) => (
          <li key={finding.id} className="truncate">
            <span className="mr-1 text-ink-faint">{finding.evidence}</span>
            {finding.text ?? t("common.unavailable")}
          </li>
        ))}
      </ul>
      <Link to="/s/$sid/findings" params={{ sid }} search={{}} className="mt-2 inline-block text-[11px] underline">
        {t("overview.findingsOpen", { count: items.length })}
      </Link>
    </div>
  );
}

function TopTable({
  title, rows, onPick, render,
}: {
  title: string;
  rows: TopEntry[];
  onPick: (row: TopEntry) => void;
  render: (row: TopEntry) => ReactNode;
}) {
  const { t } = useI18n();
  return (
    <section className="rounded border border-line p-3">
      <h2 className="text-sm font-medium">{title}</h2>
      {rows.length === 0 ? <p className="mt-2 text-xs text-ink-faint">{t("common.empty")}</p> : null}
      <ul className="mt-2 text-xs">
        {rows.map((row) => (
          <li key={row.label} className="flex items-center justify-between gap-2 border-b border-line/60 py-1">
            <button type="button" onClick={() => onPick(row)} className="truncate text-left font-mono hover:underline">
              {row.label}
            </button>
            <span className="flex items-center gap-2">
              {render(row)}
              {row.evidence ? <EvidenceBadge level={row.evidence} /> : null}
            </span>
          </li>
        ))}
      </ul>
    </section>
  );
}

function quote(value: string): string {
  return /[\s:*"]/u.test(value) ? `"${value.replaceAll('"', '\\"')}"` : value;
}
