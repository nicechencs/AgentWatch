/**
 * Self-report view (P5-UI-01).
 *
 * Left: E3 timeline rows the daemon already returns for `cats=agent`.
 * Right: E1/E2 rows from the same timeline, plus HTTP rows when that route
 * answers. There is no alignment API, so nothing is drawn as a matched pair
 * and nothing is scored. A missing route is an NA empty state, not zero rows.
 */
import { useQuery } from "@tanstack/react-query";
import { useParams } from "@tanstack/react-router";
import { EvidenceBadge } from "@/components/EvidenceBadge";
import { ProcLabel } from "@/components/ProcLabel";
import { RelTime } from "@/components/RelTime";
import { ErrorNote, Loading } from "@/components/QueryState";
import type { Gap, TimelineItem } from "@/api/types";
import { api } from "@/api/client";
import { useI18n } from "@/lib/i18n";
import { agentTimeline, httpOrMissing, observedTimeline } from "./api";

export function SelfReportPage() {
  const { t } = useI18n();
  const { sid } = useParams({ strict: false }) as { sid: string };

  const agents = useQuery({ queryKey: ["self-report", sid, "e3"], queryFn: () => agentTimeline(sid) });
  const observed = useQuery({ queryKey: ["self-report", sid, "e1"], queryFn: () => observedTimeline(sid) });
  const http = useQuery({ queryKey: ["self-report", sid, "http"], queryFn: () => httpOrMissing(sid) });
  const gaps = useQuery({ queryKey: ["gaps", sid], queryFn: () => api.gaps(sid) });

  if (agents.isLoading || observed.isLoading) return <Loading />;
  if (agents.isError || observed.isError) {
    const error = agents.error ?? observed.error;
    return (
      <ErrorNote
        message={error instanceof Error ? error.message : ""}
        onRetry={() => {
          void agents.refetch();
          void observed.refetch();
        }}
      />
    );
  }

  const e3 = agents.data ?? [];
  const e1 = observed.data ?? [];
  const selfReportGaps = (gaps.data?.gaps ?? []).filter(isSelfReportGap);
  const httpMissing = http.data?.missing === true;
  const httpRows = http.data?.page?.http ?? [];

  return (
    <div className="h-full overflow-auto px-4 py-3">
      <h1 className="text-sm font-semibold">{t("selfReport.title")}</h1>
      <p className="mt-1 text-xs text-ink-soft">{t("selfReport.lead")}</p>
      <p className="mt-1 text-[11px] text-ink-faint" data-na="agent-events">
        <EvidenceBadge level="NA" /> {t("selfReport.agentEventsNa")}
      </p>

      {selfReportGaps.length > 0 ? (
        <ul className="mt-2 space-y-1 text-xs" data-gaps="self-report">
          {selfReportGaps.map((gap) => (
            <li
              key={gap.id}
              className="rounded border border-dashed border-gap bg-[repeating-linear-gradient(135deg,transparent,transparent_4px,rgb(0_0_0/0.04)_4px,rgb(0_0_0/0.04)_8px)] px-2 py-1 text-gap"
            >
              {t("selfReport.gap", { reason: gap.reason || t("common.unavailable") })}
            </li>
          ))}
        </ul>
      ) : null}

      <div className="mt-3 grid gap-3 lg:grid-cols-2">
        <Column title={t("selfReport.left")}>
          {e3.length === 0 ? (
            <p className="text-xs text-ink-faint" data-empty="e3">
              {t("selfReport.noE3")}
            </p>
          ) : (
            <ul className="space-y-1">
              {e3.map((item) => (
                <li key={`e3-${item.id}`}>
                  <EventRow item={item} />
                </li>
              ))}
            </ul>
          )}
        </Column>
        <Column title={t("selfReport.right")}>
          {e1.length === 0 && httpRows.length === 0 ? (
            <p className="text-xs text-ink-faint" data-empty="e1">
              {t("selfReport.noObserved")}
            </p>
          ) : (
            <ul className="space-y-1">
              {e1.map((item) => (
                <li key={`e1-${item.kind}-${item.id}`}>
                  <EventRow item={item} />
                </li>
              ))}
              {httpRows.map((row) => (
                <li key={`http-${row.id}`} className="rounded border border-line px-2 py-1 text-xs">
                  <span className="font-mono">{row.method}</span> <span className="break-all font-mono">{row.url}</span>
                  <EvidenceBadge level={row.evidence} source={row.source} className="ml-1" />
                </li>
              ))}
            </ul>
          )}
          {httpMissing ? (
            <p className="mt-2 text-[11px] text-ink-faint" data-na="http">
              <EvidenceBadge level="NA" /> {t("selfReport.httpNa")}
            </p>
          ) : null}
        </Column>
      </div>

      <section className="mt-4 rounded border border-dashed border-amber-600 p-3 text-xs" data-section="unmatched">
        <h2 className="font-medium italic text-amber-700 dark:text-amber-400">{t("selfReport.unmatchedTitle")}</h2>
        <p className="mt-1 text-ink-faint">
          <EvidenceBadge level="NA" /> {t("selfReport.unmatchedNa")}
        </p>
      </section>
    </div>
  );
}

function Column({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="rounded border border-line p-3">
      <h2 className="text-xs font-medium">{title}</h2>
      <div className="mt-2">{children}</div>
    </section>
  );
}

function EventRow({ item }: { item: TimelineItem }) {
  return (
    <div className="rounded border border-line px-2 py-1 text-xs">
      <div className="flex items-center gap-2">
        <RelTime ns={item.ts_ns} />
        <EvidenceBadge level={item.evidence} source={item.source} naReason={item.na_reason} />
        {item.proc ? <ProcLabel pid={item.proc.pid} exe={item.proc.exe_name} /> : null}
      </div>
      <p className="mt-0.5 break-all font-mono">{item.summary || "–"}</p>
    </div>
  );
}

function isSelfReportGap(gap: Gap): boolean {
  return gap.kinds.some((kind) => kind.includes("self_report")) || gap.reason.includes("self_report");
}
