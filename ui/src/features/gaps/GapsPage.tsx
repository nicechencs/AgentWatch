import { useNavigate, useParams } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/api/client";
import type { CollectorCapability, Gap } from "@/api/types";
import { Count } from "@/components/Count";
import { EvidenceBadge } from "@/components/EvidenceBadge";
import { EmptyNote, ErrorNote, Loading } from "@/components/QueryState";
import { formatClockRange, nsToRfc3339 } from "@/lib/format";
import { kindLabel } from "@/lib/capabilities";
import { useI18n } from "@/lib/i18n";
import { usePrefs } from "@/lib/prefs";
import { sessionQueryOptions } from "@/lib/live-session";

export function GapsPage() {
  const { t } = useI18n();
  const { timeFormat } = usePrefs();
  const { sid } = useParams({ strict: false }) as { sid: string };
  const navigate = useNavigate();
  const session = useQuery(sessionQueryOptions(sid));
  const gaps = useQuery({ queryKey: ["gaps", sid], queryFn: () => api.gaps(sid) });

  if (session.isLoading || gaps.isLoading) return <Loading />;
  if (session.isError || gaps.isError || !session.data || !gaps.data) {
    return <ErrorNote error={session.error ?? gaps.error} onRetry={() => { void session.refetch(); void gaps.refetch(); }} />;
  }

  const jump = (gap: Gap) => {
    void navigate({
      to: "/s/$sid/timeline",
      params: { sid },
      search: { from: nsToRfc3339(gap.from_ns), to: nsToRfc3339(gap.to_ns) },
    });
  };

  return (
    <div className="h-full overflow-auto px-4 py-3">
      <h2 className="text-sm font-medium">{t("gaps.collectors")}</h2>
      {session.data.collectors.length === 0 ? (
        <p className="mt-2 text-xs text-ink-faint" data-empty="collectors">{t("gaps.noCollectors")}</p>
      ) : null}
      <div className="mt-2 grid gap-3 lg:grid-cols-2">
        {session.data.collectors.map((collector) => {
          const available = collector.capabilities.filter((item) => item.evidence !== "NA");
          const missing = collector.capabilities.filter((item) => item.evidence === "NA");
          return (
            <section key={collector.name} className="rounded border border-line p-3 text-xs">
              <h3 className="font-mono text-sm">{collector.name}</h3>
              {collector.mode ? <p className="text-ink-faint">{collector.mode}</p> : null}
              {collector.capabilities.length === 0 ? <p className="mt-2 text-ink-faint">{t("gaps.capsNotDescribed")}</p> : null}
              <CapabilityList title={t("gaps.provides")} items={available} />
              <CapabilityList title={t("gaps.unavailable")} items={missing} />
            </section>
          );
        })}
      </div>

      <h2 className="mt-5 text-sm font-medium">{t("nav.gaps")}</h2>
      {gaps.data.gaps.length === 0 ? <EmptyNote>{t("gaps.empty")}</EmptyNote> : null}
      {gaps.data.gaps.length > 0 ? (
        <table className="mt-2 w-full border-collapse text-xs">
          <thead className="text-left text-ink-faint">
            <tr>
              {(["range", "collector", "kind", "affected", "count", "note"] as const).map((col) => (
                <th key={col} className="px-2 py-1 font-normal">{t(`gaps.col.${col}`)}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {gaps.data.gaps.map((gap) => (
              <tr key={gap.id} className={`border-b border-line/60 ${gap.degradation ? "bg-amber-500/10" : ""}`}>
                <td className="px-2 py-1">
                  <button type="button" onClick={() => jump(gap)} title={t("gaps.jump")} className="font-mono hover:underline">
                    {formatClockRange(gap.from_ns, gap.to_ns, timeFormat === "utc")}
                  </button>
                </td>
                <td className="px-2 py-1 font-mono">{gap.collector}</td>
                <td className="px-2 py-1">{gap.kinds.join(", ")}</td>
                <td className="px-2 py-1">{gap.affected.join(", ")}</td>
                <td className="px-2 py-1"><Count value={gap.count} /></td>
                <td className="px-2 py-1">
                  {gap.degradation ? <span className="mr-1 rounded border border-amber-600 px-1 text-amber-700 dark:text-amber-400">{t("gaps.degraded")}</span> : null}
                  {gap.reason}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}
    </div>
  );
}

function CapabilityList({ title, items }: { title: string; items: CollectorCapability[] }) {
  const { t } = useI18n();
  if (items.length === 0) return null;
  return (
    <div className="mt-2">
      <p className="text-ink-faint">{title}</p>
      <ul className="mt-1 space-y-1">
        {items.map((item) => (
          <li key={item.kind} className="flex items-center gap-2">
            <span>{kindLabel(t, item.kind)}</span>
            <EvidenceBadge level={item.evidence} naReason={item.na_reason} />
            {item.na_reason ? <span className="text-ink-faint">{t(`na.${item.na_reason}`)}</span> : null}
          </li>
        ))}
      </ul>
    </div>
  );
}
