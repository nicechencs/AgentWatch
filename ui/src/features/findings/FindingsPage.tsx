/**
 * FindingsPage — `GET /s/:sid/findings`
 *
 * Groups (ui §3.8): content_match → fact → inferred
 * Each group header carries a ⓘ with the evidence level explanation.
 * Ignored findings default to collapsed.
 */
import { useMemo, useState } from "react";
import { useNavigate, useParams } from "@tanstack/react-router";
import { useInfiniteQuery } from "@tanstack/react-query";
import { EmptyNote, ErrorNote, Loading } from "@/components/QueryState";
import { useI18n } from "@/lib/i18n";
import { usePrefs } from "@/lib/prefs";
import { useSessionQuery } from "@/lib/session-query";
import { allFindings, findingsQueryOptions } from "./api";
import { FindingCard } from "./FindingCard";
import { GROUP_ORDER, groupOf, sortFindings, type FindingGroup } from "./model";

const GROUP_KEY: Record<FindingGroup, { header: string; info: string }> = {
  content: {
    header: "findings.group.content",
    info: "findings.group.contentInfo",
  },
  fact: {
    header: "findings.group.fact",
    info: "findings.group.factInfo",
  },
  inferred: {
    header: "findings.group.inferred",
    info: "findings.group.inferredInfo",
  },
};

export function FindingsPage() {
  const { t } = useI18n();
  const { lang } = usePrefs();
  const { sid } = useParams({ strict: false }) as { sid: string };
  const { patch } = useSessionQuery();
  const navigate = useNavigate();
  const [showIgnored, setShowIgnored] = useState(false);

  const query = useInfiniteQuery(findingsQueryOptions(sid, lang));

  const all = useMemo(() => allFindings(query.data?.pages), [query.data]);
  const sorted = useMemo(() => sortFindings(all), [all]);

  const grouped = useMemo(() => {
    const map = new Map<FindingGroup, typeof sorted>();
    for (const g of GROUP_ORDER) map.set(g, []);
    for (const f of sorted) {
      map.get(groupOf(f))!.push(f);
    }
    return map;
  }, [sorted]);

  const active = useMemo(
    () =>
      new Map(
        [...grouped.entries()].map(([g, items]) => [
          g,
          showIgnored ? items : items.filter((f) => f.user_state !== "ignored"),
        ]),
      ),
    [grouped, showIgnored],
  );

  const ignoredCount = useMemo(
    () => sorted.filter((f) => f.user_state === "ignored").length,
    [sorted],
  );

  const navigateTimeline = (sid: string) => {
    void navigate({ to: "/s/$sid/timeline", params: { sid } });
  };

  if (query.isLoading) return <Loading />;
  if (query.isError) {
    return (
      <ErrorNote
        message={query.error instanceof Error ? query.error.message : ""}
        onRetry={() => void query.refetch()}
      />
    );
  }

  const nonEmpty = GROUP_ORDER.some((g) => (active.get(g)?.length ?? 0) > 0);

  return (
    <div className="mx-auto max-w-3xl px-4 py-6">
      {/* ── Controls ── */}
      <div className="mb-4 flex items-center justify-between">
        <h1 className="text-sm font-semibold">{t("nav.findings")}</h1>
        {ignoredCount > 0 ? (
          <button
            type="button"
            onClick={() => setShowIgnored((v) => !v)}
            className="text-[11px] text-ink-faint underline hover:text-ink"
          >
            {showIgnored
              ? t("findings.hideIgnored")
              : t("findings.showIgnored", { count: ignoredCount })}
          </button>
        ) : null}
      </div>

      {!nonEmpty ? (
        <EmptyNote>{t("findings.empty")}</EmptyNote>
      ) : (
        GROUP_ORDER.map((group) => {
          const items = active.get(group) ?? [];
          if (items.length === 0) return null;
          const keys = GROUP_KEY[group];
          return (
            <section key={group} className="mb-8">
              <GroupHeader
                header={t(keys.header)}
                info={t(keys.info)}
                count={items.length}
              />
              <ul className="flex flex-col gap-2">
                {items.map((finding) => (
                  <FindingCard
                    key={finding.id}
                    finding={finding}
                    sid={sid}
                    group={group}
                    patch={patch}
                    onNavigateTimeline={navigateTimeline}
                  />
                ))}
              </ul>
            </section>
          );
        })
      )}

      {query.hasNextPage ? (
        <button
          type="button"
          onClick={() => void query.fetchNextPage()}
          disabled={query.isFetchingNextPage}
          className="mt-4 text-[11px] text-accent underline disabled:opacity-40"
        >
          {t("common.more")}
        </button>
      ) : null}
    </div>
  );
}

function GroupHeader({
  header,
  info,
  count,
}: {
  header: string;
  info: string;
  count: number;
}) {
  return (
    <div className="mb-2 flex items-center gap-1.5">
      <h2 className="text-xs font-semibold text-ink-soft">{header}</h2>
      <abbr
        title={info}
        className="cursor-help text-[11px] text-ink-faint no-underline"
        aria-label={info}
      >
        ⓘ
      </abbr>
      <span className="text-[11px] text-ink-faint">({count})</span>
    </div>
  );
}
