import { useParams } from "@tanstack/react-router";
import { useInfiniteQuery } from "@tanstack/react-query";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, subscribeLive } from "@/api/client";
import type { TimelineItem, TimelineKind } from "@/api/types";
import { DetailPanel, type DetailRecord } from "@/components/DetailPanel/DetailPanel";
import { EvidenceBadge } from "@/components/EvidenceBadge";
import { ProcLabel } from "@/components/ProcLabel";
import { RelTime } from "@/components/RelTime";
import { EmptyNote, ErrorNote } from "@/components/QueryState";
import { useListKeys } from "@/components/useListKeys";
import { formatClockRange } from "@/lib/format";
import { useI18n } from "@/lib/i18n";
import { usePrefs } from "@/lib/prefs";
import { composedFilter, useSessionQuery } from "@/lib/session-query";

const CATS: TimelineKind[] = ["proc", "file", "net", "dns", "http", "agent", "ipc", "rpc", "finding", "gap"];
const DEFAULT_ON = new Set<TimelineKind>(["proc", "file", "net", "dns", "http", "finding", "gap"]);
const PAGE = 500;
const MAX_ROWS = 2000;

const GLYPH: Record<TimelineKind, string> = {
  proc: "▶", file: "📄", net: "🔗", dns: "🌐", http: "↔",
  agent: "◎", ipc: "⇄", rpc: "⇢", finding: "∴", gap: "░",
};

export function TimelinePage() {
  const { t } = useI18n();
  const { timeFormat } = usePrefs();
  const utc = timeFormat === "utc";
  const { sid } = useParams({ strict: false }) as { sid: string };
  const { query, patch } = useSessionQuery();
  const [cats, setCats] = useState<Set<TimelineKind>>(new Set(DEFAULT_ON));
  const [merge, setMerge] = useState(true);
  const [follow, setFollow] = useState(false);
  const [lagged, setLagged] = useState(0);
  const [live, setLive] = useState<TimelineItem[]>([]);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [cursor, setCursor] = useState(0);
  const [open, setOpen] = useState(false);
  const scroller = useRef<HTMLDivElement>(null);

  const filter = composedFilter(query);
  const catList = CATS.filter((cat) => cats.has(cat));

  const pages = useInfiniteQuery({
    queryKey: ["timeline", sid, filter, query.from, query.to, catList.join(","), merge],
    initialPageParam: "",
    queryFn: ({ pageParam }) =>
      api.timeline(sid, {
        filter,
        from: query.from || undefined,
        to: query.to || undefined,
        cats: catList.join(","),
        density: merge ? "merge" : "raw",
        cursor: pageParam || undefined,
        limit: PAGE,
      }),
    getNextPageParam: (page) => page.next_cursor,
  });

  const rows = useMemo(() => {
    const history = (pages.data?.pages ?? []).flatMap((page) => page.items);
    const merged = follow ? [...live, ...history] : history;
    return merged.slice(0, MAX_ROWS);
  }, [pages.data, live, follow]);

  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scroller.current,
    estimateSize: () => 32,
    overscan: 20,
  });

  const virtualItems = virtualizer.getVirtualItems();
  useEffect(() => {
    const last = virtualItems[virtualItems.length - 1];
    if (last && last.index >= rows.length - 1 && pages.hasNextPage && !pages.isFetchingNextPage && rows.length < MAX_ROWS) {
      void pages.fetchNextPage();
    }
  }, [virtualItems, rows.length, pages]);

  useEffect(() => {
    if (!follow) return;
    const close = subscribeLive(sid, filter, {
      onRecord: (item) => {
        if (!cats.has(item.kind)) return;
        setLive((current) => [item, ...current].slice(0, PAGE));
        scroller.current?.scrollTo({ top: 0 });
      },
      onLagged: (dropped) => setLagged((current) => current + dropped),
      onError: () => setFollow(false),
    });
    return close;
  }, [follow, sid, filter, cats]);

  const selected = rows[cursor] ?? null;
  const record = selected ? toRecord(selected) : null;

  const onOpen = useCallback(() => setOpen(true), []);
  const onClose = useCallback(() => setOpen(false), []);
  useListKeys({ count: rows.length, cursor, setCursor, onOpen, onClose });

  useEffect(() => {
    if (rows.length === 0) return;
    virtualizer.scrollToIndex(cursor, { align: "auto" });
  }, [cursor, virtualizer, rows.length]);

  const toggle = (cat: TimelineKind) => {
    setCats((current) => {
      const next = new Set(current);
      if (next.has(cat)) next.delete(cat);
      else next.add(cat);
      return next;
    });
  };

  return (
    <div className="flex h-full">
      <div className="flex min-w-0 flex-1 flex-col">
        <div className="flex flex-wrap items-center gap-1 border-b border-line px-3 py-1.5 text-[11px]">
          {CATS.map((cat) => (
            <button
              key={cat}
              type="button"
              aria-pressed={cats.has(cat)}
              onClick={() => toggle(cat)}
              className={`rounded border px-1.5 py-0.5 ${cats.has(cat) ? "border-ink" : "border-line text-ink-faint"}`}
            >
              {t(`timeline.cats.${cat}`)}
            </button>
          ))}
          <label className="ml-auto flex items-center gap-1">
            {t("timeline.density")}
            <select value={merge ? "merge" : "raw"} onChange={(event) => setMerge(event.target.value === "merge")} className="rounded border border-line bg-paper px-1 py-0.5">
              <option value="merge">{t("timeline.densityMerge")}</option>
              <option value="raw">{t("timeline.densityRaw")}</option>
            </select>
          </label>
          <label className="flex items-center gap-1">
            <input type="checkbox" checked={follow} onChange={(event) => setFollow(event.target.checked)} />
            {t("timeline.follow")}
          </label>
        </div>
        {lagged > 0 ? <p className="bg-gap/10 px-3 py-1 text-[11px] text-gap">{t("timeline.lagged", { count: lagged })}</p> : null}

        {pages.isError ? <ErrorNote message={pages.error instanceof Error ? pages.error.message : ""} onRetry={() => void pages.refetch()} /> : null}
        {!pages.isLoading && rows.length === 0 ? <EmptyNote>{t("timeline.empty")}</EmptyNote> : null}

        <div ref={scroller} className="scroll-thin min-h-0 flex-1 overflow-auto">
          <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
            {virtualItems.map((virtual) => {
              const item = rows[virtual.index];
              return (
                <div
                  key={virtual.key}
                  data-index={virtual.index}
                  ref={virtualizer.measureElement}
                  style={{ position: "absolute", top: 0, left: 0, width: "100%", transform: `translateY(${virtual.start}px)` }}
                >
                  <TimelineRow
                    item={item}
                    active={virtual.index === cursor}
                    utc={utc}
                    expanded={expanded.has(rowKey(item))}
                    onToggle={() =>
                      setExpanded((current) => {
                        const next = new Set(current);
                        const key = rowKey(item);
                        if (next.has(key)) next.delete(key);
                        else next.add(key);
                        return next;
                      })
                    }
                    onSelect={() => {
                      setCursor(virtual.index);
                      setOpen(true);
                    }}
                  />
                </div>
              );
            })}
          </div>
        </div>
      </div>
      {open ? <DetailPanel record={record} patch={patch} onClose={() => setOpen(false)} /> : null}
    </div>
  );
}

function TimelineRow({
  item, active, utc, expanded, onToggle, onSelect,
}: {
  item: TimelineItem;
  active: boolean;
  utc: boolean;
  expanded: boolean;
  onToggle: () => void;
  onSelect: () => void;
}) {
  const { t } = useI18n();
  if (item.kind === "gap" && item.gap) {
    const gap = item.gap;
    return (
      <button type="button" onClick={onSelect} className="block w-full bg-gap/10 px-3 py-1 text-left text-xs text-gap">
        {t("timeline.gapBanner", {
          range: formatClockRange(gap.from_ns, gap.to_ns, utc),
          collector: gap.collector,
          count: gap.count,
          kinds: gap.kinds.join(","),
        })}
      </button>
    );
  }
  return (
    <button
      type="button"
      onClick={onSelect}
      className={`flex w-full items-baseline gap-3 px-3 py-1 text-left text-xs ${active ? "bg-paper-sunken" : "hover:bg-paper-sunken/60"}`}
    >
      <RelTime ns={item.ts_ns} precise />
      <EvidenceBadge level={item.evidence} source={item.source} naReason={item.na_reason} />
      <span aria-hidden="true">{GLYPH[item.kind]}</span>
      <span className="w-10 shrink-0 text-ink-faint">{item.kind}</span>
      <ProcLabel pid={item.proc?.pid} exe={item.proc?.exe_name} />
      <span className="min-w-0 flex-1 truncate">{item.summary}</span>
      {item.collapsed ? (
        <span
          role="button"
          tabIndex={0}
          onClick={(event) => {
            event.stopPropagation();
            onToggle();
          }}
          onKeyDown={(event) => {
            if (event.key === "Enter") {
              event.stopPropagation();
              onToggle();
            }
          }}
          className="shrink-0 text-ink-faint underline"
        >
          {expanded ? t("common.less") : t("timeline.collapsed", { dir: item.collapsed.dir, count: item.collapsed.count })}
        </span>
      ) : null}
      {item.kind === "finding" ? <span className="shrink-0 text-ink-faint">{t("timeline.findingLater")}</span> : null}
    </button>
  );
}

function rowKey(item: TimelineItem): string {
  return `${item.kind}:${item.id}:${item.ts_ns}`;
}

function toRecord(item: TimelineItem): DetailRecord {
  return {
    id: item.id,
    table: item.kind,
    tsNs: item.ts_ns,
    evidence: item.evidence,
    naReason: item.na_reason,
    source: item.source,
    corroboratedBy: item.corroborated_by,
    procUid: item.proc_uid,
    fields: item.fields,
    fieldEvidence: item.field_evidence,
  };
}
