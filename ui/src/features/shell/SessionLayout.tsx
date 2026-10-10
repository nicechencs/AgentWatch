import { isWallTime } from "@/lib/format";
import { Link, Outlet, useParams } from "@tanstack/react-router";
import * as Dropdown from "@radix-ui/react-dropdown-menu";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { api } from "@/api/client";
import { DensityBar } from "@/components/DensityBar";
import { FilterBar } from "@/components/FilterBar";
import { RelTime } from "@/components/RelTime";
import { ErrorNote, Loading } from "@/components/QueryState";
import { composedFilter, useSessionQuery } from "@/lib/session-query";
import { useExport } from "@/lib/use-export";
import { sessionQueryOptions } from "@/lib/live-session";
import { sessionTitle } from "@/lib/session-title";
import { useI18n } from "@/lib/i18n";

const TABS = [
  { to: "/s/$sid", key: "nav.overview", exact: true },
  { to: "/s/$sid/timeline", key: "nav.timeline" },
  { to: "/s/$sid/processes", key: "nav.processes" },
  { to: "/s/$sid/files", key: "nav.files" },
  { to: "/s/$sid/network", key: "nav.network" },
  { to: "/s/$sid/findings", key: "nav.findings" },
  { to: "/s/$sid/self-report", key: "nav.selfReport" },
  { to: "/s/$sid/gaps", key: "nav.gaps" },
] as const;

/** Top bar, tabs, shared filter and density strip for every in-session page. */
export function SessionLayout() {
  const { t } = useI18n();
  const exporter = useExport();
  const { sid } = useParams({ strict: false }) as { sid: string };
  const { query, patch } = useSessionQuery();
  const [stopping, setStopping] = useState(false);
  const [stopError, setStopError] = useState<unknown>(null);
  const client = useQueryClient();
  const session = useQuery(sessionQueryOptions(sid));
  const ended = session.data ? session.data.ended_ns !== null || Boolean(session.data.purged) : null;
  const wasRecording = useRef(false);
  useEffect(() => {
    // The program exited on its own: the counts on the other tabs were read
    // while recording, re-read them once.
    if (ended === false) wasRecording.current = true;
    if (ended === true && wasRecording.current) {
      wasRecording.current = false;
      void client.invalidateQueries({ queryKey: ["summary", sid] });
      void client.invalidateQueries({ queryKey: ["processes", sid] });
      void client.invalidateQueries({ queryKey: ["histogram", sid] });
    }
  }, [ended, client, sid]);
  const histogram = useQuery({
    queryKey: ["histogram", sid, query.f, query.ev, query.subtree, query.proc],
    queryFn: () => api.histogram(sid, { filter: composedFilter(query), buckets: 60 }),
  });

  if (session.isLoading) return <Loading />;
  if (session.isError || !session.data) {
    // Keep a way back: this page used to be a lone error line with no header.
    return (
      <div className="flex h-screen flex-col">
        <header className="flex items-center gap-3 border-b border-line px-3 py-2">
          <Link to="/" className="text-sm font-semibold">
            {t("app.name")}
          </Link>
          <Link to="/" className="text-xs text-ink-soft underline" data-back="">
            ← {t("session.backToList")}
          </Link>
        </header>
        <ErrorNote error={session.error} onRetry={() => void session.refetch()} />
      </div>
    );
  }
  const data = session.data;
  const active = data.ended_ns === null && !data.purged;

  const stop = async () => {
    setStopping(true);
    setStopError(null);
    try {
      await api.stopSession(sid);
      await session.refetch();
      // Counts on the other tabs were read while recording.
      void client.invalidateQueries({ queryKey: ["summary", sid] });
      void client.invalidateQueries({ queryKey: ["processes", sid] });
    } catch (caught) {
      setStopError(caught);
    } finally {
      setStopping(false);
    }
  };

  return (
    <div className="flex h-screen flex-col">
      <header className="flex items-center gap-3 border-b border-line px-3 py-2">
        <Link to="/" className="text-sm font-semibold">
          {t("app.name")}
        </Link>
        <span className="text-ink-faint">▸</span>
        <nav aria-label={t("session.breadcrumb")} className="flex min-w-0 items-center gap-1 text-sm">
          <Link to="/" className="text-ink-soft underline" data-breadcrumb="sessions">
            {t("nav.sessions")}
          </Link>
          <span className="text-ink-faint">/</span>
          <span className="truncate">{sessionTitle(data)}</span>
        </nav>
        <span className="font-mono text-xs">{data.public_id}</span>
        <span className={`text-xs ${active ? "text-accent" : "text-ink-faint"}`}>
          {active ? `● ${t("session.recording")}` : `○ ${t("session.stopped")}`}
        </span>
        <span className="text-xs text-ink-faint">
          {isWallTime(data.started_ns) ? <RelTime ns={data.started_ns} /> : "–"}
        </span>
        <div className="ml-auto flex gap-2">
          {active ? (
            <button type="button" onClick={stop} disabled={stopping} className="rounded border border-line px-2 py-1 text-xs">
              {stopping ? t("session.stopping") : t("session.stop")}
            </button>
          ) : null}
          <Dropdown.Root>
            <Dropdown.Trigger className="rounded border border-line px-2 py-1 text-xs">
              {t("session.export")} ▾
            </Dropdown.Trigger>
            <Dropdown.Portal>
              <Dropdown.Content className="rounded border border-line bg-paper p-1 text-xs shadow">
                {(["jsonl", "csv", "md"] as const).map((format) => (
                  <Dropdown.Item
                    key={format}
                    className="block cursor-pointer rounded px-2 py-1 hover:bg-paper-sunken"
                    disabled={exporter.pending !== null}
                    onSelect={() => void exporter.run(sid, format)}
                  >
                    {t(`session.export.${format}`)}
                  </Dropdown.Item>
                ))}
              </Dropdown.Content>
            </Dropdown.Portal>
          </Dropdown.Root>
          {exporter.error ? (
            <span role="alert" className="text-xs text-gap">
              {exporter.error}
            </span>
          ) : null}
          {exporter.notice ? (
            <span role="status" className="max-w-xs truncate text-xs text-ink-soft" title={exporter.notice}>
              {exporter.notice}
            </span>
          ) : null}
        </div>
      </header>
      {stopError ? <ErrorNote error={stopError} /> : null}
      <nav className="flex gap-1 border-b border-line px-3">
        {TABS.map((tab) => (
          <Link
            key={tab.key}
            to={tab.to}
            params={{ sid }}
            search={{}}
            activeOptions={{ exact: "exact" in tab }}
            className="border-b-2 border-transparent px-2 py-1.5 text-xs text-ink-soft"
            activeProps={{ className: "border-b-2 border-accent px-2 py-1.5 text-xs text-ink" }}
          >
            {t(tab.key)}
            {tab.key === "nav.gaps" && data.stats?.gap_count ? ` (${data.stats.gap_count})` : ""}
          </Link>
        ))}
      </nav>
      <FilterBar query={query} patch={patch} />
      {histogram.data ? (
        <div className="relative">
          <DensityBar
            buckets={histogram.data.buckets}
            onSelect={(from, to) => patch({ from, to })}
          />
          {query.from || query.to ? (
            <button
              type="button"
              onClick={() => patch({ from: "", to: "" })}
              className="absolute right-2 top-1 text-[11px] text-ink-faint underline"
            >
              {t("density.clear")}
            </button>
          ) : null}
        </div>
      ) : null}
      <div className="min-h-0 flex-1">
        <Outlet />
      </div>
    </div>
  );
}
