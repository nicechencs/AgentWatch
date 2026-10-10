import { isWallTime } from "@/lib/format";
import { Link, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { api } from "@/api/client";
import type { DbStats, Session } from "@/api/types";
import { Bytes } from "@/components/Bytes";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { Count } from "@/components/Count";
import { EmptyNote, ErrorNote, Loading } from "@/components/QueryState";
import { RelTime } from "@/components/RelTime";
import { formatDuration } from "@/lib/format";
import { NotCollected } from "@/components/NotCollected";
import { coverage } from "@/lib/capabilities";
import { diskUnavailableText, diskUsed } from "@/lib/disk";
import { sessionTitle } from "@/lib/session-title";
import { useI18n } from "@/lib/i18n";
import { useExport } from "@/lib/use-export";

const RANGES = ["7d", "30d", "all"] as const;

export function SessionsPage() {
  const { t } = useI18n();
  const navigate = useNavigate();
  const client = useQueryClient();
  const [q, setQ] = useState("");
  const [agent, setAgent] = useState("");
  const [range, setRange] = useState<(typeof RANGES)[number]>("7d");
  const [activeOnly, setActiveOnly] = useState(false);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [pendingDelete, setPendingDelete] = useState<Session | null>(null);
  const [renaming, setRenaming] = useState<string | null>(null);

  const since = range === "all" ? undefined : range === "7d" ? "-7d" : "-30d";
  const sessions = useQuery({
    queryKey: ["sessions", q, agent, range, activeOnly],
    queryFn: () => api.sessions({ q, agent: agent || undefined, since, active: activeOnly || undefined, limit: 200 }),
  });
  const stats = useQuery({ queryKey: ["db-stats"], queryFn: () => api.dbStats() });

  const agents = useMemo(() => {
    const names = new Set<string>();
    for (const session of sessions.data?.items ?? []) if (session.agent) names.add(session.agent);
    return [...names].sort();
  }, [sessions.data]);

  const mutate = useMutation({
    mutationFn: async (action: { kind: "pin" | "delete" | "rename"; session: Session; name?: string }) => {
      if (action.kind === "delete") return api.deleteSession(action.session.public_id);
      if (action.kind === "pin") return api.patchSession(action.session.public_id, { pinned: !action.session.pinned });
      return api.patchSession(action.session.public_id, { name: action.name });
    },
    onSuccess: () => void client.invalidateQueries({ queryKey: ["sessions"] }),
  });

  const toggle = (id: string) => {
    setPicked((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  return (
    <main className="px-4 py-3">
      <div className="flex items-center gap-3">
        <h1 className="text-base font-semibold">{t("sessions.title")}</h1>
        <Link to="/new" className="rounded bg-ink px-2 py-1 text-xs text-paper">
          + {t("sessions.new")}
        </Link>
        <span className="ml-auto text-xs text-ink-faint">
          {stats.data ? <Disk stats={stats.data} /> : null}
        </span>
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-2 text-xs">
        <input
          value={q}
          onChange={(event) => setQ(event.target.value)}
          placeholder={t("sessions.search")}
          className="rounded border border-line bg-paper px-2 py-1"
        />
        <select value={agent} onChange={(event) => setAgent(event.target.value)} className="rounded border border-line bg-paper px-2 py-1">
          <option value="">{t("sessions.agentAll")}</option>
          {agents.map((name) => (
            <option key={name} value={name}>{name}</option>
          ))}
        </select>
        <select
          value={range}
          onChange={(event) => setRange(event.target.value as (typeof RANGES)[number])}
          className="rounded border border-line bg-paper px-2 py-1"
        >
          {RANGES.map((item) => (
            <option key={item} value={item}>{t(`sessions.range.${item}`)}</option>
          ))}
        </select>
        <label className="flex items-center gap-1">
          <input type="checkbox" checked={activeOnly} onChange={(event) => setActiveOnly(event.target.checked)} />
          {t("sessions.activeOnly")}
        </label>
        <button
          type="button"
          disabled={picked.size !== 2}
          title={picked.size === 2 ? t("sessions.compare") : t("sessions.compareNeedTwo")}
          onClick={() => {
            const [first, second] = [...picked];
            if (first && second) void navigate({ to: "/compare", search: { a: first, b: second } });
          }}
          className="ml-auto rounded border border-line px-2 py-1 disabled:text-ink-faint"
        >
          {t("sessions.compare")}
        </button>
      </div>

      {sessions.isLoading ? <Loading /> : null}
      {sessions.isError ? <ErrorNote error={sessions.error} onRetry={() => void sessions.refetch()} /> : null}
      {sessions.data && sessions.data.items.length === 0 ? <EmptyNote>{t("sessions.empty")}</EmptyNote> : null}

      {sessions.data && sessions.data.items.length > 0 ? (
        <table className="mt-3 w-full border-collapse text-xs">
          <thead>
            <tr className="border-b border-line text-left text-ink-faint">
              <th className="w-6" />
              {(["status", "name", "agent", "mode", "started", "duration", "procs", "traffic", "findings", "gaps", "size"] as const).map(
                (col) => (
                  <th key={col} className="px-2 py-1 font-normal">{t(`sessions.col.${col}`)}</th>
                ),
              )}
              <th />
            </tr>
          </thead>
          <tbody>
            {sessions.data.items.map((session) => (
              <SessionRow
                key={session.public_id}
                session={session}
                checked={picked.has(session.public_id)}
                renaming={renaming === session.public_id}
                onToggle={() => toggle(session.public_id)}
                onOpen={() => void navigate({ to: "/s/$sid", params: { sid: session.public_id }, search: {} })}
                onRenameStart={() => setRenaming(session.public_id)}
                onRename={(name) => {
                  setRenaming(null);
                  mutate.mutate({ kind: "rename", session, name });
                }}
                onPin={() => mutate.mutate({ kind: "pin", session })}
                onDelete={() => setPendingDelete(session)}
              />
            ))}
          </tbody>
        </table>
      ) : null}

      <ConfirmDialog
        open={pendingDelete !== null}
        title={t("sessions.delete")}
        body={t("sessions.deleteConfirm", { name: pendingDelete ? sessionTitle(pendingDelete) : "" })}
        confirmLabel={t("sessions.delete")}
        onCancel={() => setPendingDelete(null)}
        onConfirm={() => {
          if (pendingDelete) mutate.mutate({ kind: "delete", session: pendingDelete });
          setPendingDelete(null);
        }}
      />
    </main>
  );
}

function Disk({ stats }: { stats: DbStats }) {
  const { t } = useI18n();
  const used = diskUsed(stats);
  if (used === null) {
    // One sentence instead of 「磁盘 不可得 / 不可得」.
    return <span data-disk="unavailable">{diskUnavailableText(stats, t)}</span>;
  }
  return (
    <span>
      {t("sessions.diskLabel")} <Bytes value={used} /> /{" "}
      <Bytes value={stats.max_db_bytes} />
      {/* db/stats can answer `available: false` with no numbers: never print a raw `{days}`. */}
      {typeof stats.max_age_days === "number" ? <> · {t("sessions.diskKeep", { days: stats.max_age_days })}</> : null}
    </span>
  );
}

function SessionRow({
  session, checked, renaming, onToggle, onOpen, onRenameStart, onRename, onPin, onDelete,
}: {
  session: Session;
  checked: boolean;
  renaming: boolean;
  onToggle: () => void;
  onOpen: () => void;
  onRenameStart: () => void;
  onRename: (name: string) => void;
  onPin: () => void;
  onDelete: () => void;
}) {
  const { t } = useI18n();
  const exporter = useExport();
  const [draft, setDraft] = useState(session.name ?? "");
  const active = session.ended_ns === null && !session.purged;
  const duration = session.ended_ns ? formatDuration((session.ended_ns - session.started_ns) / 1_000_000) : active ? "…" : "–";
  const purged = Boolean(session.purged);

  return (
    <tr className={`border-b border-line/70 ${purged ? "text-ink-faint" : "hover:bg-paper-sunken"}`}>
      <td className="px-1">
        <input type="checkbox" checked={checked} disabled={purged} onChange={onToggle} aria-label={session.public_id} />
      </td>
      <td className="px-2 py-1">
        <StatusCell purged={purged} pinned={session.pinned} active={active} />
      </td>
      <td className="px-2 py-1">
        {purged ? (
          <span title={t("sessions.purgedTip")}>{t("sessions.purged")}</span>
        ) : renaming ? (
          <input
            autoFocus
            value={draft}
            onChange={(event) => setDraft(event.target.value)}
            onBlur={() => onRename(draft)}
            onKeyDown={(event) => {
              if (event.key === "Enter") onRename(draft);
              if (event.key === "Escape") onRename(session.name ?? "");
            }}
            className="rounded border border-line bg-paper px-1 py-0.5"
          />
        ) : (
          <button type="button" onClick={onOpen} className="text-left">
            <span className="block">{sessionTitle(session)}</span>
            <span className="font-mono text-[11px] text-ink-faint">{session.public_id}</span>
          </button>
        )}
      </td>
      <td className="px-2 py-1">{session.agent ?? "–"}</td>
      <td className="px-2 py-1">{t(`sessions.mode.${session.mode}`)}</td>
      <td className="px-2 py-1">{isWallTime(session.started_ns) ? <RelTime ns={session.started_ns} /> : <span className="text-ink-faint">–</span>}</td>
      <td className="px-2 py-1 tabular-nums">{duration}</td>
      <td className="px-2 py-1"><ListStat value={session.stats?.proc_count} /></td>
      <td className="px-2 py-1">
        {coverage(session, "net") === "not_collected" ? (
          // Same wording as the overview: not collected, not 0 and not 不可得.
          <NotCollected kind="net" />
        ) : session.stats ? (
          <>
            <Bytes value={session.stats.bytes_up} /> / <Bytes value={session.stats.bytes_down} />
          </>
        ) : (
          <ListStat value={undefined} />
        )}
      </td>
      <td className="px-2 py-1"><ListStat value={session.stats?.finding_count} unknownTip /></td>
      <td className="px-2 py-1">
        {session.stats?.gap_count ? <span className="text-gap">{session.stats.gap_count}</span> : <Count value={session.stats?.gap_count ?? 0} />}
      </td>
      <td className="px-2 py-1"><Bytes value={session.stats?.bytes} /></td>
      <td className="px-2 py-1 text-right">
        {purged ? null : (
          <span className="inline-flex gap-2 text-ink-faint">
            <button type="button" onClick={onRenameStart}>{t("sessions.rename")}</button>
            <button type="button" onClick={onPin}>{session.pinned ? t("sessions.unpin") : t("sessions.pin")}</button>
            <button type="button" onClick={onDelete}>{t("sessions.delete")}</button>
            <button
              type="button"
              disabled={exporter.pending !== null}
              onClick={() => void exporter.run(session.public_id, "jsonl")}
            >
              {t("session.export")}
            </button>
            {exporter.error ? <span role="alert" className="text-gap">{exporter.error}</span> : null}
            {exporter.notice ? <span role="status" className="text-ink-soft">{exporter.notice}</span> : null}
          </span>
        )}
      </td>
    </tr>
  );
}

/**
 * Status as text, not only a glyph: 「● 录制中」「○ 已停止」. A pinned session
 * keeps its recording state and adds the pin.
 */
function StatusCell({ purged, pinned, active }: { purged: boolean; pinned: boolean; active: boolean }) {
  const { t } = useI18n();
  if (purged) return <span className="whitespace-nowrap text-ink-faint" title={t("sessions.purgedTip")}>◌ {t("sessions.purged")}</span>;
  const label = active ? t("session.recording") : t("session.stopped");
  return (
    <span className={`whitespace-nowrap ${active ? "text-accent" : "text-ink-faint"}`} title={pinned ? `${label} · ${t("sessions.pinned")}` : label}>
      {active ? "●" : "○"} {label}
      {pinned ? <span aria-label={t("sessions.pinned")}> 📌</span> : null}
    </span>
  );
}

/**
 * A count the list endpoint does not return. The overview has it; saying
 * 「不可得」 here contradicted the number there, so the cell points to it.
 */
function ListStat({ value, unknownTip = false }: { value: number | null | undefined; unknownTip?: boolean }) {
  const { t } = useI18n();
  if (value === undefined || (unknownTip && value === null)) {
    return <span className="text-ink-faint" title={t("sessions.statInOverview")}>–</span>;
  }
  return <Count value={value} />;
}
