import { useNavigate } from "@tanstack/react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { memo, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "@/api/client";
import type { DoctorCapability, SystemProcess, SystemProcessTable } from "@/api/types";
import { describeError } from "@/api/errors";
import { EvidenceBadge } from "@/components/EvidenceBadge";
import { ErrorNote } from "@/components/QueryState";
import { kindInSentence, kindLabel } from "@/lib/capabilities";
import { useI18n } from "@/lib/i18n";

const AGENTS = ["auto", "claude", "codex", "cursor", "other"];

export function NewSessionPage() {
  const { t } = useI18n();
  const navigate = useNavigate();
  const client = useQueryClient();
  const doctor = useQuery({ queryKey: ["doctor"], queryFn: () => api.doctor() });
  const [error, setError] = useState<unknown>(null);
  const [pending, setPending] = useState(false);

  // Stable, so the launch form does not re-render on every page update.
  const start = useCallback(async (body: Parameters<typeof api.createSession>[0]) => {
    setPending(true);
    setError(null);
    try {
      const session = await api.createSession(body);
      if (!session.public_id) throw new Error(t("common.error"));
      // The list must show the new, real session next to the others.
      await client.invalidateQueries({ queryKey: ["sessions"] });
      await navigate({ to: "/s/$sid", params: { sid: session.public_id }, search: {} });
    } catch (caught) {
      // ErrorNote words daemon codes (`program_not_found`, …) in plain text
      // instead of printing the daemon's English message.
      setError(caught ?? new Error(t("common.error")));
    } finally {
      setPending(false);
    }
  }, [client, navigate, t]);

  // The error is about the last attempt. Editing the command or directory, or
  // picking a process to attach, is a new attempt, so the old message goes.
  const clearError = useCallback(() => setError(null), []);

  return (
    <main className="px-4 py-3">
      <h1 className="text-base font-semibold">{t("new.title")}</h1>
      <div className="mt-3 grid gap-4 lg:grid-cols-2">
        <LaunchForm pending={pending} onStart={start} onEdit={clearError} />
        <AttachForm pending={pending} onStart={start} onPick={clearError} />
      </div>
      {error ? <ErrorNote error={error} /> : null}
      <section className="mt-4">
        <h2 className="text-sm font-medium">{t("new.capabilities")}</h2>
        {doctor.isError ? <ErrorNote error={doctor.error} onRetry={() => void doctor.refetch()} /> : null}
        {doctor.isLoading ? <p className="mt-2 text-xs text-ink-faint">{t("common.loading")}</p> : null}
        {doctor.data && doctor.data.capabilities.length === 0 ? (
          // The daemon may answer without probing collectors. That is "unknown",
          // not "nothing available", and the forms above still work.
          <p className="mt-2 flex items-center gap-1 text-xs text-ink-faint" data-capabilities="unknown">
            <EvidenceBadge level="NA" /> {doctor.data.probed ? t("new.capNone") : t("new.capNotProbed")}
            {doctor.data.privileged_note ? <span title={doctor.data.privileged_note}>ⓘ</span> : null}
          </p>
        ) : null}
        {doctor.data && doctor.data.capabilities.length > 0 ? <CapabilityList capabilities={doctor.data.capabilities} /> : null}
      </section>
    </main>
  );
}

/**
 * Collected kinds as chips with their evidence; the rest in one plain
 * sentence per reason, worded like the Settings page (「没采」). A kind whose
 * collector does not run in this mode (`collector_unavailable`) says exactly
 * that, not 「不可得：当前运行模式不支持采集此信息」. List separator and colon
 * come from the locale, never a hard-coded full-width 「：」.
 */
export function CapabilityList({ capabilities }: { capabilities: DoctorCapability[] }) {
  const { t } = useI18n();
  const collected = capabilities.filter((c) => c.available && c.evidence);
  const missing = new Map<string, string[]>();
  for (const capability of capabilities) {
    if (capability.available && capability.evidence) continue;
    const reason =
      !capability.na_reason || capability.na_reason === "collector_unavailable"
        ? t("new.capReasonNotRunning")
        : t(`na.${capability.na_reason}`);
    missing.set(reason, [...(missing.get(reason) ?? []), kindInSentence(t, capability.kind)]);
  }
  return (
    <div className="mt-2 text-xs" data-capability-list="">
      {collected.length > 0 ? (
        <ul className="flex flex-wrap gap-2">
          {collected.map((capability) => (
            <li key={capability.kind} className="flex items-center gap-1 rounded border border-line px-2 py-1">
              <span>{kindLabel(t, capability.kind)}</span>
              {capability.evidence ? <EvidenceBadge level={capability.evidence} /> : null}
            </li>
          ))}
        </ul>
      ) : null}
      {[...missing.entries()].map(([reason, kinds]) => (
        <p key={reason} className="mt-1 text-ink-faint" data-not-collected="">
          {t("new.capNotCollected", { kinds: kinds.join(t("common.listSep")), reason })}
        </p>
      ))}
    </div>
  );
}

/**
 * The command and directory boxes are uncontrolled: React never writes their
 * value after the first render. As controlled inputs, any re-render that ran
 * between a keystroke reaching the field and React's change handler (the
 * desktop window re-renders on channel replies; an input method's pending
 * text is not yet an input event) wrote the old state back into the field,
 * so typing `sleep 60` in the app left `leep 60`. The text is read on submit.
 */
export const LaunchForm = memo(function LaunchForm({
  pending,
  onStart,
  onEdit,
}: {
  pending: boolean;
  onStart: (body: Parameters<typeof api.createSession>[0]) => void;
  /** Called when the command or directory is edited. The inputs stay uncontrolled. */
  onEdit?: () => void;
}) {
  const { t } = useI18n();
  const commandRef = useRef<HTMLInputElement>(null);
  const cwdRef = useRef<HTMLInputElement>(null);
  const [agent, setAgent] = useState("auto");
  const [proxy, setProxy] = useState(false);
  const [follow, setFollow] = useState(true);
  const [selfReport, setSelfReport] = useState(false);

  return (
    <form
      className="rounded border border-line p-3"
      onSubmit={(event) => {
        event.preventDefault();
        const argv = splitCommand(commandRef.current?.value ?? "");
        const cwd = (cwdRef.current?.value ?? "").trim();
        if (argv.length === 0) return;
        onStart({
          mode: "launch",
          argv,
          cwd: cwd || undefined,
          agent: agent === "auto" ? undefined : agent,
          proxy,
          follow_children: follow,
          self_report: selfReport ? "auto" : "off",
        });
      }}
    >
      <h2 className="text-sm font-medium">{t("new.launch")}</h2>
      <label className="mt-3 block text-xs">
        {t("new.command")}
        <input
          ref={commandRef}
          required
          name="command"
          defaultValue=""
          autoComplete="off"
          autoCapitalize="off"
          autoCorrect="off"
          spellCheck={false}
          onInput={onEdit}
          className="mt-1 w-full rounded border border-line bg-paper px-2 py-1 font-mono"
        />
      </label>
      <label className="mt-2 block text-xs">
        {t("new.cwd")}
        <input
          ref={cwdRef}
          name="cwd"
          defaultValue=""
          autoComplete="off"
          autoCapitalize="off"
          autoCorrect="off"
          spellCheck={false}
          onInput={onEdit}
          className="mt-1 w-full rounded border border-line bg-paper px-2 py-1 font-mono"
        />
      </label>
      <label className="mt-2 block text-xs">
        {t("new.agent")}
        <select value={agent} onChange={(event) => setAgent(event.target.value)} className="mt-1 w-full rounded border border-line bg-paper px-2 py-1">
          {AGENTS.map((item) => (
            <option key={item} value={item}>{item === "auto" ? t("new.agentAuto") : item}</option>
          ))}
        </select>
      </label>
      <label className="mt-3 flex items-center gap-2 text-xs">
        <input type="checkbox" checked={proxy} onChange={(event) => setProxy(event.target.checked)} />
        {t("new.proxy")}
        <abbr title={t("new.proxyTip")} className="cursor-help text-ink-faint no-underline">ⓘ</abbr>
      </label>
      <div className="mt-2 flex flex-wrap gap-3 text-xs">
        <label className="flex items-center gap-1">
          <input type="checkbox" checked={follow} onChange={(event) => setFollow(event.target.checked)} />
          {t("new.follow")}
        </label>
        <label className="flex items-center gap-1">
          <input type="checkbox" checked={selfReport} onChange={(event) => setSelfReport(event.target.checked)} />
          {t("new.selfReport")}
        </label>
      </div>
      <p className="mt-3 text-[11px] text-ink-faint">{t("new.noTty")}</p>
      <button type="submit" disabled={pending} className="mt-3 rounded bg-ink px-3 py-1 text-xs text-paper disabled:opacity-50">
        {t("new.start")}
      </button>
    </form>
  );
});

function AttachForm({
  pending,
  onStart,
  onPick,
}: {
  pending: boolean;
  onStart: (body: Parameters<typeof api.createSession>[0]) => void;
  /** Called when a process is picked. A failed launch must not stay on screen. */
  onPick?: () => void;
}) {
  const { t } = useI18n();
  const [q, setQ] = useState("");
  // Off by default: the picker must show the program the user is looking
  // for (real-window #144: searching `sleep` found nothing).
  const [agentsOnly, setAgentsOnly] = useState(false);
  const [includeChildren, setIncludeChildren] = useState(true);
  const [selected, setSelected] = useState<number | null>(null);
  const [cursor, setCursor] = useState(0);

  const processes = useQuery({
    queryKey: ["system-processes", q, agentsOnly],
    queryFn: () => api.systemProcesses({ q, agents_only: agentsOnly }),
    refetchInterval: 2_000,
  });

  const flat = useMemo(() => flatten(processes.data?.roots ?? [], 0), [processes.data]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null;
      if (target && (target.tagName === "INPUT" || target.tagName === "TEXTAREA")) return;
      if (event.key === "j" || event.key === "ArrowDown") {
        event.preventDefault();
        setCursor((current) => Math.min(flat.length - 1, current + 1));
      } else if (event.key === "k" || event.key === "ArrowUp") {
        event.preventDefault();
        setCursor((current) => Math.max(0, current - 1));
      } else if (event.key === "Enter" && flat[cursor]) {
        setSelected(flat[cursor].pid);
        onPick?.();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [flat, cursor, onPick]);

  return (
    <form
      className="rounded border border-line p-3"
      onSubmit={(event) => {
        event.preventDefault();
        if (selected === null) return;
        onStart({ mode: "attach", pid: selected, include_existing_children: includeChildren, follow_children: true });
      }}
    >
      <h2 className="text-sm font-medium">{t("new.attach")}</h2>
      <div className="mt-3 flex items-center gap-2 text-xs">
        <input value={q} onChange={(event) => setQ(event.target.value)} placeholder={t("new.searchProc")} className="flex-1 rounded border border-line bg-paper px-2 py-1" />
        <label className="flex items-center gap-1">
          <input type="checkbox" checked={agentsOnly} onChange={(event) => setAgentsOnly(event.target.checked)} />
          {t("new.agentsOnly")}
        </label>
      </div>
      <ul className="mt-2 max-h-64 overflow-auto rounded border border-line text-xs">
        {flat.map((row, index) => (
          <li key={row.pid}>
            <button
              type="button"
              onClick={() => {
                setSelected(row.pid);
                onPick?.();
              }}
              className={`flex w-full items-center gap-2 px-2 py-1 text-left ${
                selected === row.pid ? "bg-ink text-paper" : index === cursor ? "bg-paper-sunken" : ""
              }`}
              style={{ paddingLeft: `${8 + row.depth * 14}px` }}
            >
              <span className="font-mono" title={row.argv ? row.argv.join(" ") : undefined}>{row.name}</span>
              <span className="text-ink-faint">({row.pid})</span>
              {row.agent ? <span>{row.agent}</span> : null}
            </button>
          </li>
        ))}
        {flat.length === 0 ? (
          <li className="px-2 py-2 text-ink-faint">
            <PickerStatus data={processes.data} error={processes.error} loading={processes.isPending} agentsOnly={agentsOnly} />
          </li>
        ) : null}
      </ul>
      {processes.data?.available && processes.data.scope === "own" ? (
        <p className="mt-1 text-[11px] text-ink-faint">{t("new.procScopeOwn")}</p>
      ) : null}
      <label className="mt-2 flex items-center gap-1 text-xs">
        <input type="checkbox" checked={includeChildren} onChange={(event) => setIncludeChildren(event.target.checked)} />
        {t("new.includeChildren")}
      </label>
      <button type="submit" disabled={pending || selected === null} className="mt-3 rounded bg-ink px-3 py-1 text-xs text-paper disabled:opacity-50">
        {t("new.attachButton")}
      </button>
    </form>
  );
}

/**
 * What an empty picker says. A table the service could not read (or a failed
 * request) is 「没采」 with the reason, never 「没有记录」: an empty list must
 * not read as "nothing is running".
 */
export function PickerStatus({
  data,
  error,
  loading,
  agentsOnly,
}: {
  data: SystemProcessTable | undefined;
  error: unknown;
  loading: boolean;
  agentsOnly: boolean;
}) {
  const { t } = useI18n();
  if (error) return <>{t("new.procNotCollected", { reason: describeError(error, t) })}</>;
  if (!data) return <>{loading ? t("common.loading") : t("new.procNotCollected", { reason: t("new.procReasonUnknown") })}</>;
  // `reason` is a code; the daemon's English is only in `detail`, never shown here.
  if (!data.available) return <>{t("new.procNotCollected", { reason: procReason(data.reason, t) })}</>;
  return <>{agentsOnly ? t("new.procNoAgent") : t("new.procNoMatch")}</>;
}

const PROC_REASONS: Record<string, string> = { no_process_table: "new.procReason.noProcessTable" };

function procReason(code: string | null | undefined, t: (key: string) => string): string {
  const key = code ? PROC_REASONS[code] : undefined;
  return t(key ?? "new.procReasonUnknown");
}

interface FlatProc extends SystemProcess {
  depth: number;
}

function flatten(nodes: SystemProcess[], depth: number): FlatProc[] {
  const rows: FlatProc[] = [];
  for (const node of nodes) {
    rows.push({ ...node, depth });
    rows.push(...flatten(node.children, depth + 1));
  }
  return rows;
}

function splitCommand(input: string): string[] {
  const parts: string[] = [];
  const pattern = /"([^"]*)"|'([^']*)'|(\S+)/g;
  for (const match of input.matchAll(pattern)) parts.push(match[1] ?? match[2] ?? match[0]);
  return parts;
}
