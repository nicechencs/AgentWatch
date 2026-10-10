import { useNavigate } from "@tanstack/react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { api } from "@/api/client";
import type { SystemProcess } from "@/api/types";
import { EvidenceBadge } from "@/components/EvidenceBadge";
import { ErrorNote } from "@/components/QueryState";
import { kindLabel } from "@/lib/capabilities";
import { useI18n } from "@/lib/i18n";

const AGENTS = ["auto", "claude", "codex", "cursor", "other"];

export function NewSessionPage() {
  const { t } = useI18n();
  const navigate = useNavigate();
  const client = useQueryClient();
  const doctor = useQuery({ queryKey: ["doctor"], queryFn: () => api.doctor() });
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  const start = async (body: Parameters<typeof api.createSession>[0]) => {
    setPending(true);
    setError(null);
    try {
      const session = await api.createSession(body);
      if (!session.public_id) throw new Error(t("common.error"));
      // The list must show the new, real session next to the others.
      await client.invalidateQueries({ queryKey: ["sessions"] });
      await navigate({ to: "/s/$sid", params: { sid: session.public_id }, search: {} });
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : t("common.error"));
    } finally {
      setPending(false);
    }
  };

  return (
    <main className="px-4 py-3">
      <h1 className="text-base font-semibold">{t("new.title")}</h1>
      <div className="mt-3 grid gap-4 lg:grid-cols-2">
        <LaunchForm pending={pending} onStart={start} />
        <AttachForm pending={pending} onStart={start} />
      </div>
      {error ? <ErrorNote message={error} /> : null}
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
        {doctor.data && doctor.data.capabilities.length > 0 ? (
          <ul className="mt-2 flex flex-wrap gap-2 text-xs">
            {doctor.data.capabilities.map((capability) => (
              <li key={capability.kind} className="flex items-center gap-1 rounded border border-line px-2 py-1">
                <span>{kindLabel(t, capability.kind)}</span>
                {capability.available && capability.evidence ? (
                  <EvidenceBadge level={capability.evidence} />
                ) : (
                  <span className="text-ink-faint">
                    {t("new.capMissing")}
                    {capability.na_reason ? `：${t(`na.${capability.na_reason}`)}` : capability.note ? `：${capability.note}` : ""}
                  </span>
                )}
              </li>
            ))}
          </ul>
        ) : null}
      </section>
    </main>
  );
}

function LaunchForm({ pending, onStart }: { pending: boolean; onStart: (body: Parameters<typeof api.createSession>[0]) => void }) {
  const { t } = useI18n();
  const [command, setCommand] = useState("");
  const [cwd, setCwd] = useState("");
  const [agent, setAgent] = useState("auto");
  const [proxy, setProxy] = useState(false);
  const [follow, setFollow] = useState(true);
  const [selfReport, setSelfReport] = useState(false);

  return (
    <form
      className="rounded border border-line p-3"
      onSubmit={(event) => {
        event.preventDefault();
        const argv = splitCommand(command);
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
        <input required value={command} onChange={(event) => setCommand(event.target.value)} className="mt-1 w-full rounded border border-line bg-paper px-2 py-1 font-mono" />
      </label>
      <label className="mt-2 block text-xs">
        {t("new.cwd")}
        <input value={cwd} onChange={(event) => setCwd(event.target.value)} className="mt-1 w-full rounded border border-line bg-paper px-2 py-1 font-mono" />
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
}

function AttachForm({ pending, onStart }: { pending: boolean; onStart: (body: Parameters<typeof api.createSession>[0]) => void }) {
  const { t } = useI18n();
  const [q, setQ] = useState("");
  const [agentsOnly, setAgentsOnly] = useState(true);
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
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [flat, cursor]);

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
              onClick={() => setSelected(row.pid)}
              className={`flex w-full items-center gap-2 px-2 py-1 text-left ${
                selected === row.pid ? "bg-ink text-paper" : index === cursor ? "bg-paper-sunken" : ""
              }`}
              style={{ paddingLeft: `${8 + row.depth * 14}px` }}
            >
              <span className="font-mono">{row.name}</span>
              <span className="text-ink-faint">({row.pid})</span>
              {row.agent ? <span>{row.agent}</span> : null}
            </button>
          </li>
        ))}
        {flat.length === 0 ? <li className="px-2 py-2 text-ink-faint">{t("common.empty")}</li> : null}
      </ul>
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
