import { useParams } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { api } from "@/api/client";
import type { FlowGroup, NetFlow } from "@/api/types";
import { Bytes } from "@/components/Bytes";
import { Count } from "@/components/Count";
import { DetailPanel, type DetailRecord } from "@/components/DetailPanel/DetailPanel";
import { EvidenceBadge } from "@/components/EvidenceBadge";
import { ProcLabel } from "@/components/ProcLabel";
import { EmptyNote, ErrorNote, Loading } from "@/components/QueryState";
import { useI18n } from "@/lib/i18n";
import { composedFilter, useSessionQuery } from "@/lib/session-query";
import { TrafficChart } from "./TrafficChart";
import { fetchHttp, groupByFlow, HTTP_PAGE_LIMIT, type HttpPage, type HttpRow } from "./http";
import { FlowMarks, HttpTable } from "./HttpRows";
import { fill, useNetStrings } from "./strings";

type GroupBy = "domain" | "proc" | "ip" | "port";

const QUICK: { key: string; expr: string }[] = [
  { key: "direct", expr: "direct:true" },
  { key: "non443", expr: "port!=443" },
  { key: "noDomain", expr: "not domain:*" },
  { key: "bigUpload", expr: "bytes_up>1MB" },
];

export function NetworkPage() {
  const { t } = useI18n();
  const { sid } = useParams({ strict: false }) as { sid: string };
  const { query, patch } = useSessionQuery();
  const [groupBy, setGroupBy] = useState<GroupBy>("domain");
  const [direction, setDirection] = useState<"up" | "down">("up");
  const [openFlow, setOpenFlow] = useState<Set<string>>(new Set());
  const [openHttp, setOpenHttp] = useState<Set<number>>(new Set());
  const [selected, setSelected] = useState<NetFlow | null>(null);
  const filter = composedFilter(query);
  const s = useNetStrings();

  const flows = useQuery({
    queryKey: ["flows", sid, filter, groupBy],
    queryFn: () => api.flows(sid, { filter, group_by: groupBy, sort: "total" }),
  });
  const traffic = useQuery({
    queryKey: ["traffic", sid, filter, query.from, query.to, groupBy],
    queryFn: () => api.traffic(sid, { filter, group_by: groupBy === "domain" ? "domain" : "proc", from: query.from || undefined, to: query.to || undefined }),
  });

  // Third layer: loaded once any connection's HTTP row is opened.
  const http = useQuery({
    queryKey: ["http", sid],
    queryFn: () => fetchHttp(sid, ""),
    enabled: openHttp.size > 0,
  });
  const httpIndex = http.data ? groupByFlow(http.data.http) : null;

  const toggleQuick = (expr: string) => {
    const parts = query.f.split(/\s+/u).filter(Boolean);
    patch({ f: (parts.includes(expr) ? parts.filter((part) => part !== expr) : [...parts, expr]).join(" ") });
  };
  const toggle = (set: Set<string>, value: string, update: (next: Set<string>) => void) => {
    const next = new Set(set);
    if (next.has(value)) next.delete(value);
    else next.add(value);
    update(next);
  };

  return (
    <div className="flex h-full">
      <div className="min-w-0 flex-1 overflow-auto">
        <div className="flex items-center gap-2 px-3 pt-2 text-xs">
          <span className="text-ink-faint">{t("net.chart")}</span>
          {(["up", "down"] as const).map((item) => (
            <button key={item} type="button" aria-pressed={direction === item} onClick={() => setDirection(item)} className={`rounded border px-1.5 py-0.5 ${direction === item ? "border-ink" : "border-line text-ink-faint"}`}>
              {t(item === "up" ? "net.chartUp" : "net.chartDown")}
            </button>
          ))}
          {traffic.data?.approximate ? <EvidenceBadge level="S" /> : null}
        </div>
        {traffic.data ? <TrafficChart series={traffic.data} direction={direction} label={t("net.chart")} /> : null}

        <div className="flex flex-wrap items-center gap-2 border-y border-line px-3 py-1.5 text-[11px]">
          <span className="text-ink-faint">{t("net.col.target")}</span>
          {(["domain", "proc", "ip", "port"] as const).map((item) => (
            <label key={item} className="flex items-center gap-1">
              <input type="radio" name="group" checked={groupBy === item} onChange={() => setGroupBy(item)} />
              {t(`net.group.${item}`)}
            </label>
          ))}
          <span className="mx-1 text-ink-faint">|</span>
          {QUICK.map((item) => (
            <button key={item.key} type="button" title={item.key === "direct" ? s.quickDirectTip : undefined} aria-pressed={query.f.includes(item.expr)} onClick={() => toggleQuick(item.expr)} className={`rounded border px-1.5 py-0.5 ${query.f.includes(item.expr) ? "border-ink" : "border-line text-ink-faint"}`}>
              {t(`net.quick.${item.key}`)}
            </button>
          ))}
          <abbr title={t("net.basis")} className="ml-auto cursor-help text-ink-faint no-underline">ⓘ</abbr>
        </div>
        <p className="px-3 py-1 text-[11px] text-ink-faint">{t("net.noPtr")}</p>
        {http.data && http.data.http.length >= HTTP_PAGE_LIMIT ? (
          <p className="px-3 py-1 text-[11px] text-ink-faint">{fill(s.httpTruncated, { count: HTTP_PAGE_LIMIT })}</p>
        ) : null}
        {httpIndex && httpIndex.unlinked > 0 ? (
          <p className="px-3 py-1 text-[11px] text-ink-faint">{fill(s.httpUnlinked, { count: httpIndex.unlinked })}</p>
        ) : null}

        {flows.isLoading ? <Loading /> : null}
        {flows.isError ? <ErrorNote message={flows.error instanceof Error ? flows.error.message : ""} onRetry={() => void flows.refetch()} /> : null}
        {flows.data && flows.data.groups.length === 0 ? <EmptyNote>{t("net.empty")}</EmptyNote> : null}

        <table className="w-full border-collapse text-xs">
          <thead className="text-left text-ink-faint">
            <tr>
              {(["target", "up", "down", "connections", "domain"] as const).map((col) => (
                <th key={col} className="px-3 py-1 font-normal">{t(`net.col.${col}`)}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {flows.data?.groups.map((group) => (
              <GroupRows
                key={group.key}
                group={group}
                open={openFlow.has(group.key)}
                openHttp={openHttp}
                http={{ page: http.data, rows: httpIndex?.byFlow, loading: http.isLoading, error: http.isError ? (http.error instanceof Error ? http.error.message : "") : null, retry: () => void http.refetch() }}
                onToggle={() => toggle(openFlow, group.key, setOpenFlow)}
                onToggleHttp={(id) => {
                  const next = new Set(openHttp);
                  if (next.has(id)) next.delete(id);
                  else next.add(id);
                  setOpenHttp(next);
                }}
                onSelect={setSelected}
              />
            ))}
          </tbody>
        </table>
      </div>
      {selected ? <DetailPanel record={toRecord(selected)} patch={patch} onClose={() => setSelected(null)} /> : null}
    </div>
  );
}

export interface HttpState {
  page: HttpPage | undefined;
  rows: Map<number, HttpRow[]> | undefined;
  loading: boolean;
  error: string | null;
  retry: () => void;
}

export function GroupRows({
  group, open, openHttp, http, onToggle, onToggleHttp, onSelect,
}: {
  group: FlowGroup;
  open: boolean;
  openHttp: Set<number>;
  http: HttpState;
  onToggle: () => void;
  onToggleHttp: (id: number) => void;
  onSelect: (flow: NetFlow) => void;
}) {
  return (
    <>
      <tr className="border-b border-line/60">
        <td className="px-3 py-1">
          <button type="button" onClick={onToggle} className="text-left">
            <span className="mr-1 text-ink-faint">{open ? "▾" : "▸"}</span>
            <span className="font-mono">{group.label}</span>
            {group.alt_count > 0 ? <span className="ml-1 text-ink-faint">(+{group.alt_count})</span> : null}
          </button>
          {group.inferred ? <span className="ml-1"><EvidenceBadge level="I" /></span> : null}
          {group.direct ? <FlowMarks flow={{ direct: true, via_proxy: false, proto: "tcp", remote_port: 0, na_reason: null }} /> : null}
        </td>
        <td className="px-3 py-1"><Bytes value={group.bytes_up} /></td>
        <td className="px-3 py-1"><Bytes value={group.bytes_down} /></td>
        <td className="px-3 py-1"><Count value={group.connections} /></td>
        <td className="px-3 py-1">
          <span className="mr-1 text-ink-faint">{group.domain_source ?? "–"}</span>
          <EvidenceBadge level={group.evidence} />
        </td>
      </tr>
      {open
        ? group.flows.map((flow) => (
            <FlowRows key={flow.id} flow={flow} http={http} httpOpen={openHttp.has(flow.id)} onToggleHttp={() => onToggleHttp(flow.id)} onSelect={() => onSelect(flow)} />
          ))
        : null}
    </>
  );
}

export function FlowRows({ flow, http, httpOpen, onToggleHttp, onSelect }: { flow: NetFlow; http: HttpState; httpOpen: boolean; onToggleHttp: () => void; onSelect: () => void }) {
  const { t } = useI18n();
  const s = useNetStrings();
  return (
    <>
      <tr className="border-b border-line/40 text-ink-soft">
        <td className="py-1 pl-8 pr-3">
          <button type="button" onClick={onSelect} className="text-left font-mono">
            <ProcLabel pid={flow.proc?.pid} exe={flow.proc?.exe_name} />{" "}
            {flow.local_ip}:{flow.local_port} → {flow.remote_ip}:{flow.remote_port}
          </button>
          <FlowMarks flow={flow} />
          <button type="button" aria-expanded={httpOpen} onClick={onToggleHttp} className="ml-2 text-ink-faint">{httpOpen ? "▾" : "▸"} HTTP</button>
        </td>
        <td className="px-3 py-1"><Bytes value={flow.bytes_up} naReason={flow.field_evidence?.bytes_up?.na_reason ?? flow.na_reason} /></td>
        <td className="px-3 py-1"><Bytes value={flow.bytes_down} naReason={flow.field_evidence?.bytes_down?.na_reason ?? flow.na_reason} /></td>
        <td className="px-3 py-1">{flow.proto}</td>
        <td className="px-3 py-1">
          {flow.domain_alts && flow.domain_alts.length > 0 ? <span className="mr-1 text-ink-faint">{t("net.alts", { count: flow.domain_alts.length })}</span> : null}
          <EvidenceBadge level={flow.evidence} source={flow.source} naReason={flow.na_reason} />
        </td>
      </tr>
      {httpOpen ? (
        <tr className="border-b border-line/40">
          <td colSpan={5} className="py-1 pl-14 pr-3 text-ink-faint">
            {flow.direct ? (
              <span>{s.markDirectTip}</span>
            ) : http.loading ? (
              <span>{s.httpLoading}</span>
            ) : http.error !== null ? (
              <ErrorNote message={http.error} onRetry={http.retry} />
            ) : http.page?.reason === "no_proxy" ? (
              <span>{t("net.httpPlaceholder")}</span>
            ) : http.page ? (
              <HttpTable rows={http.rows?.get(flow.id) ?? []} />
            ) : null}
          </td>
        </tr>
      ) : null}
    </>
  );
}

function toRecord(flow: NetFlow): DetailRecord {
  return {
    id: flow.id,
    table: "net_flows",
    tsNs: flow.start_ns,
    evidence: flow.evidence,
    naReason: flow.na_reason,
    source: flow.source,
    procUid: flow.proc_uid,
    fieldEvidence: flow.field_evidence,
    fields: {
      proto: flow.proto,
      local: `${flow.local_ip}:${flow.local_port}`,
      remote: `${flow.remote_ip}:${flow.remote_port}`,
      domain: flow.domain,
      domain_source: flow.domain_source,
      domain_alts: flow.domain_alts,
      bytes_up: flow.bytes_up,
      bytes_down: flow.bytes_down,
      direct: flow.direct,
      via_proxy: flow.via_proxy,
    },
  };
}
