import { useParams } from "@tanstack/react-router";
import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useCallback, useMemo, useRef, useState } from "react";
import { api } from "@/api/client";
import type { DirNode, FileAccess, NaReason } from "@/api/types";
import { Bytes } from "@/components/Bytes";
import { Count } from "@/components/Count";
import { DetailPanel, type DetailRecord } from "@/components/DetailPanel/DetailPanel";
import { EvidenceBadge } from "@/components/EvidenceBadge";
import { ProcLabel } from "@/components/ProcLabel";
import { RelTime } from "@/components/RelTime";
import { EmptyNote, ErrorNote } from "@/components/QueryState";
import { useListKeys } from "@/components/useListKeys";
import { useI18n } from "@/lib/i18n";
import { composedFilter, useSessionQuery } from "@/lib/session-query";

const QUICK: { key: string; expr: string }[] = [
  { key: "sensitive", expr: "tag:sensitive" },
  { key: "write", expr: "access:write,read_write" },
  { key: "delete", expr: "op:delete" },
  { key: "outside", expr: "not dir:." },
  { key: "failed", expr: "op:access result!=0" },
];

const PAGE = 500;

export function FilesPage() {
  const { t } = useI18n();
  const { sid } = useParams({ strict: false }) as { sid: string };
  const { query, patch } = useSessionQuery();
  const [view, setView] = useState<"list" | "tree">("list");
  const [cursor, setCursor] = useState(0);
  const [open, setOpen] = useState(false);
  const scroller = useRef<HTMLDivElement>(null);
  const filter = composedFilter(query);

  const pages = useInfiniteQuery({
    queryKey: ["files", sid, filter, query.from, query.to],
    initialPageParam: "",
    queryFn: ({ pageParam }) =>
      api.files(sid, { filter, from: query.from || undefined, to: query.to || undefined, cursor: pageParam || undefined, limit: PAGE }),
    getNextPageParam: (page) => page.next_cursor,
    enabled: view === "list",
  });
  const tree = useQuery({
    queryKey: ["file-tree", sid, filter],
    queryFn: () => api.fileTree(sid, { filter }),
    enabled: view === "tree",
  });

  const rows = useMemo(() => (pages.data?.pages ?? []).flatMap((page) => page.items).slice(0, 2000), [pages.data]);
  const virtualizer = useVirtualizer({ count: rows.length, getScrollElement: () => scroller.current, estimateSize: () => 30, overscan: 15 });

  const onOpen = useCallback(() => setOpen(true), []);
  const onClose = useCallback(() => setOpen(false), []);
  useListKeys({ count: rows.length, cursor, setCursor, onOpen, onClose, enabled: view === "list" });

  const toggleQuick = (expr: string) => {
    const parts = query.f.split(/\s+/u).filter(Boolean);
    const next = parts.includes(expr) ? parts.filter((part) => part !== expr) : [...parts, expr];
    patch({ f: next.join(" ") });
  };

  const record = rows[cursor] ? toRecord(rows[cursor]) : null;

  return (
    <div className="flex h-full">
      <div className="flex min-w-0 flex-1 flex-col">
        <div className="flex flex-wrap items-center gap-1 border-b border-line px-3 py-1.5 text-[11px]">
          <div className="mr-2 flex overflow-hidden rounded border border-line">
            {(["list", "tree"] as const).map((item) => (
              <button key={item} type="button" onClick={() => setView(item)} className={`px-2 py-0.5 ${view === item ? "bg-ink text-paper" : ""}`}>
                {t(`files.view.${item}`)}
              </button>
            ))}
          </div>
          {QUICK.map((item) => (
            <button
              key={item.key}
              type="button"
              aria-pressed={query.f.split(/\s+/u).includes(item.expr)}
              onClick={() => toggleQuick(item.expr)}
              className={`rounded border px-1.5 py-0.5 ${query.f.includes(item.expr) ? "border-ink" : "border-line text-ink-faint"}`}
            >
              {t(`files.quick.${item.key}`)}
            </button>
          ))}
        </div>

        {view === "list" ? (
          <>
            {pages.isError ? <ErrorNote message={pages.error instanceof Error ? pages.error.message : ""} onRetry={() => void pages.refetch()} /> : null}
            {!pages.isLoading && rows.length === 0 ? <EmptyNote>{t("files.empty")}</EmptyNote> : null}
            <div ref={scroller} className="scroll-thin min-h-0 flex-1 overflow-auto">
              <table className="w-full border-collapse text-xs">
                <thead className="sticky top-0 bg-paper text-left text-ink-faint">
                  <tr>
                    {(["time", "proc", "op", "path", "opens", "read", "write", "evidence", "sensitive"] as const).map((col) => (
                      <th key={col} className="px-2 py-1 font-normal">{t(`files.col.${col}`)}</th>
                    ))}
                  </tr>
                </thead>
              </table>
              <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
                {virtualizer.getVirtualItems().map((virtual) => (
                  <div key={virtual.key} style={{ position: "absolute", top: 0, left: 0, width: "100%", transform: `translateY(${virtual.start}px)` }}>
                    <FileRow item={rows[virtual.index]} active={virtual.index === cursor} onSelect={() => { setCursor(virtual.index); setOpen(true); }} />
                  </div>
                ))}
              </div>
            </div>
          </>
        ) : (
          <DirTree nodes={nest(tree.data?.roots ?? [])} />
        )}
      </div>
      {open && view === "list" ? <DetailPanel record={record} patch={patch} onClose={() => setOpen(false)} /> : null}
    </div>
  );
}

function FileRow({ item, active, onSelect }: { item: FileAccess; active: boolean; onSelect: () => void }) {
  const { t } = useI18n();
  const op = item.op === "access" ? (item.access ?? "access") : item.op;
  const readReason = fieldReason(item, "bytes_read") ?? item.na_reason;
  const writeReason = fieldReason(item, "bytes_written");
  return (
    <button type="button" onClick={onSelect} className={`grid w-full grid-cols-[8rem_8rem_4rem_1fr_4rem_6rem_6rem_5rem_6rem] items-baseline gap-1 px-2 py-1 text-left ${active ? "bg-paper-sunken" : "hover:bg-paper-sunken/60"}`}>
      <RelTime ns={item.first_ns} precise />
      <ProcLabel pid={item.proc?.pid} exe={item.proc?.exe_name} />
      <span>{t(`files.op.${op}`)}</span>
      <span className="truncate font-mono" title={item.path}>{item.path}{item.path_to ? ` → ${item.path_to}` : ""}</span>
      <Count value={item.opens} />
      <Bytes value={item.bytes_read} naReason={readReason} />
      <Bytes value={item.bytes_written} naReason={writeReason} />
      <EvidenceBadge level={item.evidence} source={item.source} naReason={item.na_reason} />
      <span className="text-sensitive">{item.sensitive_rule ? t("files.sensitiveHit", { rule: item.sensitive_rule }) : item.result ? t("files.failed") : ""}</span>
    </button>
  );
}

function fieldReason(item: FileAccess, field: string): NaReason | null {
  return item.field_evidence?.[field]?.na_reason ?? null;
}

function DirTree({ nodes }: { nodes: DirNode[] }) {
  const [open, setOpen] = useState<Set<string>>(new Set());
  return (
    <ul className="overflow-auto px-3 py-2 text-xs">
      {nodes.map((node) => (
        <DirRow key={node.path} node={node} depth={0} open={open} toggle={(path) => setOpen((current) => {
          const next = new Set(current);
          if (next.has(path)) next.delete(path);
          else next.add(path);
          return next;
        })} />
      ))}
    </ul>
  );
}

function DirRow({ node, depth, open, toggle }: { node: DirNode; depth: number; open: Set<string>; toggle: (path: string) => void }) {
  const expanded = open.has(node.path);
  const hasChildren = (node.children?.length ?? 0) > 0;
  return (
    <li>
      <button type="button" onClick={() => hasChildren && toggle(node.path)} className="flex w-full items-baseline gap-2 py-0.5 text-left" style={{ paddingLeft: depth * 14 }}>
        <span className="w-3 text-ink-faint">{hasChildren ? (expanded ? "▾" : "▸") : ""}</span>
        <span className="truncate font-mono">{node.path}</span>
        <span className="tabular-nums text-ink-faint">{node.count}</span>
        {node.writes > 0 ? <span className="text-ink-faint">({node.writes})</span> : null}
      </button>
      {expanded && node.children ? (
        <ul>
          {node.children.map((child) => (
            <DirRow key={child.path} node={child} depth={depth + 1} open={open} toggle={toggle} />
          ))}
        </ul>
      ) : null}
    </li>
  );
}

/** The dir endpoint returns a flat list; fold it into a tree by path prefix. */
function nest(flat: { path: string; count: number; writes: number }[]): DirNode[] {
  const roots: DirNode[] = [];
  const index = new Map<string, DirNode>();
  const sorted = [...flat].sort((a, b) => a.path.length - b.path.length);
  for (const entry of sorted) {
    const node: DirNode = { path: entry.path, count: entry.count, writes: entry.writes, children: [] };
    index.set(entry.path, node);
    const parentPath = entry.path.replace(/[/\\][^/\\]+$/u, "");
    const parent = parentPath !== entry.path ? index.get(parentPath) : undefined;
    if (parent) parent.children?.push(node);
    else roots.push(node);
  }
  return roots;
}

function toRecord(item: FileAccess): DetailRecord {
  return {
    id: item.id,
    table: "file_access",
    tsNs: item.first_ns,
    evidence: item.evidence,
    naReason: item.na_reason,
    source: item.source,
    procUid: item.proc_uid,
    fieldEvidence: item.field_evidence,
    fields: {
      op: item.op,
      path: item.path,
      path_to: item.path_to,
      access: item.access,
      opens: item.opens,
      bytes_read: item.bytes_read,
      bytes_written: item.bytes_written,
      result: item.result,
      sensitive_rule: item.sensitive_rule,
    },
  };
}
