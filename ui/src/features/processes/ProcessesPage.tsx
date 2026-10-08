import { useNavigate, useParams } from "@tanstack/react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api } from "@/api/client";
import type { ProcessNode } from "@/api/types";
import { Bytes } from "@/components/Bytes";
import { Count } from "@/components/Count";
import { EvidenceBadge } from "@/components/EvidenceBadge";
import { EmptyNote, ErrorNote, Loading } from "@/components/QueryState";
import { copyText, joinCommand } from "@/lib/format";
import { useI18n } from "@/lib/i18n";
import { useSessionQuery } from "@/lib/session-query";

interface MenuState {
  x: number;
  y: number;
  node: ProcessNode;
}

export function ProcessesPage() {
  const { t } = useI18n();
  const { sid } = useParams({ strict: false }) as { sid: string };
  const tree = useQuery({ queryKey: ["processes", sid], queryFn: () => api.processes(sid) });
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const [extra, setExtra] = useState<Record<string, ProcessNode[]>>({});
  const [menu, setMenu] = useState<MenuState | null>(null);
  const client = useQueryClient();

  if (tree.isLoading) return <Loading />;
  if (tree.isError || !tree.data) {
    return <ErrorNote message={tree.error instanceof Error ? tree.error.message : ""} onRetry={() => void tree.refetch()} />;
  }

  const rows = visible(tree.data.roots, collapsed, extra);
  const toggle = (node: ProcessNode) => {
    setCollapsed((current) => {
      const next = new Set(current);
      if (next.has(node.proc_uid)) next.delete(node.proc_uid);
      else next.add(node.proc_uid);
      return next;
    });
  };

  const loadChildren = async (node: ProcessNode) => {
    const result = await api.processChildren(sid, node.proc_uid);
    setExtra((current) => ({ ...current, [node.proc_uid]: result.children }));
    void client.invalidateQueries({ queryKey: ["processes", sid] });
  };

  return (
    <div className="h-full overflow-auto" onClick={() => setMenu(null)}>
      {rows.length === 0 ? <EmptyNote>{t("procs.empty")}</EmptyNote> : null}
      <table className="w-full border-collapse text-xs">
        <thead className="sticky top-0 bg-paper">
          <tr className="border-b border-line text-left text-ink-faint">
            <th className="px-3 py-1 font-normal">{t("procs.col.process")}</th>
            <th className="px-2 py-1 font-normal">{t("procs.col.files")}</th>
            <th className="px-2 py-1 font-normal">{t("procs.col.writeDelete")}</th>
            <th className="px-2 py-1 font-normal">{t("procs.col.traffic")}</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(({ node, folded }) => (
            <ProcessRow
              key={node.proc_uid}
              node={node}
              folded={folded}
              onToggle={() => toggle(node)}
              onLoad={() => void loadChildren(node)}
              onMenu={(event) => {
                event.preventDefault();
                setMenu({ x: event.clientX, y: event.clientY, node });
              }}
            />
          ))}
        </tbody>
      </table>
      {menu ? <ContextMenu state={menu} sid={sid} onClose={() => setMenu(null)} /> : null}
    </div>
  );
}

function ProcessRow({
  node, folded, onToggle, onLoad, onMenu,
}: {
  node: ProcessNode;
  folded: boolean;
  onToggle: () => void;
  onLoad: () => void;
  onMenu: (event: React.MouseEvent) => void;
}) {
  const { t } = useI18n();
  const image = node.images[node.images.length - 1];
  const chain = node.images.map((item) => item.exe?.split(/[/\\]/u).pop() ?? "?").join(" → ");
  const hasChildren = node.children.length > 0 || node.truncated;
  const files = folded ? node.subtree_files : node.files;
  const writes = folded ? node.subtree_writes : node.writes;
  const deletes = folded ? node.subtree_deletes : node.deletes;
  const up = folded ? node.subtree_bytes_up : node.bytes_up;
  const down = folded ? node.subtree_bytes_down : node.bytes_down;

  return (
    <tr className="border-b border-line/60 hover:bg-paper-sunken" onContextMenu={onMenu}>
      <td className="px-3 py-1" style={{ paddingLeft: `${12 + node.depth * 16}px` }}>
        <div className="flex items-center gap-1">
          {hasChildren ? (
            <button type="button" onClick={onToggle} aria-expanded={!folded} className="w-4 text-ink-faint">
              {folded ? "▸" : "▾"}
            </button>
          ) : (
            <span className="w-4" />
          )}
          <span className="font-mono">{image?.exe?.split(/[/\\]/u).pop() ?? "?"}</span>
          <span className="text-ink-faint">({node.pid})</span>
          {node.images.length > 1 ? <span className="text-ink-soft">{chain}</span> : null}
          <span className="truncate text-ink-faint" title={joinCommand(image?.argv)}>{joinCommand(image?.argv)}</span>
          {node.how === "snapshot" ? <span title={t("procs.snapshot")}><EvidenceBadge level="S" /></span> : null}
          {node.agent ? <span className="rounded border border-line px-1 text-[10px]">{node.agent}</span> : null}
          {node.sensitive ? <span title={t("procs.sensitive")} className="text-sensitive">▲</span> : null}
          {node.attribution_break ? <span title={t("procs.breakTip")} className="text-ink-faint">⇢ {t("procs.break")}</span> : null}
          {node.truncated && !folded ? (
            <button type="button" onClick={onLoad} className="text-ink-faint underline">{t("procs.loadChildren")}</button>
          ) : null}
        </div>
      </td>
      <td className="px-2 py-1" title={folded ? t("procs.subtree") : t("procs.own")}><Count value={files} /></td>
      <td className="px-2 py-1"><Count value={writes} /> / <Count value={deletes} /></td>
      <td className="px-2 py-1"><Bytes value={up} /> / <Bytes value={down} /></td>
    </tr>
  );
}

function ContextMenu({ state, sid, onClose }: { state: MenuState; sid: string; onClose: () => void }) {
  const { t } = useI18n();
  const navigate = useNavigate();
  const { patch } = useSessionQuery();
  const command = joinCommand(state.node.images[state.node.images.length - 1]?.argv);
  const items = [
    {
      label: t("procs.menu.subtree"),
      run: () => {
        patch({ subtree: state.node.proc_uid, proc: "" });
        void navigate({ to: "/s/$sid/files", params: { sid }, search: { subtree: state.node.proc_uid } });
      },
    },
    { label: t("procs.menu.copy"), run: () => void copyText(command) },
    {
      label: t("procs.menu.timeline"),
      run: () => void navigate({ to: "/s/$sid/timeline", params: { sid }, search: { proc: state.node.proc_uid } }),
    },
  ];
  return (
    <ul className="fixed z-20 rounded border border-line bg-paper py-1 text-xs shadow" style={{ left: state.x, top: state.y }} role="menu">
      {items.map((item) => (
        <li key={item.label}>
          <button
            type="button"
            role="menuitem"
            className="block w-full px-3 py-1 text-left hover:bg-paper-sunken"
            onClick={() => {
              item.run();
              onClose();
            }}
          >
            {item.label}
          </button>
        </li>
      ))}
    </ul>
  );
}

interface VisibleRow {
  node: ProcessNode;
  folded: boolean;
}

function visible(nodes: ProcessNode[], collapsed: Set<string>, extra: Record<string, ProcessNode[]>): VisibleRow[] {
  const rows: VisibleRow[] = [];
  const walk = (list: ProcessNode[]) => {
    for (const node of list) {
      const children = extra[node.proc_uid] ?? node.children;
      const folded = collapsed.has(node.proc_uid);
      rows.push({ node: { ...node, children }, folded });
      if (!folded) walk(children);
    }
  };
  walk(nodes);
  return rows;
}
