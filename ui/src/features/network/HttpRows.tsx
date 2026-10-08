import type { NetFlow } from "@/api/types";
import { Bytes } from "@/components/Bytes";
import { EvidenceBadge } from "@/components/EvidenceBadge";
import { flowMarks, isCertPinned, visibleHeaders, type FlowMark, type HttpRow } from "./http";
import { fill, useNetStrings } from "./strings";

const MARK_STYLE: Record<FlowMark, string> = {
  direct: "text-gap",
  quic: "text-ink-soft",
  via_proxy: "text-ink-soft",
};

/** Connection marks: 直连 (with ⓘ), QUIC, 经代理. Text always present; colour is not the only cue. */
export function FlowMarks({ flow }: { flow: Pick<NetFlow, "direct" | "via_proxy" | "proto" | "remote_port" | "na_reason"> }) {
  const s = useNetStrings();
  const marks = flowMarks(flow);
  if (marks.length === 0) return null;
  const label = { direct: s.markDirect, quic: s.markQuic, via_proxy: s.markViaProxy };
  const tip = { direct: s.markDirectTip, quic: s.markQuicTip, via_proxy: s.markViaProxyTip };
  return (
    <>
      {marks.map((mark) => (
        <span key={mark} data-mark={mark} className={`ml-2 rounded border border-line px-1 text-[10px] ${MARK_STYLE[mark]}`}>
          {label[mark]}
          {mark === "direct" ? (
            <abbr title={tip.direct} aria-label={tip.direct} className="ml-0.5 cursor-help no-underline">ⓘ</abbr>
          ) : (
            <span className="sr-only">{tip[mark]}</span>
          )}
        </span>
      ))}
    </>
  );
}

function Duration({ ms }: { ms: number | null }) {
  const s = useNetStrings();
  if (ms === null || ms === undefined) return <span className="text-ink-faint" title={s.colDuration}>–</span>;
  return <span className="tabular-nums">{ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(2)} s`}</span>;
}

/** Third table layer: HTTP requests on one connection. */
export function HttpTable({ rows }: { rows: HttpRow[] }) {
  const s = useNetStrings();
  if (rows.length === 0) return <p className="text-ink-faint">{s.httpNone}</p>;
  return (
    <table className="w-full border-collapse text-[11px]" aria-label="HTTP">
      <thead className="text-left text-ink-faint">
        <tr>
          {[s.colMethod, s.colUrl, s.colStatus, s.colReq, s.colResp, s.colDuration, s.colEvidence].map((col) => (
            <th key={col} className="px-1 py-0.5 font-normal">{col}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rows.map((row) => (
          <HttpRowView key={row.id} row={row} />
        ))}
      </tbody>
    </table>
  );
}

function HttpRowView({ row }: { row: HttpRow }) {
  const s = useNetStrings();
  const pinned = isCertPinned(row);
  const { shown, hidden } = visibleHeaders(row.req_headers);
  return (
    <>
      <tr className="border-t border-line/40 align-top" data-http-id={row.id}>
        <td className="px-1 py-0.5 font-mono">{row.method}</td>
        <td className="max-w-[28rem] break-all px-1 py-0.5 font-mono" data-field="url">
          {pinned ? (
            <span className="text-ink-faint" data-state="cert_pinned">{s.certPinned}</span>
          ) : (
            row.url
          )}
        </td>
        <td className="px-1 py-0.5 tabular-nums">
          {row.status ?? <span className="text-ink-faint">–</span>}
        </td>
        <td className="px-1 py-0.5"><Bytes value={row.req_body_bytes} naReason={pinned ? "cert_pinned" : null} /></td>
        <td className="px-1 py-0.5"><Bytes value={row.resp_body_bytes} naReason={pinned ? "cert_pinned" : null} /></td>
        <td className="px-1 py-0.5"><Duration ms={row.duration_ms} /></td>
        <td className="px-1 py-0.5">
          <EvidenceBadge level={row.evidence} source={row.source} naReason={pinned ? "cert_pinned" : null} />
        </td>
      </tr>
      {pinned ? (
        <tr>
          <td colSpan={7} className="px-1 pb-1 text-ink-faint" data-hint="tunnel">
            {s.certPinnedHint}
          </td>
        </tr>
      ) : null}
      {shown.length > 0 || hidden > 0 ? (
        <tr>
          <td colSpan={7} className="px-1 pb-1 text-ink-faint">
            <span>{s.headers}：</span>
            {shown.map(([name, value]) => (
              <span key={name} className="mr-2 font-mono">{name}: {value}</span>
            ))}
            {hidden > 0 ? <span>{fill(s.headersHidden, { count: hidden })}</span> : null}
          </td>
        </tr>
      ) : null}
    </>
  );
}
