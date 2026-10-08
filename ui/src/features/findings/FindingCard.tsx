/**
 * FindingCard — one row in the findings list (ui §3.8).
 *
 * Rendering rules (evidence-model §4, AGENTS.md §4):
 * - Three visual kinds: content_match / fact / inferred (I).
 * - Inferred: dashed amber border, no red / danger palette.
 * - Text always comes from API `text`, never from FE string assembly.
 * - Caveat is always visible for inferred findings.
 * - "查看依据" is togglable; each ref opens in the timeline via `patch`.
 */
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { EvidenceBadge } from "@/components/EvidenceBadge";
import { RelTime } from "@/components/RelTime";
import { useI18n } from "@/lib/i18n";
import type { SessionQuery } from "@/lib/session-query";
import { patchFinding, refsQueryOptions } from "./api";
import { type FindingGroup, refsOf, caveatsOf, evidenceLevel } from "./model";
import type { Finding } from "./types";

interface Props {
  finding: Finding;
  sid: string;
  group: FindingGroup;
  patch: (next: Partial<SessionQuery>) => void;
  onNavigateTimeline: (sid: string) => void;
}

export function FindingCard({ finding, sid, group, patch, onNavigateTimeline }: Props) {
  const { t } = useI18n();
  const qc = useQueryClient();
  const [refsOpen, setRefsOpen] = useState(false);

  const level = evidenceLevel(finding.evidence);
  const refs = refsOf(finding.refs);
  const caveats = caveatsOf(finding.caveats);
  const isInferred = group === "inferred";
  const isIgnored = finding.user_state === "ignored";

  const mutate = useMutation({
    mutationFn: (next: "confirmed" | "ignored" | null) => patchFinding(sid, finding.id, next),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["findings", sid] });
    },
  });

  // Outer ring style: inferred → amber dashed; content → solid muted; fact → plain
  const borderCls =
    group === "inferred"
      ? "border border-dashed border-amber-600 dark:border-amber-500"
      : group === "content"
        ? "border border-accent/50"
        : "border border-line";

  const cardCls = `rounded-md px-3 py-2.5 ${borderCls} ${isIgnored ? "opacity-50" : ""}`;

  return (
    <li className={cardCls} aria-label={finding.text ?? finding.wording_id}>
      {/* ── Main sentence ── */}
      <div className="flex flex-wrap items-start gap-2">
        <EvidenceBadge level={level} source={finding.rule_id} className="mt-[1px] shrink-0" />
        <SeverityBadge severity={finding.severity} />
        <p className="min-w-0 flex-1 text-xs leading-5">
          {finding.text ?? <span className="italic text-ink-faint">{finding.error ?? finding.wording_id}</span>}
        </p>
      </div>

      {/* ── Meta row: count, first, last ── */}
      <div className="mt-1 flex flex-wrap gap-3 text-[11px] text-ink-faint">
        {finding.count > 1 ? (
          <span>{t("findings.count", { count: finding.count })}</span>
        ) : null}
        <span>
          {t("findings.first")} <RelTime ns={finding.first_ns} />
        </span>
        {finding.last_ns !== finding.first_ns ? (
          <span>
            {t("findings.last")} <RelTime ns={finding.last_ns} />
          </span>
        ) : null}
      </div>

      {/* ── Caveat: always visible for inferred, also when gap caveat present ── */}
      {(isInferred || caveats.length > 0 || finding.kind === "content_match") && (
        <Caveats finding={finding} isInferred={isInferred} caveats={caveats} />
      )}

      {/* ── Actions row ── */}
      <div className="mt-2 flex flex-wrap gap-2 text-[11px]">
        {refs.length > 0 ? (
          <button
            type="button"
            onClick={() => setRefsOpen((v) => !v)}
            className="rounded border border-line px-1.5 py-0.5 hover:border-ink"
          >
            {refsOpen ? t("findings.refsHide") : t("findings.refsShow")}
          </button>
        ) : null}
        {finding.user_state !== "confirmed" ? (
          <button
            type="button"
            disabled={mutate.isPending}
            onClick={() => mutate.mutate("confirmed")}
            className="rounded border border-line px-1.5 py-0.5 hover:border-ink disabled:opacity-40"
          >
            {t("findings.actionConfirm")}
          </button>
        ) : null}
        {finding.user_state !== "ignored" ? (
          <button
            type="button"
            disabled={mutate.isPending}
            onClick={() => mutate.mutate("ignored")}
            className="rounded border border-line px-1.5 py-0.5 hover:border-ink disabled:opacity-40"
          >
            {t("findings.actionIgnore")}
          </button>
        ) : null}
        {finding.user_state != null ? (
          <button
            type="button"
            disabled={mutate.isPending}
            onClick={() => mutate.mutate(null)}
            className="rounded border border-line px-1.5 py-0.5 text-ink-faint hover:border-ink disabled:opacity-40"
          >
            {t("findings.actionClear")}
          </button>
        ) : null}
      </div>

      {/* ── Refs panel ── */}
      {refsOpen && refs.length > 0 ? (
        <RefsPanel sid={sid} refs={refs} patch={patch} onNavigateTimeline={onNavigateTimeline} />
      ) : null}
    </li>
  );
}

// ── Caveat display ──────────────────────────────────────────────────────────

function Caveats({
  finding,
  isInferred,
  caveats,
}: {
  finding: Finding;
  isInferred: boolean;
  caveats: ReturnType<typeof caveatsOf>;
}) {
  const { t } = useI18n();
  return (
    <div className="mt-1 flex flex-col gap-0.5">
      {/* Standard caveat for every inferred finding */}
      {isInferred ? (
        <p className="text-[11px] italic text-amber-700 dark:text-amber-400">
          {t("findings.inferredCaveat")}
        </p>
      ) : null}
      {/* Structural caveats from the API (gap references, etc.) */}
      {caveats.map((caveat, i) => (
        <p key={i} className="text-[11px] text-ink-faint">
          {"gap_id" in caveat
            ? t("findings.gapCaveat", { id: caveat.gap_id })
            : t("findings.textCaveat", { id: caveat.text_id })}
        </p>
      ))}
      {/* Additional limitation text shown under content_match findings */}
      {finding.kind === "content_match" ? (
        <p className="text-[11px] text-ink-faint">{t("findings.contentMatchCaveat")}</p>
      ) : null}
    </div>
  );
}

// ── Severity badge ──────────────────────────────────────────────────────────

function SeverityBadge({ severity }: { severity: string }) {
  const { t } = useI18n();
  const cls =
    severity === "warn"
      ? "bg-sensitive/15 text-sensitive dark:text-yellow-300"
      : severity === "notice"
        ? "bg-paper-sunken text-ink-soft"
        : "bg-paper-sunken text-ink-faint";
  return (
    <span className={`inline-flex items-center rounded px-1 text-[10px] leading-4 ${cls}`}>
      {t(`findings.severity.${severity}`, {})}
    </span>
  );
}

// ── Refs panel ──────────────────────────────────────────────────────────────

function RefsPanel({
  sid,
  refs,
  patch,
  onNavigateTimeline,
}: {
  sid: string;
  refs: ReturnType<typeof refsOf>;
  patch: (next: Partial<SessionQuery>) => void;
  onNavigateTimeline: (sid: string) => void;
}) {
  const { t } = useI18n();
  const { data, isLoading } = useQuery(refsQueryOptions(sid, refs));

  if (isLoading) return <p className="mt-2 text-[11px] text-ink-faint">{t("common.loading")}</p>;

  return (
    <ul className="mt-2 flex flex-col gap-1.5 border-t border-line pt-2">
      {(data ?? []).map((resolved) => {
        const { ref, status } = resolved;
        const item = status === "found" ? resolved.item : null;
        return (
          <li key={`${ref.table}:${ref.id}`} className="flex items-start gap-2">
            {status === "found" && item ? (
              <>
                <EvidenceBadge level={item.evidence} source={item.source} className="mt-[1px] shrink-0" />
                <span className="min-w-0 flex-1 truncate text-[11px] text-ink-soft">
                  {item.summary || `${ref.table}:${ref.id}`}
                </span>
                <button
                  type="button"
                  onClick={() => {
                    // ±5s window around the ref's timestamp, then navigate to timeline
                    const five = 5_000_000_000;
                    patch({
                      from: new Date((item.ts_ns - five) / 1_000_000).toISOString(),
                      to: new Date((item.ts_ns + five) / 1_000_000).toISOString(),
                    });
                    onNavigateTimeline(sid);
                  }}
                  className="shrink-0 text-[11px] text-accent underline hover:no-underline"
                >
                  {t("findings.goTimeline")}
                </button>
              </>
            ) : (
              <span className="text-[11px] text-ink-faint">
                {status === "missing"
                  ? t("findings.refMissing", { table: ref.table, id: ref.id })
                  : t("findings.refUnsupported", { table: ref.table })}
              </span>
            )}
          </li>
        );
      })}
    </ul>
  );
}
