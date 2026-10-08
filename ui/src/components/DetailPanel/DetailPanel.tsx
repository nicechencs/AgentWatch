import type { ReactNode } from "react";
import type { EvidenceLevel, FieldEvidence, NaReason } from "@/api/types";
import { EvidenceBadge } from "@/components/EvidenceBadge";
import { copyText, nsToRfc3339 } from "@/lib/format";
import { useI18n } from "@/lib/i18n";
import type { SessionQuery } from "@/lib/session-query";

export interface DetailRecord {
  id: number;
  table: string;
  tsNs: number;
  evidence: EvidenceLevel;
  naReason?: NaReason | null;
  source: string | null;
  corroboratedBy?: string[] | null;
  procUid: string | null;
  fields: Record<string, unknown>;
  fieldEvidence?: Record<string, FieldEvidence> | null;
}

interface Props {
  record: DetailRecord | null;
  patch: (next: Partial<SessionQuery>) => void;
  onClose: () => void;
}

function display(value: unknown): string {
  if (value === null || value === undefined) return "–";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return JSON.stringify(value);
}

/** Shared record sidebar: every field with its evidence, plus scope actions. */
export function DetailPanel({ record, patch, onClose }: Props) {
  const { t } = useI18n();
  return (
    <aside className="flex w-80 shrink-0 flex-col border-l border-line bg-paper-raised">
      <header className="flex items-center justify-between border-b border-line px-3 py-2">
        <h2 className="text-sm font-medium">{t("detail.title")}</h2>
        <button type="button" onClick={onClose} className="text-xs text-ink-faint hover:text-ink">
          {t("common.close")}
        </button>
      </header>
      {record ? <Body record={record} patch={patch} /> : <p className="px-3 py-4 text-xs text-ink-faint">{t("detail.empty")}</p>}
    </aside>
  );
}

function Body({ record, patch }: { record: DetailRecord; patch: (next: Partial<SessionQuery>) => void }) {
  const { t } = useI18n();
  const entries = Object.entries(record.fields);

  const around = () => {
    const tenSeconds = 10_000_000_000;
    patch({
      from: nsToRfc3339(record.tsNs - tenSeconds),
      to: nsToRfc3339(record.tsNs + tenSeconds),
      f: "",
      ev: "",
    });
  };

  const actions: { label: string; run: () => void; hidden?: boolean }[] = [
    { label: t("detail.around"), run: around },
    { label: t("detail.onlyProc"), run: () => patch({ proc: record.procUid ?? "", subtree: "" }), hidden: !record.procUid },
    {
      label: t("detail.onlySubtree"),
      run: () => patch({ subtree: record.procUid ?? "", proc: "" }),
      hidden: !record.procUid,
    },
    {
      label: t("detail.copyFilter"),
      run: () => void copyText(`${record.table}:${record.id}`),
    },
  ];

  return (
    <div className="flex-1 overflow-y-auto">
      <div className="flex flex-wrap gap-1 border-b border-line px-3 py-2">
        {actions
          .filter((action) => !action.hidden)
          .map((action) => (
            <button
              key={action.label}
              type="button"
              onClick={action.run}
              className="rounded border border-line px-1.5 py-0.5 text-[11px] hover:border-ink"
            >
              {action.label}
            </button>
          ))}
      </div>
      <dl className="px-3 py-2 text-xs">
        <Row label={t("detail.source")}>
          <span className="flex items-center gap-1">
            <EvidenceBadge level={record.evidence} source={record.source} naReason={record.naReason} />
            <span className="font-mono text-ink-soft">{record.source ?? "–"}</span>
          </span>
        </Row>
        {record.corroboratedBy && record.corroboratedBy.length > 0 ? (
          <Row label={t("detail.corroborated")}>
            <span className="font-mono">{record.corroboratedBy.join(", ")}</span>
          </Row>
        ) : null}
        {entries.map(([key, value]) => {
          const field = record.fieldEvidence?.[key];
          return (
            <Row key={key} label={key}>
              <span className="flex items-start gap-1 break-all">
                {field ? (
                  <EvidenceBadge level={field.evidence} source={field.source} naReason={field.na_reason} />
                ) : null}
                <span className="font-mono">{display(value)}</span>
              </span>
            </Row>
          );
        })}
      </dl>
    </div>
  );
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[7rem_1fr] gap-2 border-b border-line/60 py-1">
      <dt className="text-ink-faint">{label}</dt>
      <dd>{children}</dd>
    </div>
  );
}
