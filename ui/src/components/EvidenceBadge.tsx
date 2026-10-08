import type { EvidenceLevel, NaReason } from "@/api/types";
import { useI18n } from "@/lib/i18n";

const STYLE: Record<EvidenceLevel, string> = {
  E1: "bg-ink text-paper",
  E2: "bg-ink-soft text-paper",
  E3: "border border-dashed border-ink text-ink",
  S: "border border-dashed border-ink-soft text-ink-soft",
  I: "border border-dashed border-amber-600 italic text-amber-700 dark:text-amber-400",
  NA: "bg-paper-sunken text-ink-faint",
};

interface Props {
  level: EvidenceLevel;
  source?: string | null;
  naReason?: NaReason | null;
  className?: string;
}

/** Always carries its text; colour alone never conveys the level (evidence-model §4). */
export function EvidenceBadge({ level, source, naReason, className = "" }: Props) {
  const { t } = useI18n();
  const tip = naReason
    ? t(`na.${naReason}`)
    : level === "E1"
      ? t("evidence.tip.E1", { source: source ?? t("common.unknown") })
      : t(`evidence.tip.${level}`);
  return (
    <abbr
      title={tip}
      className={`inline-flex items-center whitespace-nowrap rounded px-1 text-[11px] leading-4 no-underline ${STYLE[level]} ${className}`}
    >
      {t(`evidence.${level}`)}
    </abbr>
  );
}
