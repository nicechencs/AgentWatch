import type { NaReason } from "@/api/types";
import { formatBytes } from "@/lib/format";
import { useI18n } from "@/lib/i18n";

interface Props {
  value: number | null | undefined;
  naReason?: NaReason | null;
  /** Prefix ≈ when the figure mixes sampled data or covers a gap window. */
  approximate?: boolean;
  approximateReason?: string | null;
}

/**
 * Renders an unavailable byte count as grey "不可得" with the reason on hover.
 * Never renders 0 for an unknown value (evidence-model §7).
 */
export function Bytes({ value, naReason, approximate, approximateReason }: Props) {
  const { t } = useI18n();
  if (value === null || value === undefined) {
    const reason = naReason ? t(`na.${naReason}`) : t("evidence.tip.NA");
    return (
      <span title={reason} className="text-ink-faint">
        {t("common.unavailable")}
      </span>
    );
  }
  const text = formatBytes(value, t("common.unavailable"));
  if (!approximate) return <span className="tabular-nums">{text}</span>;
  return (
    <span
      title={t("bytes.approx", { reason: approximateReason ?? t("evidence.tip.S") })}
      className="tabular-nums"
    >
      ≈ {text}
    </span>
  );
}
