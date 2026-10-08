import { formatCount } from "@/lib/format";
import { useI18n } from "@/lib/i18n";

interface Props {
  value: number | null | undefined;
  approximate?: boolean;
  approximateReason?: string | null;
}

/** Same rule as Bytes: unknown stays unknown, and mixed-quality totals gain ≈. */
export function Count({ value, approximate, approximateReason }: Props) {
  const { t } = useI18n();
  if (value === null || value === undefined) {
    return <span className="text-ink-faint">{t("common.unavailable")}</span>;
  }
  const text = formatCount(value, t("common.unavailable"));
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
