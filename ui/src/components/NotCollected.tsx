import { EvidenceBadge } from "@/components/EvidenceBadge";
import { kindLabel, type Coverage } from "@/lib/capabilities";
import { useI18n } from "@/lib/i18n";

/** Short cell text for a value this session's collectors do not observe. */
export function NotCollected({ kind }: { kind: string }) {
  const { t } = useI18n();
  return (
    <span className="text-ink-faint" title={t("coverage.notCollectedTip", { kind: kindLabel(t, kind) })}>
      {t("coverage.notCollectedShort")}
    </span>
  );
}

/**
 * Page-level statement for a category that is not collected, or whose
 * collection cannot be confirmed. Returns null when the category is collected,
 * so the page's own empty state ("没有记录") applies only then.
 */
export function CoverageNote({ kind, coverage }: { kind: string; coverage: Coverage }) {
  const { t } = useI18n();
  if (coverage === "collected") return null;
  const label = kindLabel(t, kind);
  return (
    <p className="flex items-center gap-1 px-4 py-6 text-sm text-ink-soft" data-coverage={coverage}>
      <EvidenceBadge level="NA" naReason={coverage === "not_collected" ? "collector_unavailable" : null} />
      {coverage === "not_collected"
        ? t("coverage.notCollected", { kind: label })
        : t("coverage.unknown", { kind: label })}
    </p>
  );
}
