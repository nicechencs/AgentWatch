import { useI18n } from "@/lib/i18n";

export function Loading() {
  const { t } = useI18n();
  return <p className="px-4 py-6 text-sm text-ink-faint">{t("common.loading")}</p>;
}

export function ErrorNote({ message, onRetry }: { message: string; onRetry?: () => void }) {
  const { t } = useI18n();
  return (
    <p className="px-4 py-6 text-sm text-ink-soft">
      {t("common.error")}：{message}{" "}
      {onRetry ? (
        <button type="button" className="underline" onClick={onRetry}>
          {t("common.retry")}
        </button>
      ) : null}
    </p>
  );
}

export function EmptyNote({ children }: { children?: string }) {
  const { t } = useI18n();
  return <p className="px-4 py-6 text-sm text-ink-faint">{children ?? t("common.empty")}</p>;
}
