import type { ReactNode } from "react";
import { describeError } from "@/api/errors";
import { useI18n } from "@/lib/i18n";

export function Loading() {
  const { t } = useI18n();
  return <p className="px-4 py-6 text-sm text-ink-faint">{t("common.loading")}</p>;
}

/** Pass `error` (the caught value) so common daemon errors read as a sentence. */
export function ErrorNote({ message, error, onRetry }: { message?: string; error?: unknown; onRetry?: () => void }) {
  const { t } = useI18n();
  const text = error !== undefined && error !== null ? describeError(error, t) : message || t("error.unknown");
  return (
    <p className="px-4 py-6 text-sm text-ink-soft">
      {t("common.error")}{t("common.colon")}{text}{" "}
      {onRetry ? (
        <button type="button" className="underline" onClick={onRetry}>
          {t("common.retry")}
        </button>
      ) : null}
    </p>
  );
}

export function EmptyNote({ children }: { children?: ReactNode }) {
  const { t } = useI18n();
  return <p className="px-4 py-6 text-sm text-ink-faint">{children ?? t("common.empty")}</p>;
}
