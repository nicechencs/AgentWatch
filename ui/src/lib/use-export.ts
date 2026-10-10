import { useState } from "react";
import { exportToFile, type ExportFormat } from "@/api/client";
import { describeError } from "@/api/errors";
import { useI18n } from "@/lib/i18n";

/**
 * Export through the request layer and save the bytes, staying on the page.
 * A failure is shown where the user clicked, not as a navigation to the
 * daemon's JSON error.
 */
export function useExport() {
  const { t } = useI18n();
  const [pending, setPending] = useState<ExportFormat | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const run = async (sid: string, format: ExportFormat) => {
    setPending(format);
    setError(null);
    setNotice(null);
    try {
      const outcome = await exportToFile(sid, format);
      // The app wrote the file where the user chose: say where.
      if (outcome.kind === "saved") setNotice(t("export.savedTo", { path: outcome.path }));
    } catch (caught) {
      setError(t("export.failed", { reason: describeError(caught, t) }));
    } finally {
      setPending(null);
    }
  };
  return {
    run,
    pending,
    error,
    notice,
    clear: () => {
      setError(null);
      setNotice(null);
    },
  };
}
