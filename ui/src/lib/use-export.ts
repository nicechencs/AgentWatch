import { useState } from "react";
import { api, saveFile, type ExportFormat } from "@/api/client";
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
  const run = async (sid: string, format: ExportFormat) => {
    setPending(format);
    setError(null);
    try {
      saveFile(await api.exportFile(sid, format));
    } catch (caught) {
      const reason = caught instanceof Error && caught.message ? caught.message : t("common.error");
      setError(t("export.failed", { reason }));
    } finally {
      setPending(null);
    }
  };
  return { run, pending, error, clear: () => setError(null) };
}
