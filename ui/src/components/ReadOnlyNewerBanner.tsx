import { useQuery } from "@tanstack/react-query";
import { api } from "@/api/client";
import { useI18n } from "@/lib/i18n";

/** Visible on every app layout when a newer AgentWatch wrote this database. */
export function ReadOnlyNewerBanner() {
  const { t } = useI18n();
  const doctor = useQuery({ queryKey: ["doctor"], queryFn: () => api.doctor(), refetchInterval: 10_000 });
  if (doctor.data?.database?.read_only !== true) return null;
  return <p role="alert" className="border-b border-line bg-paper-sunken px-4 py-2 text-xs text-ink-soft">{t("error.dbReadOnlyNewer")}</p>;
}
