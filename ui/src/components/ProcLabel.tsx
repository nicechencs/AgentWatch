import { useI18n } from "@/lib/i18n";

interface Props {
  pid: number | null | undefined;
  exe: string | null | undefined;
  className?: string;
}

export function ProcLabel({ pid, exe, className = "" }: Props) {
  const { t } = useI18n();
  if (!pid && !exe) return <span className="text-ink-faint">–</span>;
  return (
    <span className={`font-mono text-xs ${className}`}>
      {exe ?? <span className="font-sans text-ink-faint" title={t("procs.nameNaTip")}>{t("procs.nameNa")}</span>}
      {pid ? <span className="text-ink-faint">({pid})</span> : null}
    </span>
  );
}
