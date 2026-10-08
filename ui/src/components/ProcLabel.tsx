interface Props {
  pid: number | null | undefined;
  exe: string | null | undefined;
  className?: string;
}

export function ProcLabel({ pid, exe, className = "" }: Props) {
  if (!pid && !exe) return <span className="text-ink-faint">–</span>;
  return (
    <span className={`font-mono text-xs ${className}`}>
      {exe ?? "?"}
      {pid ? <span className="text-ink-faint">({pid})</span> : null}
    </span>
  );
}
