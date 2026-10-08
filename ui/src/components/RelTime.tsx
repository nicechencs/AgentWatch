import { formatTime, formatTimePrecise } from "@/lib/format";
import { usePrefs } from "@/lib/prefs";

interface Props {
  ns: number;
  precise?: boolean;
}

export function RelTime({ ns, precise = false }: Props) {
  const { lang, timeFormat } = usePrefs();
  const utc = timeFormat === "utc";
  return (
    <time dateTime={new Date(ns / 1_000_000).toISOString()} className="tabular-nums">
      {precise ? formatTimePrecise(ns, utc) : formatTime(ns, lang, utc)}
    </time>
  );
}
