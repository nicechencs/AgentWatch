import { dayKey, formatDay, formatTimePrecise, isWallTime, nsToDate } from "@/lib/format";
import { useI18n } from "@/lib/i18n";
import { usePrefs } from "@/lib/prefs";

/**
 * Row time on the timeline. A clock time alone hid the day: a process that
 * started yesterday at 03:50 showed as 「03:50:24」 in a session that began
 * today at 19:10. The date is added when the row's day differs from the
 * session's start day, and a row before the session start is labelled.
 */
export function TimelineTime({ ns, sessionStart }: { ns: number; sessionStart: number | null }) {
  const { t } = useI18n();
  const { lang, timeFormat } = usePrefs();
  const utc = timeFormat === "utc";
  if (!isWallTime(ns)) {
    return (
      <span className="shrink-0 text-ink-faint" title={t("timeline.timeNaTip")}>
        {t("timeline.timeNa")}
      </span>
    );
  }
  const reference = sessionStart ?? Date.now() * 1_000_000;
  const otherDay = dayKey(ns, utc) !== dayKey(reference, utc);
  const before = sessionStart !== null && ns < sessionStart;
  return (
    <span className="flex shrink-0 items-baseline gap-1">
      <time dateTime={nsToDate(ns).toISOString()} className="tabular-nums">
        {otherDay ? `${formatDay(ns, lang, utc)} ` : ""}
        {formatTimePrecise(ns, utc)}
      </time>
      {before ? (
        <span className="rounded border border-line px-1 text-[10px] text-ink-faint" title={t("timeline.beforeSessionTip")}>
          {t("timeline.beforeSession")}
        </span>
      ) : null}
    </span>
  );
}
