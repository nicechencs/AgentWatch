import type { Lang } from "./i18n";

const UNITS = ["B", "KB", "MB", "GB", "TB"];

/** Decimal byte units, matching the filter grammar (1KB = 1000B). */
export function formatBytes(value: number | null | undefined, unavailable: string): string {
  if (value === null || value === undefined) return unavailable;
  if (!Number.isFinite(value)) return unavailable;
  let n = Math.abs(value);
  let unit = 0;
  while (n >= 1000 && unit < UNITS.length - 1) {
    n /= 1000;
    unit += 1;
  }
  const digits = unit === 0 || n >= 100 ? 0 : n >= 10 ? 1 : 2;
  const text = `${n.toFixed(digits)} ${UNITS[unit]}`;
  return value < 0 ? `-${text}` : text;
}

export function formatCount(value: number | null | undefined, unavailable: string): string {
  if (value === null || value === undefined) return unavailable;
  return new Intl.NumberFormat().format(value);
}

export function formatDuration(ms: number): string {
  if (ms < 0) ms = 0;
  const total = Math.floor(ms / 1000);
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  if (h > 0) return `${h}h${m}m`;
  if (m > 0) return `${m}m${s.toString().padStart(2, "0")}s`;
  return `${s}s`;
}

export function nsToDate(ns: number): Date {
  return new Date(ns / 1_000_000);
}

export function formatTime(ns: number, lang: Lang, utc: boolean): string {
  const date = nsToDate(ns);
  return new Intl.DateTimeFormat(lang === "zh" ? "zh-CN" : "en-GB", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hourCycle: "h23",
    timeZone: utc ? "UTC" : undefined,
  }).format(date);
}

export function formatTimePrecise(ns: number, utc: boolean): string {
  const date = nsToDate(ns);
  const base = new Intl.DateTimeFormat("en-GB", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23",
    timeZone: utc ? "UTC" : undefined,
  }).format(date);
  const ms = Math.floor((ns / 1_000_000) % 1000)
    .toString()
    .padStart(3, "0");
  return `${base}.${ms}`;
}

export function formatClockRange(fromNs: number, toNs: number, utc: boolean): string {
  return `${formatTimePrecise(fromNs, utc)}–${formatTimePrecise(toNs, utc)}`;
}

/** RFC3339 with millisecond precision, as the API accepts for time bounds. */
export function nsToRfc3339(ns: number): string {
  return nsToDate(ns).toISOString();
}

export function joinCommand(argv: string[] | null | undefined): string {
  if (!argv || argv.length === 0) return "";
  return argv
    .map((part) => (/[\s"]/u.test(part) ? `"${part.replaceAll('"', '\\"')}"` : part))
    .join(" ");
}

export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

/** Calendar day key of `ns` in local time or UTC. */
export function dayKey(ns: number, utc: boolean): string {
  const date = nsToDate(ns);
  return utc
    ? `${date.getUTCFullYear()}-${date.getUTCMonth()}-${date.getUTCDate()}`
    : `${date.getFullYear()}-${date.getMonth()}-${date.getDate()}`;
}

/** `MM/DD` (zh) or `DD/MM` (en) for a row whose day is not the reference day. */
export function formatDay(ns: number, lang: Lang, utc: boolean): string {
  return new Intl.DateTimeFormat(lang === "zh" ? "zh-CN" : "en-GB", {
    month: "2-digit",
    day: "2-digit",
    timeZone: utc ? "UTC" : undefined,
  }).format(nsToDate(ns));
}

/**
 * Whether `ns` reads as a real unix time (after 2001-01-01). A monotonic tick
 * or a zero stored where wall time belongs showed as 「01/01 08:00」 (1970).
 */
export function isWallTime(ns: number | null | undefined): ns is number {
  return typeof ns === "number" && ns >= 978_307_200_000_000_000;
}
