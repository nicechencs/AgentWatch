import type { DbStats } from "@/api/types";

type T = (key: string, vars?: Record<string, string | number>) => string;

/** Bytes used by the database, or null when the daemon did not report sizes. */
export function diskUsed(stats: DbStats | null | undefined): number | null {
  if (!stats || stats.available === false) return null;
  const db = typeof stats.db_bytes === "number" ? stats.db_bytes : null;
  const wal = typeof stats.wal_bytes === "number" ? stats.wal_bytes : 0;
  return db === null ? null : db + wal;
}

/**
 * Why disk usage is unknown, in one sentence. The daemon's reason is English
 * developer text; the common one (per-user stats not exported) is translated.
 */
export function diskUnavailableText(stats: DbStats | null | undefined, t: T): string {
  const reason = stats?.reason ?? "";
  if (/per-user/iu.test(reason) || stats?.available === false) return t("disk.unavailablePerUser");
  return t("disk.unavailable");
}
