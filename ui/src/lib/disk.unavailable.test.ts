/**
 * Disk usage. When the daemon does not export per-user stats, the page says
 * so in one sentence instead of repeating 不可得.
 */
import { describe, expect, it } from "vitest";
import { diskUnavailableText, diskUsed } from "@/lib/disk";
import zh from "@/i18n/zh.json";

const ZH = zh as Record<string, string>;
const t = (key: string, vars?: Record<string, string | number>) =>
  (ZH[key] ?? key).replace(/\{(\w+)\}/gu, (_, name: string) => String(vars?.[name] ?? `{${name}}`));

describe("disk usage unavailable", () => {
  it("is one sentence, not 不可得 / 不可得", () => {
    const stats = { available: false, reason: "per-user stats are not exported", db_bytes: null, wal_bytes: null } as never;
    expect(diskUsed(stats)).toBeNull();
    expect(diskUnavailableText(stats, t)).toBe(ZH["disk.unavailablePerUser"]);
    expect(diskUsed({ db_bytes: 10, wal_bytes: 2 } as never)).toBe(12);
  });
});
