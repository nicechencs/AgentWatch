import type { Session } from "@/api/types";
import { redactionForDisplay } from "@/lib/format";
import type { Lang } from "@/lib/i18n";

/**
 * What to call a session: its name, else the command it ran ("sleep 90"),
 * else its public id. A session made with 「启动程序」 has no name and was
 * listed as `s-31988513fa4a`.
 */
export function sessionTitle(session: Pick<Session, "name" | "argv" | "public_id">, lang: Lang = "zh"): string {
  const name = session.name?.trim();
  if (name) return name;
  const command = (session.argv ?? []).map((part) => redactionForDisplay(part, lang)).join(" ").trim();
  return command || session.public_id;
}
