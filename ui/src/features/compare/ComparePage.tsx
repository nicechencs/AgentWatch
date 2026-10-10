/**
 * Multi-session compare (P5-UI-02).
 *
 * The daemon has no compare endpoint, so the three columns (only A / shared /
 * only B) stay an NA empty state. Session identity and the collector list are
 * real: they come from `GET /sessions/{id}` and `/summary`. Differing
 * collector sets are named, not scored.
 */
import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { api } from "@/api/client";
import type { Session } from "@/api/types";
import { EvidenceBadge } from "@/components/EvidenceBadge";
import { EmptyNote, ErrorNote, Loading } from "@/components/QueryState";
import { capabilitiesUnknown, coverage, kindInSentence, uncollectedKinds } from "@/lib/capabilities";
import { useI18n } from "@/lib/i18n";
import { sessionTitle } from "@/lib/session-title";
import { loadSide, type CompareSide } from "./api";

const DIMENSIONS = ["files", "commands", "domains", "findings"] as const;
type Dimension = (typeof DIMENSIONS)[number];

export function ComparePage({ initialA, initialB }: { initialA?: string; initialB?: string }) {
  const { t } = useI18n();
  const navigate = useNavigate();
  const [a, setA] = useState(initialA ?? "");
  const [b, setB] = useState(initialB ?? "");
  const [picked, setPicked] = useState(Boolean(initialA && initialB));
  const [dimension, setDimension] = useState<Dimension>("files");

  const sessions = useQuery({
    queryKey: ["sessions", "compare-picker"],
    queryFn: () => api.sessions({ limit: 200 }),
  });

  const pair = useQuery({
    queryKey: ["compare-sides", a, b],
    queryFn: () => Promise.all([loadSide(a), loadSide(b)]),
    enabled: picked && a !== "" && b !== "" && a !== b,
  });

  const start = (nextA: string, nextB: string) => {
    setA(nextA);
    setB(nextB);
    setPicked(true);
    void navigate({ to: "/compare", search: { a: nextA, b: nextB } });
  };

  return (
    <main className="px-4 py-3">
      <h1 className="text-base font-semibold">{t("compare.title")}</h1>
      <p className="mt-1 text-xs text-ink-soft">{t("compare.lead")}</p>

      <Picker
        items={sessions.data?.items ?? []}
        a={a}
        b={b}
        onApply={start}
      />

      {!picked || a === "" || b === "" ? <EmptyNote>{t("compare.pick")}</EmptyNote> : null}
      {picked && a !== "" && a === b ? <p className="mt-3 text-xs text-ink-faint">{t("compare.same")}</p> : null}

      {pair.isLoading ? <Loading /> : null}
      {pair.isError ? (
        <ErrorNote error={pair.error} onRetry={() => void pair.refetch()} />
      ) : null}

      {pair.data ? <PairView left={pair.data[0]} right={pair.data[1]} dimension={dimension} onDimension={setDimension} /> : null}
    </main>
  );
}

function Picker({
  items,
  a,
  b,
  onApply,
}: {
  items: Session[];
  a: string;
  b: string;
  onApply: (a: string, b: string) => void;
}) {
  const { t } = useI18n();
  const [draftA, setDraftA] = useState(a);
  const [draftB, setDraftB] = useState(b);
  return (
    <form
      className="mt-3 flex flex-wrap items-end gap-2 text-xs"
      onSubmit={(event) => {
        event.preventDefault();
        onApply(draftA, draftB);
      }}
    >
      <SessionSelect label={t("compare.sideA")} value={draftA} items={items} onChange={setDraftA} />
      <SessionSelect label={t("compare.sideB")} value={draftB} items={items} onChange={setDraftB} />
      <button type="submit" className="rounded border border-line px-2 py-1" disabled={!draftA || !draftB}>
        {t("compare.show")}
      </button>
    </form>
  );
}

function SessionSelect({
  label,
  value,
  items,
  onChange,
}: {
  label: string;
  value: string;
  items: Session[];
  onChange: (value: string) => void;
}) {
  const { t } = useI18n();
  return (
    <label className="flex flex-col gap-1">
      <span className="text-ink-faint">{label}</span>
      <select value={value} onChange={(event) => onChange(event.target.value)} className="rounded border border-line bg-paper px-2 py-1">
        <option value="">{t("compare.none")}</option>
        {items.map((session) => (
          <option key={session.public_id} value={session.public_id}>
            {sessionTitle(session)}
          </option>
        ))}
      </select>
    </label>
  );
}

function PairView({
  left,
  right,
  dimension,
  onDimension,
}: {
  left: CompareSide;
  right: CompareSide;
  dimension: Dimension;
  onDimension: (dimension: Dimension) => void;
}) {
  const { t } = useI18n();
  const differ = useMemo(() => capabilitiesDiffer(left.session, right.session), [left.session, right.session]);

  return (
    <div className="mt-4">
      {differ ? (
        <p className="rounded border border-dashed border-amber-600 px-2 py-1 text-xs text-ink-soft" data-note="capability">
          {t("compare.capabilityNote")}
        </p>
      ) : null}

      <div className="mt-3 grid gap-3 lg:grid-cols-2">
        <SideCard side={left} label={t("compare.sideA")} />
        <SideCard side={right} label={t("compare.sideB")} />
      </div>

      <div className="mt-3 flex gap-1 text-xs" role="tablist">
        {DIMENSIONS.map((item) => (
          <button
            key={item}
            type="button"
            role="tab"
            aria-selected={dimension === item}
            onClick={() => onDimension(item)}
            className={`rounded border px-2 py-1 ${dimension === item ? "border-accent text-ink" : "border-line text-ink-soft"}`}
          >
            {t(`compare.dim.${item}`)}
          </button>
        ))}
      </div>

      <div className="mt-3 grid gap-3 lg:grid-cols-3" data-na="compare">
        {(["onlyA", "shared", "onlyB"] as const).map((column) => (
          <section key={column} className="rounded border border-dashed border-line p-3 text-xs">
            <h2 className="font-medium">{t(`compare.col.${column}`)}</h2>
            <p className="mt-2 text-ink-faint">
              <EvidenceBadge level="NA" /> {t("compare.apiNa")}
            </p>
          </section>
        ))}
      </div>
      <p className="mt-2 text-[11px] text-ink-faint">{t("compare.noVerdict")}</p>
    </div>
  );
}

/**
 * Where the session ran. The session list leaves `platform` off (it is a column
 * of the session row, not of the list item), so an empty string is "not sent",
 * shown as 「不可得」 — never a blank after the colon.
 */
export function platformText(session: Pick<Session, "platform" | "os_version">, unavailable: string): string {
  const platform = session.platform.trim();
  if (!platform) return unavailable;
  return session.os_version ? `${platform} ${session.os_version}` : platform;
}

/**
 * Capabilities as the Settings page words them: 「进程 可采，文件 / 网络 / DNS
 * 没采」. Kinds the collectors list only as NA are "not collected", not extra
 * capabilities. No capability list at all is 「不可得」.
 */
export function capabilityText(
  session: Pick<Session, "collectors">,
  t: (key: string, vars?: Record<string, string | number>) => string,
): string {
  if (capabilitiesUnknown(session)) return t("common.unavailable");
  const kinds = [...new Set(session.collectors.flatMap((collector) => collector.capabilities.map((item) => item.kind)))];
  const collected = kinds.filter((kind) => coverage(session, kind) === "collected").map((kind) => kindInSentence(t, kind));
  const missing = uncollectedKinds(session).map((kind) => kindInSentence(t, kind));
  const parts: string[] = [];
  if (collected.length > 0) parts.push(`${collected.join(t("common.listSep"))} ${t("settings.capYes")}`);
  if (missing.length > 0) parts.push(`${missing.join(t("compare.kindSep"))} ${t("settings.capNo")}`);
  return parts.join(t("common.listSep"));
}

function SideCard({ side, label }: { side: CompareSide; label: string }) {
  const { t } = useI18n();
  const { session } = side;
  return (
    <section className="rounded border border-line p-3 text-xs">
      <h2 className="text-ink-faint">{label}</h2>
      <p className="mt-1 font-mono">
        <Link to="/s/$sid" params={{ sid: session.public_id }} search={{}} className="hover:underline">
          {session.public_id}
        </Link>
      </p>
      <p>{session.name ?? session.argv?.[0] ?? t("common.unavailable")}</p>
      <p className="text-ink-faint" data-platform="">
        {t("compare.platform")}{t("common.colon")}{platformText(session, t("common.unavailable"))}
        {session.agent ? ` · ${session.agent}` : ""}
      </p>
      <p className="mt-1 text-ink-faint" data-capabilities="">
        {t("compare.collectors")}{t("common.colon")}{capabilityText(session, t)}
      </p>
    </section>
  );
}

function capabilitiesDiffer(a: Session, b: Session): boolean {
  const left = new Set(a.collectors.flatMap((collector) => collector.capabilities.map((item) => `${item.kind}:${item.evidence}`)));
  const right = b.collectors.flatMap((collector) => collector.capabilities.map((item) => `${item.kind}:${item.evidence}`));
  if (left.size !== right.length) return true;
  return right.some((item) => !left.has(item));
}
