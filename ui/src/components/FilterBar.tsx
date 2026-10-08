import { useEffect, useRef, useState } from "react";
import { checkFilter } from "@/lib/filter";
import { useI18n } from "@/lib/i18n";
import { EVIDENCE, selectedEvidence, type SessionQuery } from "@/lib/session-query";

interface Props {
  query: SessionQuery;
  patch: (next: Partial<SessionQuery>) => void;
}

/** Shared filter row: expression, syntax hint, evidence switches (ui §2). */
export function FilterBar({ query, patch }: Props) {
  const { t } = useI18n();
  const input = useRef<HTMLInputElement>(null);
  const [draft, setDraft] = useState(query.f);
  const issue = draft.trim() ? checkFilter(draft) : null;
  const active = selectedEvidence(query.ev);

  useEffect(() => setDraft(query.f), [query.f]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== "/" || event.metaKey || event.ctrlKey || event.altKey) return;
      const target = event.target as HTMLElement | null;
      if (target && (target.tagName === "INPUT" || target.tagName === "TEXTAREA")) return;
      event.preventDefault();
      input.current?.focus();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const commit = () => {
    if (draft !== query.f) patch({ f: draft });
  };

  const toggle = (level: (typeof EVIDENCE)[number]) => {
    const next = new Set(active);
    if (next.has(level)) next.delete(level);
    else next.add(level);
    patch({ ev: next.size === EVIDENCE.length ? "" : [...next].join(",") });
  };

  return (
    <div className="flex flex-wrap items-start gap-2 border-b border-line px-3 py-2">
      <div className="min-w-64 flex-1">
        <input
          ref={input}
          value={draft}
          placeholder={t("filter.placeholder")}
          aria-invalid={issue ? true : undefined}
          onChange={(event) => setDraft(event.target.value)}
          onBlur={commit}
          onKeyDown={(event) => {
            if (event.key === "Enter") commit();
            if (event.key === "Escape") input.current?.blur();
          }}
          className="w-full rounded border border-line bg-paper px-2 py-1 font-mono text-xs outline-none focus:border-accent"
        />
        {issue ? (
          <p className="mt-1 text-xs text-amber-700 dark:text-amber-400">
            {t("filter.errorAt", { column: issue.column, message: issue.message })}
            {issue.suggestion ? ` ${t("filter.suggestion", { field: issue.suggestion })}` : ""}
          </p>
        ) : null}
      </div>
      <div className="flex gap-1">
        {EVIDENCE.map((level) => (
          <button
            key={level}
            type="button"
            aria-pressed={active.has(level)}
            onClick={() => toggle(level)}
            className={`rounded border px-1.5 py-0.5 text-[11px] ${
              active.has(level) ? "border-ink bg-ink text-paper" : "border-line text-ink-faint"
            }`}
          >
            {level === "I" ? t("evidence.I") : level}
          </button>
        ))}
      </div>
    </div>
  );
}
