import { useState } from "react";
import { describeError } from "@/api/errors";
import { useI18n } from "@/lib/i18n";

/**
 * Router-level fallback for a page that threw while rendering. Replaces the
 * router's English "Something went wrong!" with a sentence the user can act
 * on and a way back to the session list. This is a last resort: pages handle
 * their own data errors and must not rely on it.
 */
export function AppError({ error }: { error: unknown }) {
  const { t } = useI18n();
  const [open, setOpen] = useState(false);
  const detail = error instanceof Error ? error.message : String(error ?? "");
  return (
    <main className="mx-auto mt-24 max-w-md px-4" role="alert">
      <h1 className="text-lg font-semibold">{t("error.page.title")}</h1>
      <p className="mt-2 text-sm text-ink-soft">{t("error.page.body")}</p>
      <div className="mt-3 flex gap-2 text-xs">
        <a href="/" className="rounded bg-ink px-2 py-1 text-paper">{t("error.page.home")}</a>
        <button type="button" onClick={() => setOpen((v) => !v)} className="rounded border border-line px-2 py-1">
          {open ? t("error.page.hideDetail") : t("error.page.showDetail")}
        </button>
      </div>
      {open ? <pre className="mt-2 whitespace-pre-wrap break-all text-[11px] text-ink-faint">{describeError(error, t) || detail}</pre> : null}
    </main>
  );
}

export function NotFoundPage() {
  const { t } = useI18n();
  return (
    <main className="mx-auto mt-24 max-w-md px-4">
      <h1 className="text-lg font-semibold">{t("error.notFoundPage")}</h1>
      <a href="/" className="mt-3 inline-block rounded bg-ink px-2 py-1 text-xs text-paper">{t("error.page.home")}</a>
    </main>
  );
}
