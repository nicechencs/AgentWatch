import { isDesktop } from "@/api/transport";
import { useAuth } from "@/lib/auth";
import { useI18n } from "@/lib/i18n";

export function SignIn() {
  const { t } = useI18n();
  const { status, error, retry } = useAuth();
  if (isDesktop()) {
    // The desktop window never asks for a ticket. Only an unreachable channel
    // is "not running"; a refused channel and a daemon error say so plainly.
    return (
      <main className="mx-auto mt-24 max-w-md px-4">
        <h1 className="text-lg font-semibold">{t("app.name")}</h1>
        {status === "unreachable" ||
        status === "forbidden" ||
        status === "busy" ||
        status === "timeout" ||
        status === "broken" ||
        status === "failed" ? (
          <>
            {status === "unreachable" ? (
              <>
                <p className="mt-3 text-sm">{t("auth.serviceDown")}</p>
                <p className="mt-1 text-xs text-ink-soft">{t("auth.serviceDownBody")}</p>
              </>
            ) : status === "forbidden" ? (
              <>
                <p className="mt-3 text-sm">{t("auth.forbidden")}</p>
                <p className="mt-1 text-xs text-ink-soft">{t("auth.forbiddenBody")}</p>
              </>
            ) : status === "busy" ? (
              <p className="mt-3 text-sm">{t("auth.busy")}</p>
            ) : status === "timeout" ? (
              <p className="mt-3 text-sm">{t("auth.timeout")}</p>
            ) : status === "broken" ? (
              <p className="mt-3 text-sm">{t("auth.broken", { reason: error ?? "" })}</p>
            ) : (
              <p className="mt-3 text-sm">{t("auth.daemonError", { reason: error ?? "" })}</p>
            )}
            <button type="button" className="mt-3 rounded border border-line px-2 py-1 text-xs" onClick={retry}>
              {t("auth.retry")}
            </button>
          </>
        ) : (
          <p className="mt-3 text-sm">{t("auth.connecting")}</p>
        )}
      </main>
    );
  }
  return (
    <main className="mx-auto mt-24 max-w-md px-4">
      <h1 className="text-lg font-semibold">{t("app.name")}</h1>
      <p className="mt-3 text-sm">{status === "checking" ? t("auth.exchanging") : t("auth.title")}</p>
      <p className="mt-1 text-xs text-ink-soft">{t("auth.body")}</p>
      {error ? <p className="mt-2 text-xs text-amber-700 dark:text-amber-400">{t("auth.failed")}</p> : null}
    </main>
  );
}
