import { Link, Outlet } from "@tanstack/react-router";
import { useI18n } from "@/lib/i18n";

/** Chrome for pages that are not inside a session. */
export function AppShell() {
  const { t } = useI18n();
  return (
    <div className="flex h-screen flex-col">
      <header className="flex items-center gap-4 border-b border-line px-4 py-2">
        <Link to="/" className="text-sm font-semibold">
          {t("app.name")}
        </Link>
        <nav className="flex gap-3 text-xs text-ink-soft">
          <Link to="/" activeOptions={{ exact: true }} activeProps={{ className: "text-xs text-ink" }}>
            {t("nav.sessions")}
          </Link>
          <Link to="/search" search={{ q: undefined, kind: undefined }} activeProps={{ className: "text-xs text-ink" }}>
            {t("nav.search")}
          </Link>
          <Link to="/settings" activeProps={{ className: "text-xs text-ink" }}>
            {t("nav.settings")}
          </Link>
        </nav>
      </header>
      <div className="min-h-0 flex-1 overflow-auto">
        <Outlet />
      </div>
    </div>
  );
}
