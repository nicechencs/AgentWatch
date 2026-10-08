import { createRoute, createRouter, redirect } from "@tanstack/react-router";
import type { SessionQuery } from "@/lib/session-query";
import { Route as RootRoute } from "@/routes/root";
import { AppShell } from "@/features/shell/AppShell";
import { SessionLayout } from "@/features/shell/SessionLayout";
import { SessionsPage } from "@/features/sessions/SessionsPage";
import { NewSessionPage } from "@/features/sessions/NewSessionPage";
import { OverviewPage } from "@/features/overview/OverviewPage";
import { TimelinePage } from "@/features/timeline/TimelinePage";
import { ProcessesPage } from "@/features/processes/ProcessesPage";
import { FilesPage } from "@/features/files/FilesPage";
import { NetworkPage } from "@/features/network/NetworkPage";
import { GapsPage } from "@/features/gaps/GapsPage";
import { FindingsPage } from "@/features/findings/FindingsPage";
import { SettingsPage } from "@/features/settings/SettingsPage";
import { SearchPage } from "@/features/search/SearchPage";

const text = (value: unknown) => (typeof value === "string" ? value : undefined);

/** All keys stay optional so links only carry the filters they set. */
const search = (raw: Record<string, unknown>): Partial<SessionQuery> => ({
  f: text(raw.f),
  from: text(raw.from),
  to: text(raw.to),
  ev: text(raw.ev),
  subtree: text(raw.subtree),
  proc: text(raw.proc),
});

const shellRoute = createRoute({
  getParentRoute: () => RootRoute,
  id: "shell",
  component: AppShell,
});

const indexRoute = createRoute({
  getParentRoute: () => shellRoute,
  path: "/",
  component: SessionsPage,
});

const newRoute = createRoute({
  getParentRoute: () => shellRoute,
  path: "/new",
  component: NewSessionPage,
});

const searchRoute = createRoute({
  getParentRoute: () => shellRoute,
  path: "/search",
  validateSearch: (raw: Record<string, unknown>) => ({
    q: text(raw.q),
    kind: text(raw.kind),
  }),
  component: SearchPage,
});

const settingsRoute = createRoute({
  getParentRoute: () => shellRoute,
  path: "/settings",
  component: SettingsPage,
});

const sessionRoute = createRoute({
  getParentRoute: () => RootRoute,
  path: "/s/$sid",
  validateSearch: search,
  component: SessionLayout,
});

const overviewRoute = createRoute({
  getParentRoute: () => sessionRoute,
  path: "/",
  component: OverviewPage,
});

const timelineRoute = createRoute({
  getParentRoute: () => sessionRoute,
  path: "/timeline",
  component: TimelinePage,
});

const processesRoute = createRoute({
  getParentRoute: () => sessionRoute,
  path: "/processes",
  component: ProcessesPage,
});

const filesRoute = createRoute({
  getParentRoute: () => sessionRoute,
  path: "/files",
  component: FilesPage,
});

const networkRoute = createRoute({
  getParentRoute: () => sessionRoute,
  path: "/network",
  component: NetworkPage,
});

const gapsRoute = createRoute({
  getParentRoute: () => sessionRoute,
  path: "/gaps",
  component: GapsPage,
});

const findingsRoute = createRoute({
  getParentRoute: () => sessionRoute,
  path: "/findings",
  component: FindingsPage,
});

// Pages owned by later phases: present in the information architecture, but
// not built here. They redirect to the overview so a shared link still lands.
const laterRoute = createRoute({
  getParentRoute: () => sessionRoute,
  path: "/$rest",
  beforeLoad: ({ params }) => {
    throw redirect({ to: "/s/$sid", params: { sid: params.sid }, search: {} });
  },
  component: () => null,
});

const routeTree = RootRoute.addChildren([
    shellRoute.addChildren([indexRoute, newRoute, searchRoute, settingsRoute]),
    sessionRoute.addChildren([
      overviewRoute,
      timelineRoute,
      processesRoute,
      filesRoute,
      networkRoute,
      findingsRoute,
      gapsRoute,
      laterRoute,
    ]),
  ]);

export const router = createRouter({
  routeTree,
  defaultPreload: "intent",
});

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
