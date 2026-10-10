import { createRootRoute, Outlet, useRouterState } from "@tanstack/react-router";
import { SignIn } from "@/features/shell/SignIn";
import { useAuth } from "@/lib/auth";

export const Route = createRootRoute({
  component: Root,
});

function Root() {
  const { status } = useAuth();
  const path = useRouterState({ select: (state) => state.location.pathname });
  // In the desktop app nothing works without the daemon, settings included.
  if (status === "unreachable" || (status !== "signed-in" && path !== "/settings")) return <SignIn />;
  return <Outlet />;
}
