import { createRootRoute, Outlet, useRouterState } from "@tanstack/react-router";
import { SignIn } from "@/features/shell/SignIn";
import { useAuth } from "@/lib/auth";

export const Route = createRootRoute({
  component: Root,
});

function Root() {
  const { status } = useAuth();
  const path = useRouterState({ select: (state) => state.location.pathname });
  if (status !== "signed-in" && path !== "/settings") return <SignIn />;
  return <Outlet />;
}
