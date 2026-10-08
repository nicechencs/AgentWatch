import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { api, getToken, setToken } from "@/api/client";
import { isApiError } from "@/api/errors";
import type { Me } from "@/api/types";

type AuthStatus = "checking" | "anonymous" | "signed-in";

interface AuthValue {
  status: AuthStatus;
  me: Me | null;
  error: string | null;
}

const AuthContext = createContext<AuthValue>({ status: "checking", me: null, error: null });

export function useAuth(): AuthValue {
  return useContext(AuthContext);
}

/**
 * Reads the one-time ticket from the URL fragment (#ticket=...), swaps it for a
 * token kept in memory, then strips the fragment. A reload has no ticket and no
 * stored token, so it returns to the signed-out state (P2-UI-01).
 */
export function AuthProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<AuthStatus>(getToken() ? "signed-in" : "checking");
  const [me, setMe] = useState<Me | null>(null);
  const [error, setError] = useState<string | null>(null);

  const loadMe = useCallback(async () => {
    try {
      setMe(await api.me());
    } catch (caught) {
      if (isApiError(caught) && caught.status === 404) {
        setMe({ user_id: "", admin: false });
        return;
      }
      throw caught;
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    const fragment = new URLSearchParams(window.location.hash.replace(/^#/, ""));
    const ticket = fragment.get("ticket");
    if (ticket) {
      const url = new URL(window.location.href);
      url.hash = "";
      window.history.replaceState(null, "", url);
      api
        .exchangeTicket(ticket)
        .then(async ({ token }) => {
          if (cancelled) return;
          setToken(token);
          await loadMe();
          if (!cancelled) setStatus("signed-in");
        })
        .catch((caught: unknown) => {
          if (cancelled) return;
          setToken(null);
          setError(caught instanceof Error ? caught.message : "ticket");
          setStatus("anonymous");
        });
      return () => {
        cancelled = true;
      };
    }
    if (getToken()) {
      loadMe()
        .then(() => {
          if (!cancelled) setStatus("signed-in");
        })
        .catch(() => {
          if (cancelled) return;
          setToken(null);
          setStatus("anonymous");
        });
    } else {
      setStatus("anonymous");
    }
    return () => {
      cancelled = true;
    };
  }, [loadMe]);

  const value = useMemo(() => ({ status, me, error }), [status, me, error]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
