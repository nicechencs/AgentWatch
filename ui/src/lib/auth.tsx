import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { api, getToken, setToken } from "@/api/client";
import { isDesktop } from "@/api/transport";
import { isApiError } from "@/api/errors";
import type { Me } from "@/api/types";

/** `unreachable`: desktop app only, the daemon did not answer on the internal channel. */
type AuthStatus = "checking" | "anonymous" | "signed-in" | "unreachable";

interface AuthValue {
  status: AuthStatus;
  me: Me | null;
  error: string | null;
  /** Check again (desktop: after the service was started). */
  retry: () => void;
}

const AuthContext = createContext<AuthValue>({ status: "checking", me: null, error: null, retry: () => {} });

export function useAuth(): AuthValue {
  return useContext(AuthContext);
}

/** Paths that only exist as files. The router knows them as `/`. */
const LANDING_PATHS = new Set(["/index.html"]);

/**
 * Take the one-time ticket out of the URL fragment (#ticket=...) and clean the
 * address bar in the same step: the fragment is dropped, and a file landing
 * path such as `/index.html` (where the preview redirect lands) becomes `/`,
 * so the router renders the app instead of Not Found.
 *
 * Returns the ticket, or null when the URL has none. Call it once per page
 * load; the second call sees a clean URL and returns null.
 */
export function takeTicketFromLocation(): string | null {
  const fragment = new URLSearchParams(window.location.hash.replace(/^#/, ""));
  const ticket = fragment.get("ticket");
  const url = new URL(window.location.href);
  const landing = LANDING_PATHS.has(url.pathname);
  if (!ticket && !landing) return null;
  if (landing) url.pathname = "/";
  if (ticket) url.hash = "";
  window.history.replaceState(null, "", url);
  return ticket || null;
}

/**
 * One exchange per page load, shared by every mount. React StrictMode runs an
 * effect, cleans it up and runs it again; reading the fragment inside the
 * effect let the first run spend the ticket and the second run find nothing,
 * which showed "invalid or expired" for a ticket that had just worked.
 */
let pending: Promise<string> | null = null;

/**
 * Read at module load, before the router is created: the router would
 * otherwise see `/index.html`, redirect to `/`, and drop the fragment before
 * any effect could read the ticket.
 */
let startupTicket: string | null = takeTicketFromLocation();

function exchangeOnce(ticket: string): Promise<string> {
  if (!pending) {
    pending = api.exchangeTicket(ticket).then(({ token }) => {
      setToken(token);
      return token;
    });
  }
  return pending;
}

/** Tests only: forget the shared exchange between cases. */
export function resetAuthForTests(): void {
  pending = null;
  startupTicket = null;
}

/**
 * Reads the ticket, swaps it for a token, then keeps that token for this tab
 * (see `setToken`). A reload in the same tab reuses the token instead of
 * asking for a ticket that was already spent (P2-UI-01).
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

  const [attempt, setAttempt] = useState(0);
  const retry = useCallback(() => {
    setStatus("checking");
    setAttempt((n) => n + 1);
  }, []);

  useEffect(() => {
    let cancelled = false;
    if (isDesktop()) {
      // The desktop window talks to the daemon over the internal channel; the
      // daemon names the OS user. No ticket, no token, no sign-in screen.
      loadMe()
        .then(() => {
          if (!cancelled) setStatus("signed-in");
        })
        .catch((caught: unknown) => {
          if (cancelled) return;
          setError(caught instanceof Error ? caught.message : "daemon_unreachable");
          setStatus("unreachable");
        });
      return () => {
        cancelled = true;
      };
    }
    const ticket = startupTicket ?? takeTicketFromLocation();
    startupTicket = null;
    const ready: Promise<unknown> | null = ticket ? exchangeOnce(ticket) : pending;
    if (ready) {
      ready
        .then(async () => {
          if (cancelled) return;
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
  }, [loadMe, attempt]);

  const value = useMemo(() => ({ status, me, error, retry }), [status, me, error, retry]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
