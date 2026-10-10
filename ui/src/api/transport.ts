/**
 * Where API requests go (ADR-0002, 2026-10-10 revision).
 *
 * In the desktop app (Tauri window) the page has no port to call. Requests are
 * handed to the app process with the `aw_request` command, which forwards them
 * to agentwatchd on the internal channel (Unix socket / named pipe). The
 * daemon identifies the OS user; there is no token and no sign-in.
 *
 * In a browser (development, or `aw ui`) requests stay same-origin `fetch`.
 *
 * Both paths return a standard `Response`, so `client.ts` handles status and
 * JSON the same way.
 */

type Invoke = (cmd: string, args?: Record<string, unknown>) => Promise<unknown>;

interface ChannelReply {
  status: number;
  body: string;
}

function tauriInvoke(): Invoke | null {
  if (typeof window === "undefined") return null;
  const internals = (window as unknown as { __TAURI_INTERNALS__?: { invoke?: Invoke } })
    .__TAURI_INTERNALS__;
  return typeof internals?.invoke === "function" ? internals.invoke : null;
}

/** True inside the desktop app window. Sign-in is not needed there. */
export function isDesktop(): boolean {
  return tauriInvoke() !== null;
}

function bodyText(body: RequestInit["body"]): string | undefined {
  if (body === undefined || body === null) return undefined;
  if (typeof body === "string") return body;
  throw new Error("desktop transport sends JSON text bodies only");
}

/**
 * Send one request. `url` is the same-origin path (`/api/v1/...?...`).
 * In the desktop app a failure to reach the daemon becomes status 503 with
 * `{"error":{"code":"daemon_unreachable",...}}`, so the page can say the
 * service is not running instead of failing silently.
 */
export async function send(url: string, init: RequestInit & { method: string }): Promise<Response> {
  const invoke = tauriInvoke();
  if (!invoke) return fetch(url, init);
  try {
    const reply = (await invoke("aw_request", {
      method: init.method,
      target: url,
      body: bodyText(init.body),
    })) as ChannelReply;
    const nullBody = reply.status === 204 || reply.status === 304;
    return new Response(nullBody ? null : reply.body, {
      status: reply.status,
      headers: { "content-type": "application/json" },
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    const code = message.startsWith("daemon_unreachable") ? "daemon_unreachable" : "channel_error";
    return new Response(JSON.stringify({ error: { code, message } }), {
      status: 503,
      headers: { "content-type": "application/json" },
    });
  }
}
