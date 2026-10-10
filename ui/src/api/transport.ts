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
 *
 * Commands the page calls in the app (interface in app/README.md):
 * - `aw_request {method, target, body?}` → `{status, body}`: JSON/text.
 * - `aw_request_bytes {method, target, body?}` → `{status, headers, body_base64}`:
 *   binary-safe, used for exports (the CSV export is a zip).
 * A rejected command's error text starts with `daemon_unreachable:` (nothing
 * is listening), `daemon_forbidden:` (the socket/pipe refused this OS user),
 * or anything else (the channel itself failed).
 */

type Invoke = (cmd: string, args?: Record<string, unknown>) => Promise<unknown>;

interface ChannelReply {
  status: number;
  body: string;
}

interface BytesReply {
  status: number;
  headers?: Record<string, string>;
  body_base64: string;
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
    return channelFailure(err);
  }
}

/**
 * The error a rejected app command becomes. `daemon_unreachable` (503) is the
 * only case the page calls "service not running"; a refused socket is
 * `daemon_forbidden` (403); anything else is `channel_error` (502).
 */
export function channelFailure(err: unknown): Response {
  const message = err instanceof Error ? err.message : String(err);
  const [code, status]: [string, number] = message.startsWith("daemon_unreachable")
    ? ["daemon_unreachable", 503]
    : message.startsWith("daemon_forbidden")
      ? ["daemon_forbidden", 403]
      : ["channel_error", 502];
  return new Response(JSON.stringify({ error: { code, message } }), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function decodeBase64(text: string): Uint8Array {
  const binary = atob(text);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

/**
 * Like {@link send}, but the body is never decoded as text, so a zip survives.
 * In a browser this is the same `fetch`; in the app it uses `aw_request_bytes`.
 */
export async function sendBytes(url: string, init: RequestInit & { method: string }): Promise<Response> {
  const invoke = tauriInvoke();
  if (!invoke) return fetch(url, init);
  try {
    const reply = (await invoke("aw_request_bytes", {
      method: init.method,
      target: url,
      body: bodyText(init.body),
    })) as BytesReply;
    const bytes = decodeBase64(reply.body_base64 ?? "");
    return new Response(bytes.byteLength ? (bytes as unknown as BodyInit) : null, {
      status: reply.status,
      headers: reply.headers ?? {},
    });
  } catch (err) {
    return channelFailure(err);
  }
}
