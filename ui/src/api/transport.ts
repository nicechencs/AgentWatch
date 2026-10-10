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
 * Commands the page calls in the app (app/README.md "Page ↔ shell interface"):
 * - `aw_request {method, target, body?}` → `{status, headers, body, body_base64}`.
 *   `body` for JSON, `body_base64` for exact bytes (the CSV export is a zip).
 * - `aw_stream_open {target, onEvent: Channel}` → id, `aw_stream_close {id}`: `/live`.
 * - `aw_save_export {sid, format}` → `{status, path, cancelled, error_body, bytes}`:
 *   the shell fetches the export, shows the native "Save As" dialog and writes
 *   the file there (a webview download link wrote into the launch directory).
 * A rejected command gives `{code, message, detail}` (`message` is plain
 * Chinese for the page; `detail` is technical, for a details field). Only `daemon_unreachable` means
 * the service is not running; `daemon_forbidden` is a permission problem.
 */

type Invoke = (cmd: string, args?: Record<string, unknown>) => Promise<unknown>;

interface ChannelReply {
  status: number;
  headers?: Record<string, string>;
  body: string;
  body_base64?: string;
}

function tauriInvoke(): Invoke | null {
  if (typeof window === "undefined") return null;
  const internals = (window as unknown as { __TAURI_INTERNALS__?: { invoke?: Invoke } })
    .__TAURI_INTERNALS__;
  return typeof internals?.invoke === "function" ? internals.invoke : null;
}

/** What `aw_save_export` answers. */
export interface SavedExport {
  status: number;
  path: string | null;
  cancelled: boolean;
  error_body: string | null;
  bytes: number;
}

/**
 * App only: export through the shell's "Save As" dialog. Returns null in a
 * browser (the caller downloads instead). A rejected command (daemon not
 * reachable, write failed) comes back as the same error {@link send} gives.
 */
export async function saveExportInApp(sid: string, format: string): Promise<SavedExport | Response | null> {
  const invoke = tauriInvoke();
  if (!invoke) return null;
  try {
    return (await invoke("aw_save_export", { sid, format })) as SavedExport;
  } catch (err) {
    return channelFailure(err);
  }
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
      headers: { "content-type": "application/json", ...(reply.headers ?? {}) },
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
/** `{code, message, detail?}` from a rejected command (older shells sent `"code: text"`). */
export function channelError(err: unknown): { code: string; message: string; detail?: string } {
  if (typeof err === "object" && err !== null && "code" in err) {
    const e = err as { code?: unknown; message?: unknown; detail?: unknown };
    const out: { code: string; message: string; detail?: string } = {
      code: String(e.code),
      message: typeof e.message === "string" ? e.message : String(e.code),
    };
    if (typeof e.detail === "string" && e.detail !== "") out.detail = e.detail;
    return out;
  }
  const message = err instanceof Error ? err.message : String(err);
  const prefix = /^([a-z_]+):/u.exec(message)?.[1];
  return { code: prefix ?? "channel_broken", message };
}

/** HTTP-like status for a channel error code, so callers branch the same way. */
const CHANNEL_STATUS: Record<string, number> = {
  daemon_unreachable: 503,
  daemon_forbidden: 403,
  daemon_busy: 503,
  daemon_timeout: 504,
  refused: 400,
};

export function channelFailure(err: unknown): Response {
  const error = channelError(err);
  const status = CHANNEL_STATUS[error.code] ?? 502;
  return new Response(JSON.stringify({ error }), {
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
 * In a browser this is the same `fetch`; in the app it reads `body_base64`.
 */
export async function sendBytes(url: string, init: RequestInit & { method: string }): Promise<Response> {
  const invoke = tauriInvoke();
  if (!invoke) return fetch(url, init);
  try {
    const reply = (await invoke("aw_request", {
      method: init.method,
      target: url,
      body: bodyText(init.body),
    })) as ChannelReply;
    const bytes = decodeBase64(reply.body_base64 ?? "");
    return new Response(bytes.byteLength ? (bytes as unknown as BodyInit) : null, {
      status: reply.status,
      headers: reply.headers ?? {},
    });
  } catch (err) {
    return channelFailure(err);
  }
}

/** One message of `aw_stream_open`'s channel. */
export type StreamEvent =
  | { kind: "event"; id: string | null; event: string; data: string }
  | { kind: "error"; code: string; message: string; status: number | null };

/**
 * App only: open the shell's `/live` stream. Returns a close function. In a
 * browser this returns null and the caller polls through {@link send}.
 */
export async function openStream(target: string, onEvent: (event: StreamEvent) => void): Promise<(() => void) | null> {
  const invoke = tauriInvoke();
  if (!invoke) return null;
  const { Channel } = await import("@tauri-apps/api/core");
  const channel = new Channel<StreamEvent>();
  channel.onmessage = onEvent;
  const id = (await invoke("aw_stream_open", { target, onEvent: channel })) as number;
  return () => {
    void invoke("aw_stream_close", { id }).catch(() => undefined);
  };
}
