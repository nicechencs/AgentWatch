# AgentWatch desktop app (`aw-desktop`)

Tauri 2 window over the bundled `ui/dist` (ADR-0002, 2026-10-10 revision).

- `agentwatchd` keeps running in the background (as root / LocalSystem in a
  normal install). This app runs as the ordinary user and talks to it only on
  the internal channel. No port is opened and there is no sign-in: the daemon
  identifies the OS user from the socket peer uid / pipe client token.
- Only `/health` and `/api/v1/*` are forwarded (`src-tauri/src/channel.rs`).
- The client is the shared crate `crates/aw-channel`, the same one `aw` uses,
  so path order, error codes, pipe-busy retry and timeouts are identical.

## Where the channel is

Same order in the daemon, `aw`, and the app (`aw_channel::candidates`):

| OS | 1st (system daemon) | 2nd (daemon run as a normal user) |
|---|---|---|
| Linux | `/run/agentwatch/api.sock` | `$XDG_RUNTIME_DIR/agentwatch/api.sock`, else `$HOME/.local/state/agentwatch/api.sock` |
| macOS | `/var/run/agentwatch/api.sock` | `$HOME/Library/Application Support/AgentWatch/api.sock` |
| Windows | `\\.\pipe\agentwatch-api` | — |

`AW_SOCKET` overrides all of them. Clients dial the first candidate that
exists. Access:

- Linux/macOS: if a group `agentwatch` exists the socket is
  `root:agentwatch 0660`; otherwise `0666`. Every request is still tied to
  the peer uid: an ordinary user sees only their own sessions; root is admin.
- Windows: the pipe DACL grants SYSTEM, Administrators and the pipe owner full
  control, and `AgentWatch Users` (or, if that group does not exist,
  interactive users) read/write without create-instance. Admin = the client
  token is elevated or LocalSystem.

## Page ↔ shell interface

The page (`ui/src/api/transport.ts`, `client.ts`) uses four commands.

All of them go to one daemon: the first path in the dial order that answers
(`AW_SOCKET`, else system socket, then the per-user one) is kept for the life
of the window. The order is walked again only after that path stops answering
(not found / refused). Resolving per request let one window talk to two
daemons when another daemon's socket appeared or vanished, so a page could get
"session not found" for a session the user's own daemon holds.

### `aw_request`

```ts
invoke('aw_request', { method: 'GET', target: '/api/v1/sessions?limit=50', body?: string })
  -> Promise<{
       status: number,                       // HTTP status from the daemon
       headers: Record<string, string>,      // names lowercased
       body: string,                         // body as UTF-8 text (JSON routes)
       body_base64: string,                  // exact body bytes (zip / CSV export)
     }>
```

Rejects with `{ code, message, detail }`: `message` is one plain Chinese
sentence for a person (no paths, no OS error text; show it as is), `detail`
is the technical part (paths tried, OS error kind) for a collapsible
"details" field. Every call re-runs the socket lookup (system path, then
per-user; only not-found / refused falls through), so Retry is just calling
again:

| `code` | meaning | suggested UI |
|---|---|---|
| `daemon_unreachable` | no socket/pipe, or connection refused | "AgentWatch service is not running" + retry |
| `daemon_forbidden` | the service runs, this account may not connect | "No permission to connect to the service" (ask admin to add you to `agentwatch` / `AgentWatch Users`) |
| `daemon_busy` | every pipe instance stayed busy for 2 s | retry shortly |
| `daemon_timeout` | no full answer within 30 s | retry |
| `channel_broken` | the exchange broke or did not parse | error |
| `refused` | the app will not send this (path/method/body size) | bug |

Each call runs on its own thread; a large export does not block other calls.

### `aw_save_export`

```ts
invoke('aw_save_export', { sid: 's-1', format: 'jsonl' | 'csv' | 'md', tz?: number /* minutes east of UTC */ })
  -> Promise<{
       status: number,              // export request status
       path: string | null,         // where the file was written
       cancelled: boolean,          // the user closed the dialog
       error_body: string | null,   // daemon JSON error when status is not 2xx
       bytes: number,
     }>
```

The shell fetches `/api/v1/sessions/{sid}/export?format=…` on the channel. A
daemon error comes back without opening a dialog. Otherwise the native "Save
As" dialog (`tauri-plugin-dialog`, capability `dialog:allow-save`) opens in the
user's Downloads folder (home if there is none; never the launch directory) with
the daemon's file name (`agentwatch-<sid>.jsonl`, `.csv.zip`, `.md`); the exact
bytes are written to the chosen path and the page shows "已保存到 <path>".
A browser keeps the normal download. Rejects with `{ code, message }` as
above, plus `write_failed`. The dialog itself needs a real window to verify;
the fetch / name / write steps are unit-tested in `src/export.rs`.

### `aw_stream_open` / `aw_stream_close`

The live stream goes over the channel too.

```ts
import { Channel, invoke } from '@tauri-apps/api/core'
const onEvent = new Channel<StreamEvent>()
onEvent.onmessage = (ev) => { ... }
const id: number = await invoke('aw_stream_open', {
  target: '/api/v1/sessions/s-1/live?filter=...',   // only .../sessions/{id}/live
  onEvent,
})
// later
await invoke('aw_stream_close', { id })

type StreamEvent =
  | { kind: 'event', id: string | null, event: string, data: string }
      // event = SSE event name: 'record' (data = record JSON), 'lagged', ...
  | { kind: 'error', code: string, message: string, detail: string, status: number | null }
      // code as in the table above, or 'http_<status>'. On 403/404 the stream
      // ends; otherwise it retries after 2 s.
```

The shell polls the daemon's SSE snapshot route with `cursor=<last id>` at the
`retry:` interval (1 s) and pushes each event; no event is dropped between
polls. `aw_stream_open` rejects with `{ code: 'refused' }` for another target.

## Run

The crate has its own `[workspace]` and is **not** a member of the root
workspace, so `cargo test --workspace` at the repository root does not need
the WebView libraries. CI (`.github/workflows/desktop.yml`) builds it on all
three OSes for pull requests and pushes to `dev` / `main`.

```bash
# Linux only: WebView libraries
sudo apt-get install -y libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev libsoup-3.0-dev
```

### Normal / production build — bundled pages

`custom-protocol` is a **default feature**, so every normal build serves the
bundled `ui/dist` (never the dev server). A release build without it does not
compile (`compile_error!` in `main.rs`), and `cargo test` checks the default.

```bash
pnpm -C ui install && pnpm -C ui build      # produces ui/dist, which is embedded
cd app/src-tauri
cargo test
cargo run                                   # window with the bundled pages
cargo build --release                       # target/release/aw-desktop
# or, with the Tauri CLI: cargo tauri build (installers are P4)
```

### Development — live reload with Vite

```bash
pnpm -C ui dev                              # Vite on http://localhost:5173
cd app/src-tauri
cargo run --no-default-features             # window loads devUrl (localhost:5173)
```

### Against an unprivileged daemon

A daemon started as a normal user binds the per-user socket by itself, and the
app finds it there. To pin one explicit path instead:

```bash
AW_SOCKET=/tmp/aw/api.sock agentwatchd --foreground --config <dev config>
AW_SOCKET=/tmp/aw/api.sock cargo run
```

Not in this package: installers, signing, auto-update (P4).
