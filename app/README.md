# AgentWatch desktop app (`aw-desktop`)

Tauri 2 window over the bundled `ui/dist` (ADR-0002, 2026-10-10 revision).

- `agentwatchd` keeps running privileged in the background. This app runs as
  the ordinary user and talks to it only on the internal channel: Unix socket
  `/run/agentwatch/api.sock` (Linux), `/var/run/agentwatch/api.sock` (macOS),
  named pipe `\\.\pipe\agentwatch-api` (Windows). `AW_SOCKET` overrides the path.
- No port is opened and there is no sign-in: the daemon identifies the OS user
  from the socket peer.
- The page calls the `aw_request` command (`src-tauri/src/main.rs`); only
  `/health` and `/api/v1/*` are forwarded (`src-tauri/src/channel.rs`).
- Frontend side: `ui/src/api/transport.ts` picks the Tauri command inside the
  app window and same-origin `fetch` in a browser.

## Build

The crate has its own `[workspace]` and is **not** a member of the root
workspace, so `cargo test --workspace` at the repository root does not need the
WebView libraries. CI builds it in `.github/workflows/desktop.yml` on all three
OSes.

```bash
# Linux only: WebView libraries
sudo apt-get install -y libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev libsoup-3.0-dev

pnpm -C ui install && pnpm -C ui build      # app bundles ui/dist
cd app/src-tauri
cargo test                                  # channel unit tests
cargo run                                   # opens the window
```

For an unprivileged development run, start the daemon and the app on the same
socket:

```bash
AW_SOCKET=/tmp/aw/api.sock agentwatchd --foreground --config <dev config>
AW_SOCKET=/tmp/aw/api.sock cargo run
```

Not in this package: installers, signing, auto-update (P4). On Windows the
daemon's pipe keeps the default DACL, so only an elevated (administrator) app
can open it today; an ordinary user sees `daemon_unreachable` until the
`AgentWatch Users` DACL lands.
