//! AgentWatch desktop app (ADR-0002, 2026-10-10 revision).
//!
//! One window over the bundled `ui/dist`. The page calls the `aw_request`
//! command; this process forwards it to `agentwatchd` on the internal channel
//! ([`channel`]). The app opens no port and holds no token.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod channel;

/// Forward one API request to the daemon. `target` is the path plus query.
///
/// Errors are strings for the page: `daemon_unreachable: …` means the service
/// is not running or this user may not open the socket or pipe.
#[tauri::command]
async fn aw_request(
    method: String,
    target: String,
    body: Option<String>,
) -> Result<channel::Reply, String> {
    let path = channel::channel_path(std::env::var(channel::AW_SOCKET).ok());
    let body = body.unwrap_or_default();
    tauri::async_runtime::spawn_blocking(move || {
        channel::exchange(&path, &method, &target, &body).map_err(|err| err.to_string())
    })
    .await
    .map_err(|err| format!("channel_broken: {err}"))?
}

fn main() {
    let result = tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![aw_request])
        .run(tauri::generate_context!());
    if let Err(err) = result {
        eprintln!("aw-desktop: {err}");
        std::process::exit(1);
    }
}
