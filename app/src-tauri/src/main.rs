//! AgentWatch desktop app (ADR-0002, 2026-10-10 revision).
//!
//! One window over the bundled `ui/dist`. The page calls the commands below;
//! this process forwards them to `agentwatchd` on the internal channel
//! ([`channel`]). The app opens no port and holds no token. The interface is
//! written down in `app/README.md` ("Page ↔ shell interface").

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// A release build that served the dev server would show a blank window on
// every user's machine. `custom-protocol` is a default feature; only a dev run
// (`cargo run --no-default-features` against Vite) turns it off.
#[cfg(all(not(debug_assertions), not(feature = "custom-protocol")))]
compile_error!(
    "release builds must enable the `custom-protocol` feature so the window loads the bundled ui/dist"
);

mod channel;
mod stream;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use channel::Failure;
use tauri::ipc::Channel;

fn channel_path() -> std::path::PathBuf {
    channel::channel_path(&|key| std::env::var(key).ok())
}

/// Forward one API request to the daemon. `target` is the path plus query.
/// Each call runs on its own blocking thread: a large export does not hold up
/// other requests.
///
/// The reply carries the body twice: `body` (UTF-8 text, for JSON) and
/// `body_base64` (exact bytes, for downloads). A failure is
/// `{ code, message }`, see [`Failure`].
#[tauri::command]
async fn aw_request(
    method: String,
    target: String,
    body: Option<String>,
) -> Result<channel::Reply, Failure> {
    let path = channel_path();
    let body = body.unwrap_or_default();
    tauri::async_runtime::spawn_blocking(move || channel::exchange(&path, &method, &target, &body))
        .await
        .map_err(|err| Failure {
            code: "channel_broken".to_owned(),
            message: format!("request task failed: {err}"),
        })?
}

/// Open streams, by id. Only the registry is locked, never a request.
#[derive(Default)]
struct Streams {
    next: AtomicU64,
    open: Mutex<HashMap<u64, Arc<AtomicBool>>>,
}

/// Start a live stream. Events arrive on `on_event` as
/// [`stream::StreamEvent`]; returns the id to pass to `aw_stream_close`.
#[tauri::command]
fn aw_stream_open(
    target: String,
    on_event: Channel<stream::StreamEvent>,
    streams: tauri::State<'_, Streams>,
) -> Result<u64, Failure> {
    stream::check_target(&target)?;
    let id = streams.next.fetch_add(1, Ordering::SeqCst) + 1;
    let closed = Arc::new(AtomicBool::new(false));
    if let Ok(mut open) = streams.open.lock() {
        open.insert(id, Arc::clone(&closed));
    }
    let path = channel_path();
    std::thread::Builder::new()
        .name(format!("aw-live-{id}"))
        .spawn(move || {
            let mut send = |event| on_event.send(event).is_ok();
            stream::run(&path, &target, &closed, &mut send, std::thread::sleep);
        })
        .map_err(|err| Failure {
            code: "channel_broken".to_owned(),
            message: format!("stream thread: {err}"),
        })?;
    Ok(id)
}

/// Stop a stream. Unknown ids are ignored.
#[tauri::command]
fn aw_stream_close(id: u64, streams: tauri::State<'_, Streams>) {
    if let Ok(mut open) = streams.open.lock() {
        if let Some(flag) = open.remove(&id) {
            flag.store(true, Ordering::SeqCst);
        }
    }
}

fn main() {
    let result = tauri::Builder::default()
        .manage(Streams::default())
        .invoke_handler(tauri::generate_handler![
            aw_request,
            aw_stream_open,
            aw_stream_close
        ])
        .run(tauri::generate_context!());
    if let Err(err) = result {
        eprintln!("aw-desktop: {err}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    /// T1: a normal build (default features) loads the bundled pages.
    #[test]
    fn default_build_serves_the_bundled_ui() {
        const {
            assert!(
                cfg!(feature = "custom-protocol"),
                "default features must include custom-protocol"
            );
        }
    }
}
