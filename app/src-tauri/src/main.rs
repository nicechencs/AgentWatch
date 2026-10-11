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
mod export;
mod stream;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use channel::Failure;
use tauri::ipc::Channel;
use tauri::Manager;
use tauri_plugin_dialog::DialogExt;

/// The daemon this window is pinned to, else the documented lookup.
fn channel_path() -> std::path::PathBuf {
    channel::pinned_path(channel::channel_path(&|key| std::env::var(key).ok()))
}

/// Adds the desktop user's locale to a direct App launch request.
///
/// The daemon intentionally starts the child from a scrubbed account
/// environment.  Forward only these user-facing settings, never its complete
/// application environment (which could contain credentials or sockets).
fn launch_body_with_user_locale<F>(method: &str, target: &str, body: String, get: F) -> String
where
    F: Fn(&str) -> Option<String>,
{
    if method != "POST" || target.split('?').next() != Some("/api/v1/sessions") {
        return body;
    }
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(&body) else {
        return body;
    };
    if value.get("mode").and_then(serde_json::Value::as_str) != Some("launch") {
        return body;
    }
    let Some(request) = value.as_object_mut() else {
        return body;
    };
    let locale: Vec<(String, String)> = ["LANG", "LC_ALL", "TZ"]
        .into_iter()
        .filter_map(|name| get(name).map(|value| (name.to_owned(), value)))
        .collect();
    if locale.is_empty() {
        return body;
    }
    let env = request
        .entry("env".to_owned())
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    let Some(env) = env.as_object_mut() else {
        return body;
    };
    for (name, value) in locale {
        // The window, not arbitrary UI JSON, is authoritative for these
        // values: a direct App launch must use the desktop user's locale.
        env.insert(name, serde_json::Value::String(value));
    }
    serde_json::to_string(&value).unwrap_or(body)
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
    let body = launch_body_with_user_locale(&method, &target, body.unwrap_or_default(), |key| {
        std::env::var(key).ok()
    });
    tauri::async_runtime::spawn_blocking(move || channel::exchange(&path, &method, &target, &body))
        .await
        .map_err(|err| Failure::broken(&format!("request task failed: {err}")))?
}

/// Export a session to a file the user chooses (native "Save As").
///
/// Fetches `/sessions/{sid}/export?format=…` on the channel first, so a daemon
/// error is shown without opening a dialog; then asks where to save, writes
/// the exact bytes there and returns the path. Cancelling writes nothing.
/// The dialog itself needs a real window to verify.
#[tauri::command]
async fn aw_save_export(
    app: tauri::AppHandle,
    sid: String,
    format: String,
    tz: Option<i32>,
) -> Result<export::Saved, Failure> {
    let target = export::target(&sid, &format, tz)?;
    let path = channel_path();
    tauri::async_runtime::spawn_blocking(move || {
        let response = channel::exchange_response(&path, "GET", &target, "")?;
        if let Some(error) = export::daemon_error(&response) {
            return Ok(error);
        }
        let name = export::file_name(&sid, &format, response.header("content-disposition"));
        let mut dialog = app.dialog().file().set_file_name(&name);
        let paths = app.path();
        if let Some(dir) = export::default_dir(
            paths.download_dir().ok(),
            paths.home_dir().ok(),
            std::path::Path::is_dir,
        ) {
            dialog = dialog.set_directory(dir);
        }
        if let Some((label, extensions)) = export::filter(&format) {
            dialog = dialog.add_filter(label, &extensions);
        }
        let chosen = match dialog.blocking_save_file() {
            None => None,
            Some(file) => Some(file.into_path().map_err(|err| {
                export::write_failed(&format!("the chosen location is not a file path: {err}"))
            })?),
        };
        export::finish(&response, chosen)
    })
    .await
    .map_err(|err| Failure::broken(&format!("export task failed: {err}")))?
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
    std::thread::Builder::new()
        .name(format!("aw-live-{id}"))
        .spawn(move || {
            let mut send = |event| on_event.send(event).is_ok();
            // Resolved per poll, not once: a reconnect after the pinned
            // daemon went away walks the ordered lookup again.
            let get = |target: &str| stream::window_get(&channel_path, target);
            stream::run(&get, &target, &closed, &mut send, std::thread::sleep);
        })
        .map_err(|err| Failure::broken(&format!("stream thread: {err}")))?;
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
        .plugin(tauri_plugin_dialog::init())
        .manage(Streams::default())
        .invoke_handler(tauri::generate_handler![
            aw_request,
            aw_save_export,
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
    use super::launch_body_with_user_locale;

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

    #[test]
    fn direct_launch_forwards_only_set_user_locale_values() {
        let body = launch_body_with_user_locale(
            "POST",
            "/api/v1/sessions",
            r#"{"mode":"launch","argv":["tool"]}"#.to_owned(),
            |name| match name {
                "LANG" => Some("zh_TW.UTF-8".to_owned()),
                "TZ" => Some("Asia/Taipei".to_owned()),
                _ => None,
            },
        );
        let value: serde_json::Value = match serde_json::from_str(&body) {
            Ok(value) => value,
            Err(error) => panic!("request json: {error}"),
        };
        assert_eq!(value["env"]["LANG"], "zh_TW.UTF-8");
        assert_eq!(value["env"]["TZ"], "Asia/Taipei");
        assert!(value["env"].get("LC_ALL").is_none());
    }

    #[test]
    fn unset_locale_does_not_add_an_env_object() {
        let original = r#"{"mode":"launch","argv":["tool"]}"#.to_owned();
        let body =
            launch_body_with_user_locale("POST", "/api/v1/sessions", original.clone(), |_| None);
        assert_eq!(body, original);
    }
}
