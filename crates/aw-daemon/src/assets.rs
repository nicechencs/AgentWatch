//! Embedded Web UI.
//!
//! P2-DAEMON-01. `build.rs` sets `aw_ui_dist` only when `ui/dist` exists, and
//! then this module pulls that directory in with `rust-embed` (gzip at serve
//! time, not a second copy of the tree). A checkout with no frontend build
//! compiles the empty branch: [`get`] returns `None` and the HTTP layer answers
//! 404 for page routes. Nothing outside `ui/dist` is named here.
//!
//! Development (`AW_UI_DEV_URL`) does not change the embed. [`AssetMode::DevProxy`]
//! tells the HTTP layer to reverse-proxy page requests at that origin. The URL
//! is read when the server starts; a ticket or token is never appended to it
//! in a log line.

/// How the UI is served.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssetMode {
    /// Files compiled in from `ui/dist`, or an empty set when it was absent.
    Embedded,
    /// `AW_UI_DEV_URL` is set. Page requests are proxied there.
    DevProxy {
        /// Origin without a trailing slash, for example `http://127.0.0.1:5173`.
        origin: String,
    },
}

impl AssetMode {
    /// `AW_UI_DEV_URL` wins when it is a non-empty http(s) URL.
    ///
    /// A missing, blank, or non-http value is [`AssetMode::Embedded`]. The
    /// value is a local dev-server origin, not a credential.
    #[must_use]
    pub fn from_env() -> Self {
        match std::env::var("AW_UI_DEV_URL") {
            Ok(raw) => {
                let trimmed = raw.trim().trim_end_matches('/').to_owned();
                if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
                    Self::DevProxy { origin: trimmed }
                } else {
                    Self::Embedded
                }
            }
            Err(_) => Self::Embedded,
        }
    }
}

/// One embedded file.
pub struct EmbeddedFile {
    /// Path relative to `ui/dist`, using `/`, no leading slash.
    pub path: String,
    /// Uncompressed file bytes.
    pub data: Vec<u8>,
}

/// Look up `path` (leading slash ignored) in the embedded tree.
///
/// Returns `None` when `ui/dist` was absent at build time, when `path` escapes
/// the tree (`..`), or when the file is not embedded. SPA fallback to
/// `index.html` is the HTTP layer's decision, not this function's.
#[must_use]
pub fn get(path: &str) -> Option<EmbeddedFile> {
    let path = path.trim_start_matches('/');
    if path.is_empty() || path.split('/').any(|seg| seg == ".." || seg == ".") {
        return None;
    }
    embedded_get(path)
}

/// `index.html`, if the UI was built.
#[must_use]
pub fn index_html() -> Option<EmbeddedFile> {
    get("index.html")
}

/// True when `build.rs` found `ui/dist` and the embed cfg is on.
#[must_use]
pub fn dist_was_present() -> bool {
    option_env!("AW_UI_DIST_PRESENT") == Some("1")
}

/// Content-Type for a UI path. Unknown extensions are `application/octet-stream`.
#[must_use]
pub fn content_type(path: &str) -> &'static str {
    let ext = path.rsplit('.').next().unwrap_or("");
    match ext {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" | "map" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        "txt" => "text/plain; charset=utf-8",
        "wasm" => "application/wasm",
        _ => "application/octet-stream",
    }
}

#[cfg(not(aw_ui_dist))]
fn embedded_get(_path: &str) -> Option<EmbeddedFile> {
    None
}

#[cfg(aw_ui_dist)]
#[derive(rust_embed::Embed)]
#[folder = "../../ui/dist"]
struct UiDist;

#[cfg(aw_ui_dist)]
fn embedded_get(path: &str) -> Option<EmbeddedFile> {
    UiDist::get(path).map(|file| EmbeddedFile {
        path: path.to_owned(),
        data: file.data.into_owned(),
    })
}
