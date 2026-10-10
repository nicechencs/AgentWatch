//! Foreground runtime: file lock, rolling logs, and in-process shutdown.
//!
//! There is no tokio runtime. A std thread runs the Batcher placeholder; the
//! main thread polls a stop file. SIGTERM and Windows service control are out
//! of scope for this card. P1-DAEMON-05 is expected to raise the same stop
//! flag (or create [`STOP_FILE_NAME`]) when a service stop arrives. The `ctrlc`
//! crate is not used: it is not in the offline crates.io cache, and a stop file
//! is enough to test graceful shutdown without SCM.
//!
//! Single instance: an exclusive std lock on `agentwatchd.lock` in the data
//! directory, plus the pid written into that file. This is not a Windows named
//! mutex. Named mutexes need platform APIs, and this card has no platform
//! module. `File::try_lock` is the portable substitute (flock on Unix,
//! LockFileEx on Windows). The operating system releases the lock when the
//! process exits, including after a crash; `Drop` also unlocks on the graceful
//! path. Do not call `std::process::exit` while holding the lock if you need
//! `Drop` to run — the OS still releases it, but the pid file would linger locked
//! only until the handle closes, which `exit` does close.
//!
//! Core dumps are **not** disabled. [`core_dump_guard_status`] says so. Calling
//! `prctl`, `setrlimit`, or the Windows error-reporting API would be platform
//! code and, here, unsafe, which this crate forbids.

use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use thiserror::Error;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_core::span::{Attributes, Id, Record};
use tracing_core::Metadata;

use crate::api::{socket_path, ApiState, HttpServer, IpcServer, OtlpRegistry, StoreQuery};
use crate::config::{resolve_data_dir, ConfigWarning, DaemonConfig};
use crate::paths::ensure_data_dir;
use crate::sample::HostSampler;

/// Lock file inside the data directory.
pub const LOCK_FILE_NAME: &str = "agentwatchd.lock";

/// Creating this file asks a running foreground instance to shut down.
pub const STOP_FILE_NAME: &str = "agentwatchd.stop";

/// Active log file. Rotated copies are `agentwatchd.log.1` … `.4`.
pub const LOG_FILE_NAME: &str = "agentwatchd.log";

/// One log file is capped at 10 MiB.
pub const LOG_MAX_BYTES: u64 = 10 * 1024 * 1024;

/// How many historical files to keep (plus the active file).
pub const LOG_KEEP: usize = 5;

/// How often the foreground loop looks for the stop file.
const POLL: Duration = Duration::from_millis(50);

/// How often that loop also takes a poll sample. A divisor of the wait so a
/// sample is not late by more than one stop-file poll.
const SAMPLE_EVERY_POLLS: u32 = 5;

const SHUTDOWN_STOP_COLLECTORS: &str = "shutdown: stop collectors";
const SHUTDOWN_FLUSH: &str = "shutdown: flush pipeline";
const SHUTDOWN_CLOSE_STORE: &str = "shutdown: close store";
const BATCHER_STOP: &str = "batcher: received stop signal";

/// Honest status: core dumps are still enabled because no platform API is called.
pub fn core_dump_guard_status() -> &'static str {
    "core dump guard not implemented, reason: needs platform API, left for a later platform card"
}

/// Why the foreground process cannot continue.
#[derive(Debug, Error)]
pub enum RuntimeError {
    /// Config or path setup failed before the lock.
    #[error("{0}")]
    Config(String),

    /// The data directory could not be created. No other directory was used.
    #[error("failed to create data directory `{}`: {source}", path.display())]
    DataDir {
        /// Directory we tried to create.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// Another live process holds the lock.
    #[error("another agentwatchd instance is already running (lock `{}`, pid {holder})", path.display())]
    AlreadyRunning {
        /// Lock file path.
        path: PathBuf,
        /// Pid recorded by the holder, or "unknown" if the file was empty.
        holder: String,
    },

    /// The lock file could not be opened or locked for a reason other than contention.
    #[error("failed to lock `{}`: {source}", path.display())]
    LockIo {
        /// Lock file path.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// Logging could not be started.
    #[error("failed to open log `{}`: {source}", path.display())]
    Log {
        /// Log path.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },
}

/// Exclusive lock held for the life of the process.
///
/// Drop unlocks. If Drop is skipped, the OS releases the lock when the file
/// handle is closed at process exit.
pub struct InstanceLock {
    file: File,
    /// Kept so a later status command can name the lock file without reopening it.
    #[allow(dead_code)]
    path: PathBuf,
}

impl InstanceLock {
    /// Try once. On contention, reads the holder's pid (best effort) and returns
    /// [`RuntimeError::AlreadyRunning`].
    ///
    /// # Errors
    ///
    /// See [`RuntimeError::AlreadyRunning`] and [`RuntimeError::LockIo`].
    pub fn acquire(data_dir: &Path) -> Result<Self, RuntimeError> {
        let path = data_dir.join(LOCK_FILE_NAME);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|source| RuntimeError::LockIo {
                path: path.clone(),
                source,
            })?;
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                let holder = read_holder_pid(&path);
                return Err(RuntimeError::AlreadyRunning { path, holder });
            }
            Err(TryLockError::Error(source)) => {
                return Err(RuntimeError::LockIo { path, source });
            }
        }
        file.set_len(0).map_err(|source| RuntimeError::LockIo {
            path: path.clone(),
            source,
        })?;
        writeln!(file, "{}", std::process::id()).map_err(|source| RuntimeError::LockIo {
            path: path.clone(),
            source,
        })?;
        let _ = file.flush();
        Ok(Self { file, path })
    }

    /// Lock file path. No caller in this card; a later status command prints it.
    #[allow(dead_code)]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for InstanceLock {
    fn drop(&mut self) {
        // Best effort. Process exit releases the OS lock even if this fails.
        let _ = self.file.unlock();
    }
}

fn read_holder_pid(path: &Path) -> String {
    fs::read_to_string(path)
        .ok()
        .map(|text| text.trim().to_owned())
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| "unknown".to_owned())
}

/// Size-capped log file. Keeps [`LOG_KEEP`] files total: the active file plus
/// `LOG_KEEP - 1` rotated copies.
struct RollingFile {
    dir: PathBuf,
    active: File,
    current_len: u64,
    max_bytes: u64,
    keep: usize,
}

impl RollingFile {
    fn open(dir: &Path, max_bytes: u64, keep: usize) -> Result<Self, RuntimeError> {
        let path = dir.join(LOG_FILE_NAME);
        let active = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|source| RuntimeError::Log {
                path: path.clone(),
                source,
            })?;
        let current_len = match active.metadata() {
            Ok(meta) => meta.len(),
            Err(_) => 0,
        };
        Ok(Self {
            dir: dir.to_path_buf(),
            active,
            current_len,
            max_bytes,
            keep,
        })
    }

    fn write_line(&mut self, line: &str) -> io::Result<()> {
        let bytes = line.len() as u64 + 1;
        if self.current_len > 0 && self.current_len + bytes > self.max_bytes {
            self.rotate()?;
        }
        self.active.write_all(line.as_bytes())?;
        self.active.write_all(b"\n")?;
        self.current_len += bytes;
        // The subscriber flushes once per event, after the line is counted.
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.active.flush()
    }

    fn rotate(&mut self) -> io::Result<()> {
        let keep_rotated = self.keep.saturating_sub(1);
        if keep_rotated == 0 {
            return Ok(());
        }
        // Close the active handle before renaming. Windows refuses to rename a
        // file that still has a write handle. The placeholder exists only so
        // `self.active` stays a File while the real one is dropped.
        let placeholder_path = self.dir.join("agentwatchd.log.open");
        let placeholder = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&placeholder_path)?;
        let old = std::mem::replace(&mut self.active, placeholder);
        drop(old);

        let oldest = self.dir.join(format!("{LOG_FILE_NAME}.{keep_rotated}"));
        let _ = fs::remove_file(&oldest);
        for index in (1..keep_rotated).rev() {
            let from = self.dir.join(format!("{LOG_FILE_NAME}.{index}"));
            let to = self.dir.join(format!("{LOG_FILE_NAME}.{}", index + 1));
            if from.exists() {
                let _ = fs::rename(&from, &to);
            }
        }
        let active_path = self.dir.join(LOG_FILE_NAME);
        let rotated = self.dir.join(format!("{LOG_FILE_NAME}.1"));
        fs::rename(&active_path, &rotated)?;
        self.active = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&active_path)?;
        self.current_len = 0;
        let _ = fs::remove_file(&placeholder_path);
        Ok(())
    }
}

/// tracing subscriber that writes one sanitized line per event.
///
/// `max_level` is inclusive. The default is [`Level::DEBUG`]: coding-conventions
/// §2 assigns queue depth and batch timing to `debug`, and those lines are only
/// useful if they reach the file. `trace` stays off unless a caller asks for it,
/// matching the "trace is compiled out of release" rule.
struct FileSubscriber {
    writer: Mutex<RollingFile>,
    max_level: Level,
}

impl FileSubscriber {
    fn new(writer: RollingFile) -> Self {
        Self {
            writer: Mutex::new(writer),
            max_level: Level::DEBUG,
        }
    }
}

impl Subscriber for FileSubscriber {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.level() <= &self.max_level
    }

    fn new_span(&self, _span: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _span: &Id, _values: &Record<'_>) {}

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut visitor = SanitizeVisitor::default();
        event.record(&mut visitor);
        let level = event.metadata().level();
        let target = event.metadata().target();
        let fields = visitor.finish();
        let stamp = rfc3339_utc(SystemTime::now());
        let line = format!("{stamp} {level} {target}{fields}");
        if let Ok(mut writer) = self.writer.lock() {
            let _ = writer.write_line(&line);
            let _ = writer.flush();
        }
    }

    fn enter(&self, _span: &Id) {}

    fn exit(&self, _span: &Id) {}
}

/// `2026-10-10T10:01:02.345Z`. UTC with an explicit `Z`, so a reader in any
/// zone can convert it; no timezone database is needed.
fn rfc3339_utc(at: SystemTime) -> String {
    let since = at.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = since.as_secs();
    let millis = since.subsec_millis();
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let rem = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Days since 1970-01-01 to (year, month, day). Howard Hinnant's algorithm.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (
        year,
        u32::try_from(month).unwrap_or(1),
        u32::try_from(day).unwrap_or(1),
    )
}

#[derive(Default)]
struct SanitizeVisitor {
    parts: Vec<String>,
}

impl SanitizeVisitor {
    fn finish(self) -> String {
        if self.parts.is_empty() {
            String::new()
        } else {
            format!(" {}", self.parts.join(" "))
        }
    }

    fn push_raw(&mut self, field: &Field, rendered: &str) {
        if is_sensitive_field(field.name()) {
            let len = rendered.len();
            self.parts
                .push(format!("{}=<redacted len={len}>", field.name()));
        } else {
            self.parts.push(format!("{}={rendered}", field.name()));
        }
    }
}

impl Visit for SanitizeVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        // Sensitive strings are never copied into the log. Only the length is.
        if is_sensitive_field(field.name()) {
            self.parts
                .push(format!("{}=<redacted len={}>", field.name(), value.len()));
        } else {
            self.parts.push(format!("{}={value}", field.name()));
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if is_sensitive_field(field.name()) {
            // Do not Debug-format the value. argv, env, URL, and headers must
            // never be rendered, even as a length-unavailable placeholder path
            // that would otherwise call {:?}.
            self.parts
                .push(format!("{}=<redacted len=unavailable>", field.name()));
            return;
        }
        let rendered = format!("{value:?}");
        self.parts.push(format!("{}={rendered}", field.name()));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.push_raw(field, &value.to_string());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.push_raw(field, &value.to_string());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.push_raw(field, if value { "true" } else { "false" });
    }
}

fn is_sensitive_field(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("argv")
        || lower.contains("env")
        || lower == "url"
        || lower.contains("header")
        || lower.contains("authorization")
        || lower.contains("cookie")
        // A raw event, a request or response body, or a file path can carry the
        // content ADR-0012 forbids persisting. Match the field name so a future
        // `tracing::debug!(event = ?raw, ...)` cannot render it.
        || lower == "body"
        || lower.contains("payload")
        || lower.contains("content")
        || lower == "event"
        || lower == "raw_event"
        || lower == "cmdline"
        || lower == "command"
        || lower == "path"
        || lower.contains("token")
        || lower.contains("secret")
        || lower.contains("password")
}

/// Shared stop flag. The stop file and a test can both set it.
struct StopFlag {
    inner: AtomicBool,
}

impl StopFlag {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: AtomicBool::new(false),
        })
    }

    fn request(&self) {
        self.inner.store(true, Ordering::SeqCst);
    }

    fn is_set(&self) -> bool {
        self.inner.load(Ordering::SeqCst)
    }
}

struct Batcher {
    handle: Option<JoinHandle<()>>,
}

impl Batcher {
    /// Placeholder thread. It does not open SQLite. It logs once when stopped.
    fn spawn(stop: Arc<StopFlag>) -> Self {
        let handle = thread::Builder::new()
            .name("aw-batcher".to_owned())
            .spawn(move || {
                while !stop.is_set() {
                    thread::sleep(POLL);
                }
                tracing::info!("{}", BATCHER_STOP);
            })
            .ok();
        Self { handle }
    }

    fn join(mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Run until [`STOP_FILE_NAME`] appears in the data directory, then shut down
/// in order: collectors placeholder, pipeline flush placeholder, store close
/// placeholder. Each step is one log line.
///
/// # Errors
///
/// Directory creation, locking, and log setup failures.
pub fn run_foreground(
    config: &DaemonConfig,
    warnings: &[ConfigWarning],
) -> Result<(), RuntimeError> {
    let data_dir = resolve_data_dir(config).map_err(|err| RuntimeError::Config(err.to_string()))?;
    ensure_data_dir(&data_dir).map_err(|source| RuntimeError::DataDir {
        path: data_dir.clone(),
        source,
    })?;
    // A leftover stop file from a previous run must not exit immediately.
    let stop_path = data_dir.join(STOP_FILE_NAME);
    let _ = fs::remove_file(&stop_path);

    let lock = InstanceLock::acquire(&data_dir)?;
    init_logging(&data_dir)?;

    // The directory is recorded, but not as a field named `path`: the subscriber
    // redacts that name because file paths in events can be sensitive.
    tracing::info!(
        data_dir = %data_dir.display(),
        "agentwatchd foreground started"
    );
    tracing::info!("{}", core_dump_guard_status());
    for warning in warnings {
        tracing::warn!("{}", warning.message());
    }

    let stop = StopFlag::new();
    // Stop the batcher only after collectors have stopped. Sharing the runtime
    // flag would let it exit as soon as the stop file is seen.
    let batcher_stop = StopFlag::new();
    let batcher = Batcher::spawn(Arc::clone(&batcher_stop));
    // The registry binds 127.0.0.1:0 only, and only from `OtlpRegistry::open`.
    // Nothing here calls `open`: the foreground runtime has no session yet, and
    // the session orchestrator does not carry an agent id to bind one to.
    // Holding the empty registry keeps the type in the binary. Drop closes
    // nothing because nothing was opened, and nothing is forwarded.
    let otlp = OtlpRegistry::new();

    // Loopback only. `HttpServer::bind` refuses anything else. A port that is
    // already taken is a warning: the daemon keeps running without HTTP.
    // `api.http_port` picks the port; 0 turns the listener off.
    let http_port = config.api.http_port;
    // One state for both listeners: a ticket issued on the internal channel
    // (`aw ui`, the desktop app) must be redeemable on loopback HTTP.
    let shared = Arc::new(Mutex::new(foreground_api(config, &data_dir)));
    let mut ipc = start_ipc(&shared);
    let mut http = if http_port == 0 {
        tracing::info!("http listener disabled (api.http_port = 0)");
        None
    } else {
        match HttpServer::bind_shared(http_port, Arc::clone(&shared)) {
            Ok(server) => {
                tracing::info!(port = server.addr.port(), "http listener started");
                Some(server)
            }
            Err(err) => {
                tracing::warn!(port = http_port, error = %err, "http listener not started");
                None
            }
        }
    };

    // Poll only. No ETW, eBPF, or eslogger. The sampler attaches to pid 1 so
    // the host source refreshes the process table; launch scope would not.
    // See `sample.rs`. A machine where pid 1's identity cannot be hashed does
    // not start sampling — that is logged, and the stop loop still runs.
    let mut sampler = HostSampler::new(data_dir.join("agentwatch.db"));
    sampler.start();
    let mut polls_until_sample: u32 = SAMPLE_EVERY_POLLS;

    while !stop.is_set() {
        if stop_path.is_file() {
            stop.request();
            break;
        }
        polls_until_sample = polls_until_sample.saturating_sub(1);
        if polls_until_sample == 0 {
            sampler.tick();
            polls_until_sample = SAMPLE_EVERY_POLLS;
        }
        thread::sleep(POLL);
    }

    stop.request();
    if let Some(server) = http.as_mut() {
        server.shutdown();
    }
    if let Some(server) = ipc.as_mut() {
        server.shutdown();
    }

    // The sampler is stopped before the shutdown lines. One last tick flushes
    // the delta, then the collector is stopped. The three lines below stay in
    // this order: tests match them.
    sampler.flush();
    sampler.stop();

    // Order is part of the acceptance test. Do not reorder these lines.
    tracing::info!("{}", SHUTDOWN_STOP_COLLECTORS);
    // Release the batcher after collector shutdown, then wait before closing the store.
    batcher_stop.request();
    batcher.join();
    tracing::info!("{}", SHUTDOWN_FLUSH);
    tracing::info!("{}", SHUTDOWN_CLOSE_STORE);
    drop(otlp);
    drop(lock);
    Ok(())
}

/// Open the internal channel. A failure is a warning, not an exit: the daemon
/// keeps collecting, and `aw` reports the socket as unreachable (exit 3).
fn start_ipc(state: &Arc<Mutex<ApiState>>) -> Option<IpcServer> {
    let Some(path) = socket_path() else {
        tracing::warn!("internal channel not started: no socket path on this platform");
        return None;
    };
    match IpcServer::bind(&path, Arc::clone(state)) {
        Ok(server) => {
            tracing::info!(socket = %server.path.display(), "internal channel started");
            Some(server)
        }
        Err(err) => {
            tracing::warn!(error = %err, "internal channel not started");
            None
        }
    }
}

/// API state for the foreground listener: the data-dir database, the loaded
/// config, and no in-memory sessions.
fn foreground_api(config: &DaemonConfig, data_dir: &Path) -> ApiState {
    let mut state = ApiState::default();
    state.sessions.clear();
    state.query = StoreQuery::open_path(data_dir.join("agentwatch.db"));
    state.config_json = config_snapshot(config);
    // Off unless the config asks for it. The flag only changes `GET /`.
    state.preview_ui = config.debug.preview_ui;
    state
}

/// Non-secret view of the loaded config. No paths: the data directory can
/// contain a user name, and the startup log already recorded it.
fn config_snapshot(config: &DaemonConfig) -> serde_json::Value {
    serde_json::json!({
        "retention": {
            "max_db_size_mb": config.retention.max_db_size_mb,
            "max_age_days": config.retention.max_age_days,
        },
        "proxy": {
            "on_tls_reject": match config.proxy.on_tls_reject {
                crate::config::TlsReject::Fail => "fail",
                crate::config::TlsReject::Tunnel => "tunnel",
            },
            "max_hash_body": config.proxy.max_hash_body,
        },
        "collectors": {
            "windows": { "sni": config.collectors.windows.sni },
            "linux": {
                "tls_uprobe": config.collectors.linux.tls_uprobe,
                "ipc_payload_peek": config.collectors.linux.ipc_payload_peek,
            },
        },
        "correlation": { "max_hash_file_size": config.correlation.max_hash_file_size },
        "debug": {
            "keep_raw_events": config.debug.keep_raw_events,
            "preview_ui": config.debug.preview_ui,
        },
    })
}

/// Install the process-wide file subscriber. Call once per process.
///
/// # Errors
///
/// Returns [`RuntimeError::Log`] when the file cannot be opened or tracing
/// already has a global subscriber.
pub fn init_logging(data_dir: &Path) -> Result<(), RuntimeError> {
    let rolling = RollingFile::open(data_dir, LOG_MAX_BYTES, LOG_KEEP)?;
    let subscriber = FileSubscriber::new(rolling);
    tracing::subscriber::set_global_default(subscriber).map_err(|err| RuntimeError::Log {
        path: data_dir.join(LOG_FILE_NAME),
        source: io::Error::other(err.to_string()),
    })
}

/// Emit one event whose sensitive fields must not appear as values in the log.
///
/// The values are sentinels. The subscriber replaces them with length placeholders.
pub fn emit_sensitive_probe() {
    let argv = "secret-argv-value";
    let env = "secret-env-value";
    let url = "https://secret.example/path?token=secret-url-value";
    let headers = "Authorization: secret-header-value";
    tracing::info!(argv, env, url, headers, "log probe");
}

/// Write the stop file that [`run_foreground`] polls.
///
/// No caller in this card. Integration tests write the file themselves. A later
/// service-control hook calls this.
///
/// # Errors
///
/// Returns the I/O error. Does not create parent directories.
#[allow(dead_code)]
pub fn signal_stop(data_dir: &Path) -> io::Result<()> {
    let path = data_dir.join(STOP_FILE_NAME);
    let mut file = File::create(&path)?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    writeln!(file, "stop {stamp}")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        core_dump_guard_status, is_sensitive_field, rfc3339_utc, InstanceLock, RollingFile,
        RuntimeError, LOG_MAX_BYTES,
    };

    #[test]
    fn log_timestamp_is_rfc3339_utc() {
        let at = std::time::UNIX_EPOCH + std::time::Duration::from_millis(1_791_626_461_007);
        assert_eq!(rfc3339_utc(at), "2026-10-10T10:01:01.007Z");
        assert_eq!(
            rfc3339_utc(std::time::UNIX_EPOCH),
            "1970-01-01T00:00:00.000Z"
        );
        let leap = std::time::UNIX_EPOCH + std::time::Duration::from_secs(951_782_400);
        assert_eq!(rfc3339_utc(leap), "2000-02-29T00:00:00.000Z");
    }

    #[test]
    fn sensitive_names_cover_content_and_credentials() {
        for name in [
            "argv",
            "env",
            "url",
            "headers",
            "authorization",
            "cookie",
            "body",
            "payload",
            "content",
            "event",
            "raw_event",
            "cmdline",
            "command",
            "path",
            "token",
            "secret",
            "password",
        ] {
            assert!(is_sensitive_field(name), "{name} must be redacted");
        }
        // Names the lifecycle logs actually use must survive.
        for name in [
            "session",
            "pid",
            "status",
            "reason",
            "collector",
            "detail",
            "route",
        ] {
            assert!(!is_sensitive_field(name), "{name} must stay visible");
        }
    }

    #[test]
    fn core_dump_status_admits_it_is_not_implemented() {
        let text = core_dump_guard_status();
        assert!(text.contains("not implemented"));
        assert!(text.contains("platform API"));
    }

    #[test]
    fn second_lock_in_same_process_is_not_required() -> Result<(), RuntimeError> {
        // Same-process double lock is unspecified by std. Cross-process coverage
        // lives in the integration test. Here we only check acquire + drop.
        let dir = std::env::temp_dir().join(format!(
            "agentwatchd-lock-{}-{}",
            std::process::id(),
            match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
                Ok(duration) => duration.as_nanos(),
                Err(_) => 0,
            }
        ));
        std::fs::create_dir_all(&dir).map_err(|source| RuntimeError::DataDir {
            path: dir.clone(),
            source,
        })?;
        let lock = InstanceLock::acquire(&dir)?;
        let held = lock.path().is_file();
        drop(lock);
        let _ = std::fs::remove_dir_all(&dir);
        if held {
            Ok(())
        } else {
            Err(RuntimeError::Config("lock file missing".to_owned()))
        }
    }

    #[test]
    fn rolling_writer_rotates_before_max() -> Result<(), RuntimeError> {
        let dir = std::env::temp_dir().join(format!(
            "agentwatchd-roll-{}-{}",
            std::process::id(),
            match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
                Ok(duration) => duration.as_nanos(),
                Err(_) => 0,
            }
        ));
        std::fs::create_dir_all(&dir).map_err(|source| RuntimeError::DataDir {
            path: dir.clone(),
            source,
        })?;
        let mut rolling = RollingFile::open(&dir, 64, 5)?;
        for index in 0..8 {
            rolling
                .write_line(&format!("line-{index}-abcdefghijklmnopqrstuvwxyz"))
                .map_err(|source| RuntimeError::Log {
                    path: dir.join("agentwatchd.log"),
                    source,
                })?;
        }
        let rotated = dir.join("agentwatchd.log.1").is_file();
        let active_len = match std::fs::metadata(dir.join("agentwatchd.log")) {
            Ok(meta) => meta.len(),
            Err(_) => u64::MAX,
        };
        let _ = std::fs::remove_dir_all(&dir);
        if rotated && active_len <= 64 {
            Ok(())
        } else {
            Err(RuntimeError::Config(format!(
                "rotation failed rotated={rotated} active_len={active_len} cap={LOG_MAX_BYTES}"
            )))
        }
    }
}
