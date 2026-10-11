//! `POST /sessions` (attach / launch), `POST /sessions/run`,
//! `POST /sessions/{sid}/adopt`, `POST /sessions/{sid}/attach`.
//!
//! Each inserts or finds the `sessions` row and queues a
//! [`WatchRequest::Start`] for the foreground loop ([`crate::watch`]), which
//! runs the poll sampler on that root (evidence S). Rules (api-and-cli §2):
//!
//! - Attaching to a process of another OS user needs an administrator (403).
//! - Launch from the API (`POST /sessions`, `mode: "launch"`) starts the
//!   program as the caller: as is when the caller is the daemon's account, and
//!   dropped to the caller's uid, gid and login group list when the daemon
//!   runs as root ([`super::launch_as`]). The account comes only from the OS peer
//!   credential; an unknown one is refused, never run as root.
//! - A route is available only when `aw-platform` exposes both process identity
//!   and a process table to the sampler; otherwise it answers 503
//!   `collector_unavailable` and creates nothing.

use serde_json::{json, Value};

use super::auth::{random_secret, Caller};
use super::routes::{error_response, ApiResponse, ApiState};
use crate::sample::SampleTarget;
use crate::watch::{now_ns, PendingLaunch, WatchRequest, ADOPT_TIMEOUT_NS};

/// macOS launch result, before the watcher takes ownership. A platform launch
/// is already a released handle; a same-account spawn is still a `Child`.
/// Either becomes the one handle the watcher reaps.
#[cfg(target_os = "macos")]
enum ChildHandoff {
    Released(Box<dyn aw_platform::ReleasedChild>),
    Process(std::process::Child),
}

#[cfg(target_os = "macos")]
impl ChildHandoff {
    fn into_released(self) -> Box<dyn aw_platform::ReleasedChild> {
        match self {
            Self::Released(child) => child,
            Self::Process(child) => crate::watch::released_child(child),
        }
    }
}

fn parse(body: &[u8]) -> Result<Value, ApiResponse> {
    if body.is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_slice(body).map_err(|_| error_response(400, "bad_request", "body is not JSON"))
}

fn opt_text(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

fn pid_field(value: &Value) -> Result<u32, ApiResponse> {
    value
        .get("pid")
        .and_then(Value::as_u64)
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|pid| *pid > 0)
        .ok_or_else(|| error_response(400, "bad_argument", "pid: expected a positive integer"))
}

fn argv_field(value: &Value) -> Result<Vec<String>, ApiResponse> {
    let argv: Vec<String> = value
        .get("argv")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    if argv.is_empty() || argv[0].trim().is_empty() {
        return Err(error_response(
            400,
            "bad_argument",
            "argv: expected a non-empty array of strings",
        ));
    }
    Ok(argv)
}

/// `sessions.argv` as stored: each argument through the built-in redactor.
fn redacted_argv_json(argv: &[String]) -> String {
    let redactor = aw_pipeline::Redactor::new(&aw_pipeline::config::RedactionConfig::default());
    let scrubbed: Vec<String> = redactor
        .redact_args(argv)
        .iter()
        .map(|arg| redactor.scrub_text(arg))
        .collect();
    serde_json::to_string(&scrubbed).unwrap_or_else(|_| "[]".to_owned())
}

/// The one executable label the pipe-gated `/adopt` path can retain when its
/// root exits before the first poll. It comes from the session argv already
/// accepted for storage, not a post-exit `/proc` read.
fn argv0_basename(argv_json: Option<&str>) -> Option<String> {
    let argv: Vec<String> = serde_json::from_str(argv_json?).ok()?;
    let argv0 = argv.first()?;
    std::path::Path::new(argv0)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
}

/// The daemon's effective uid (0 when it runs as root).
fn daemon_uid() -> u32 {
    #[cfg(unix)]
    {
        nix::unistd::geteuid().as_raw()
    }
    #[cfg(not(unix))]
    {
        u32::MAX
    }
}

/// Linux socket callers obtain `user_id` from `SO_PEERCRED`; a UI token keeps
/// the account bound to the peer that received it. The route uses that value
/// to ensure a non-root daemon only launches for its own uid, never an account
/// reconstructed from the user database.
#[cfg(target_os = "linux")]
fn linux_launch_peer_user_id(caller: &Caller) -> String {
    #[cfg(test)]
    if let Some(uid) = TEST_LINUX_LAUNCH_PEER_UID.with(std::cell::Cell::get) {
        return uid.to_string();
    }
    caller.user_id.clone()
}

// Route tests cannot create a second Unix socket user on every CI host. This
// test-only override stands in for the uid that SO_PEERCRED supplied; it is not
// compiled into non-test binaries and no request field can affect it.
#[cfg(all(test, target_os = "linux"))]
thread_local! {
    static TEST_LINUX_LAUNCH_PEER_UID: std::cell::Cell<Option<u32>> = const { std::cell::Cell::new(None) };
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) fn set_test_linux_launch_peer_uid(uid: Option<u32>) {
    TEST_LINUX_LAUNCH_PEER_UID.with(|slot| slot.set(uid));
}

fn collector_available() -> Result<(), ApiResponse> {
    let available = |capability| {
        aw_platform::platform().capability(capability) == aw_platform::CapabilityStatus::Available
    };
    if available(aw_platform::Capability::ProcessIdentity)
        && available(aw_platform::Capability::ProcessTable)
    {
        Ok(())
    } else {
        Err(error_response(
            503,
            "collector_unavailable",
            "the poll sampler process identity is not available in this build",
        ))
    }
}

/// Whether the process identity the platform just read belongs to this
/// authenticated peer.  A failure to read an owner is never treated as a
/// match, and Windows compares a SID rather than a daemon account or pid.
fn caller_owns_process(caller: &Caller, process: &aw_platform::ProcessEntry) -> bool {
    match process.owner.as_ref() {
        Some(aw_platform::Owner::Unix {
            ruid, euid, suid, ..
        }) => caller
            .user_id
            .parse::<u32>()
            .is_ok_and(|uid| [ruid, euid, suid].iter().all(|actual| **actual == uid)),
        Some(aw_platform::Owner::Windows { sid, .. }) => sid == &caller.user_id,
        None => false,
    }
}

/// The pid must be running and identifiable. Adoption requires real,
/// effective, and saved uids all to belong to the caller. `allow_admin` is
/// only for explicit attach, where an administrator may record another
/// account's process; adopt always passes `false`.
fn check_pid_owner(
    caller: &Caller,
    pid: u32,
    allow_admin: bool,
) -> Result<aw_core::ProcUid, ApiResponse> {
    collector_available()?;
    let before = crate::sample::proc_uid_of(pid).ok_or_else(|| {
        error_response(
            400,
            "no_such_process",
            "pid is not running (or its identity cannot be read)",
        )
    })?;
    let process = aw_platform::platform().process_identity(pid).ok().flatten();
    let after = crate::sample::proc_uid_of(pid);
    let after_key = aw_platform::platform()
        .sampling_process(pid)
        .ok()
        .flatten()
        .map(|sample| sample.key);
    if after != Some(before) {
        return Err(error_response(
            400,
            "no_such_process",
            "pid changed while its identity was being checked",
        ));
    }
    let owned_by_caller = process.is_some_and(|process| {
        after_key == Some(process.key) && caller_owns_process(caller, &process)
    });
    if owned_by_caller || (allow_admin && caller.admin) {
        return Ok(before);
    }
    let message = if allow_admin {
        "this process belongs to another account; recording another account's process needs an \
         administrator"
    } else {
        "this process belongs to another account and cannot be adopted"
    };
    Err(error_response(403, "not_your_process", message))
}

fn db_path(state: &ApiState) -> Result<std::path::PathBuf, ApiResponse> {
    state.query.db_path.clone().ok_or_else(|| {
        error_response(
            503,
            "no_database",
            "this daemon has no database to record sessions in",
        )
    })
}

fn require_writable_database(path: &std::path::Path) -> Result<(), ApiResponse> {
    let store = aw_store::Store::open_runtime(path)
        .map_err(|err| super::routes::database_store_response(&err, "cannot open the database"))?;
    if store.is_read_only() {
        Err(super::routes::database_read_only_newer_response())
    } else {
        Ok(())
    }
}

/// Allocate `sessions.id` and insert the row. Id 1 stays the daemon sample's.
fn insert_session(path: &std::path::Path, target: &mut SampleTarget) -> Result<(), ApiResponse> {
    let store_error =
        |err: &aw_store::StoreError, what: &str| super::routes::database_store_response(err, what);
    let mut store = aw_store::Store::open_runtime(path)
        .map_err(|err| store_error(&err, "cannot open the database"))?;
    if store.is_read_only() {
        return Err(super::routes::database_read_only_newer_response());
    }
    let max: i64 = store
        .connection()
        .query_row("SELECT COALESCE(MAX(id), 1) FROM sessions", [], |row| {
            row.get(0)
        })
        .map_err(|_| error_response(500, "store", "cannot read session ids"))?;
    target.db_id = max.max(1).saturating_add(1);
    let mut batch = aw_store::WriteBatch::default();
    batch.sessions.push(target.session_row(now_ns()));
    let mut sink = aw_store::SqliteSink::new(&mut store)
        .map_err(|err| store_error(&err, "cannot open the writer"))?;
    use aw_store::RecordSink;
    sink.write_batch(&batch)
        .map_err(|err| store_error(&err, "cannot write the session row"))?;
    target.write_session_row = false;
    Ok(())
}

fn new_public_id() -> Result<String, ApiResponse> {
    random_secret("s-")
        .map(|secret| secret.chars().take(14).collect())
        .ok_or_else(|| {
            error_response(
                503,
                "random_unavailable",
                "the OS random source failed; no session was created",
            )
        })
}

/// Label from the command line when the body gives no `name`: the program's
/// base name, then each redacted argument, joined by spaces. Capped at 60
/// characters (59 plus `…`).
fn label_from_argv(argv: &[String]) -> String {
    let redacted: Vec<String> = serde_json::from_str(&redacted_argv_json(argv)).unwrap_or_default();
    let mut parts = Vec::with_capacity(redacted.len());
    for (index, arg) in redacted.iter().enumerate() {
        if index == 0 {
            parts.push(arg.rsplit(['/', '\\']).next().unwrap_or(arg).to_owned());
        } else {
            parts.push(arg.clone());
        }
    }
    let label = parts.join(" ");
    let mut chars = label.chars();
    let head: String = chars.by_ref().take(59).collect();
    if chars.next().is_some() {
        format!("{head}…")
    } else {
        label
    }
}

fn target_for(
    caller: &Caller,
    body: &Value,
    mode: &'static str,
    root_pid: u32,
    argv: Option<&[String]>,
) -> Result<SampleTarget, ApiResponse> {
    // Attach used to read the entire host process table here merely to derive
    // a display label.  That made the HTTP 201 wait for the initial scan
    // (notably several seconds on a busy host).  The watcher performs that
    // scan after this response; callers can supply a name if one is needed.
    let name = opt_text(body, "name").or_else(|| argv.map(label_from_argv));
    Ok(SampleTarget {
        db_id: 0,
        public_id: new_public_id()?,
        name,
        mode,
        root_pid,
        user_id: caller.user_id.clone(),
        argv_json: argv.map(redacted_argv_json),
        agent: opt_text(body, "agent"),
        write_session_row: true,
        root_hint: None,
        root_identity: None,
    })
}

/// Convert the optional public duration into a daemon-owned absolute
/// deadline.  The daemon, rather than the CLI connection, owns session end.
fn duration_deadline(value: &Value) -> Result<Option<i64>, ApiResponse> {
    let Some(milliseconds) = value.get("duration_ms") else {
        return Ok(None);
    };
    let milliseconds = milliseconds
        .as_u64()
        .filter(|milliseconds| *milliseconds > 0)
        .ok_or_else(|| {
            error_response(
                400,
                "bad_argument",
                "duration_ms: expected a positive integer",
            )
        })?;
    let nanos = milliseconds
        .checked_mul(1_000_000)
        .and_then(|nanos| i64::try_from(nanos).ok())
        .ok_or_else(|| error_response(400, "bad_argument", "duration_ms is too large"))?;
    Ok(Some(now_ns().saturating_add(nanos)))
}

fn created(target: &SampleTarget, extra: Value) -> ApiResponse {
    let mut body = json!({
        "id": target.public_id,
        "session_id": target.db_id,
        "mode": target.mode,
        "root_pid": if target.root_pid == 0 { Value::Null } else { json!(target.root_pid) },
    });
    if let (Some(obj), Some(more)) = (body.as_object_mut(), extra.as_object()) {
        obj.extend(more.clone());
    }
    ApiResponse::json(201, &body)
}

/// `POST /sessions` with a database. `mode` is `attach` or `launch`.
pub(super) fn create(state: &mut ApiState, caller: &Caller, body: &[u8]) -> ApiResponse {
    match create_inner(state, caller, body) {
        Ok(response) | Err(response) => response,
    }
}

fn create_inner(
    state: &mut ApiState,
    caller: &Caller,
    body: &[u8],
) -> Result<ApiResponse, ApiResponse> {
    let value = parse(body)?;
    let path = db_path(state)?;
    match value.get("mode").and_then(Value::as_str) {
        Some("attach") => {
            let pid = pid_field(&value)?;
            let root_identity = check_pid_owner(caller, pid, true)?;
            let deadline_ns = duration_deadline(&value)?;
            let mut target = target_for(caller, &value, "attach", pid, None)?;
            // This is a single identity read, not the full process-table scan.
            // It is retained so the session always identifies the root the
            // daemon actually authorized, even if that root exits before the
            // asynchronous sampler gets its first turn.
            target.root_identity = Some(root_identity);
            target.root_hint =
                crate::sample::root_hint(pid, None).filter(|hint| hint.uid == root_identity);
            insert_session(&path, &mut target)?;
            let response = created(&target, json!({ "scan_pending": true }));
            state.pending_scans.insert(target.public_id.clone());
            state.watch_requests.push(WatchRequest::Start {
                target: Box::new(target),
                child: None,
                deadline_ns,
            });
            Ok(response)
        }
        Some("launch") => {
            let env: Vec<(String, String)> = value
                .get("env")
                .and_then(Value::as_object)
                .map(|env| {
                    env.iter()
                        .filter_map(|(key, val)| val.as_str().map(|v| (key.clone(), v.to_owned())))
                        .collect()
                })
                .unwrap_or_default();
            // HOME/USER/LOGNAME/SHELL/PATH come from the target account and the
            // fixed base path. A request that sets one is refused, not started
            // with the name dropped or overridden. The platform owns whether
            // those names compare case-sensitively.
            if let Some(reserved) = super::launch_as::reserved_env_var(&env) {
                return Err(super::launch_as::reserved_env_response(&reserved.name));
            }
            // App/API launch creation has no Windows token-to-user launch path
            // yet. `aw run` is different: its CLI creates a held child as the
            // current user and this daemon only adopts it through `/adopt`.
            #[cfg(windows)]
            {
                Err(error_response(
                    503,
                    "launch_not_in_this_build",
                    "Windows 上从 App 新建会话本版本未接入，请在终端里用 aw run 启动。",
                ))
            }
            #[cfg(not(windows))]
            {
                let argv = argv_field(&value)?;
                // Whose account: only the OS-verified caller (see `launch_as`).
                // A `uid` / `user` in the body is never read.
                #[cfg(target_os = "linux")]
                let caller_user_id = linux_launch_peer_user_id(caller);
                #[cfg(not(target_os = "linux"))]
                let caller_user_id = caller.user_id.clone();
                let who = super::launch_as::identity_for(&caller_user_id, daemon_uid())?;
                collector_available()?;
                let cwd = opt_text(&value, "cwd");
                // A relative working directory would be resolved against the
                // daemon's own directory. The caller makes it absolute before
                // sending; the daemon refuses one that is not.
                if let Some(dir) = cwd.as_deref() {
                    if !std::path::Path::new(dir).is_absolute() {
                        return Err(error_response(
                            400,
                            "cwd_not_found",
                            &format!("找不到工作目录「{dir}」"),
                        ));
                    }
                }
                // Linux and macOS both map `SpawnAsError::Drop` here. Windows never
                // reaches it: a different account is refused before spawn.
                #[cfg(unix)]
                let drop_failed = |uid: u32, step: &str| {
                    tracing::error!(uid, step, "account switch failed");
                    error_response(
                        500,
                        "drop_failed",
                        "the program did not switch to the caller's account and was stopped",
                    )
                };
                // macOS: both accounts go through the hold stage. It blocks on a
                // pipe, switches (when the caller is someone else) and only then
                // uses the caller's cwd and env. The watcher reaps this handle.
                #[cfg(target_os = "macos")]
                let (pid, child) = {
                    let Some(peer) = caller.peer.clone() else {
                        return Err(error_response(
                            403,
                            "caller_unidentified",
                            "the caller's account could not be identified",
                        ));
                    };
                    let released = super::launch_as::spawn_as(
                        peer,
                        &account_of(who.as_ref(), &caller.user_id)?,
                        &argv,
                        cwd.as_deref(),
                        &env,
                    )
                    .map_err(|err| match err {
                        super::launch_as::SpawnAsError::Program { step, error } => {
                            spawn_error(step, cwd.as_deref(), &argv, &error)
                        }
                        super::launch_as::SpawnAsError::Drop(step) => {
                            drop_failed(caller.user_id.parse().unwrap_or(0), &step)
                        }
                    })?;
                    (released.pid(), ChildHandoff::Released(released))
                };
                #[cfg(not(target_os = "macos"))]
                #[allow(unused_mut)]
                let (pid, mut child) = match &who {
                    #[cfg(unix)]
                    Some(who) => {
                        let child = super::launch_as::spawn_as(who, &argv, cwd.as_deref(), &env)
                            .map_err(|err| match err {
                                super::launch_as::SpawnAsError::Program { step, error } => {
                                    spawn_error(step, cwd.as_deref(), &argv, &error)
                                }
                                super::launch_as::SpawnAsError::Drop(step) => {
                                    drop_failed(who.uid, &step)
                                }
                            })?;
                        (child.id(), child)
                    }
                    // No account switch here: never start it as the service account.
                    #[cfg(not(unix))]
                    Some(_) => return Err(super::launch_as::no_account_switch()),
                    None => {
                        let child = spawn_as_self(&argv, cwd.as_deref(), &env)?;
                        (child.id(), child)
                    }
                };
                // A root daemon's other-account branch uses the helper and is
                // checked against that account's login groups. A same-account
                // launch is direct: it must retain the daemon's live uid, gid,
                // and groups rather than a fresh `getgrouplist` lookup.
                #[cfg(target_os = "linux")]
                {
                    let dropped = match &who {
                        Some(who) => super::launch_as::verify_dropped(pid, who),
                        None => super::launch_as::verify_dropped_as_self(pid),
                    };
                    if !dropped {
                        let _ = child.kill();
                        let _ = child.wait();
                        tracing::error!(
                            pid,
                            uid = who.as_ref().map_or_else(daemon_uid, |account| account.uid),
                            "launched child did not drop to the caller; killed"
                        );
                        return Err(error_response(
                            500,
                            "drop_failed",
                            "the program did not switch to the caller's account and was stopped",
                        ));
                    }
                }
                let mut target = target_for(caller, &value, "launch", pid, Some(&argv))?;
                target.root_hint =
                    crate::sample::root_hint(pid, argv0_basename(target.argv_json.as_deref()));
                target.root_identity = target.root_hint.as_ref().map(|hint| hint.uid);
                insert_session(&path, &mut target)?;
                let response = created(&target, json!({}));
                state.watch_requests.push(WatchRequest::Start {
                    target: Box::new(target),
                    // Both the platform launch and a same-account spawn hand over a
                    // released handle. The watcher reaps it; nothing is left as a pid.
                    #[cfg(target_os = "macos")]
                    child: Some(child.into_released()),
                    #[cfg(not(target_os = "macos"))]
                    child: Some(crate::watch::released_child(child)),
                    deadline_ns: None,
                });
                Ok(response)
            }
        }
        _ => Err(error_response(
            400,
            "bad_argument",
            "mode: expected \"attach\" or \"launch\"",
        )),
    }
}

/// The account a macOS launch starts as. `who` is `Some` when the daemon must
/// drop to another account; `None` means the caller is the daemon's own
/// account, looked up so the program still gets that account's home and shell.
#[cfg(target_os = "macos")]
fn account_of(
    who: Option<&super::launch_as::Identity>,
    user_id: &str,
) -> Result<super::launch_as::Identity, ApiResponse> {
    match who {
        Some(who) => Ok(who.clone()),
        None => super::launch_as::own_account(user_id),
    }
}

/// Start `argv` as the daemon's own account. Used only when the caller is that
/// same account, so there is nothing to switch. The environment is still built
/// from scratch for that account (`base_env`): a daemon that happens to be the
/// caller must not hand over its own process environment.
///
/// This path never switches accounts, including root calling a root daemon.
/// It starts with the daemon's active uid, gid, and groups, while `base_env`
/// still builds the target environment from scratch.
#[cfg(target_os = "linux")]
fn spawn_as_self(
    argv: &[String],
    cwd: Option<&str>,
    env: &[(String, String)],
) -> Result<std::process::Child, ApiResponse> {
    let who = super::launch_as::own_account_of_self()?;
    super::launch_as::spawn_exact(&who, argv, cwd, env).map_err(|err| match err {
        super::launch_as::SpawnAsError::Program { step, error } => {
            spawn_error(step, cwd, argv, &error)
        }
        super::launch_as::SpawnAsError::Drop(step) => {
            tracing::error!(step, "same-account launch failed");
            error_response(
                500,
                "drop_failed",
                "the program did not switch to the caller's account and was stopped",
            )
        }
    })
}

/// `POST /sessions/run`: record the session and hand back an adopt ticket.
/// The caller (`aw run`) starts the process itself, as itself, then posts
/// `/sessions/{id}/adopt` within [`ADOPT_TIMEOUT_NS`].
pub(super) fn run(state: &mut ApiState, caller: &Caller, body: &[u8]) -> ApiResponse {
    let mut inner = || -> Result<ApiResponse, ApiResponse> {
        let value = parse(body)?;
        let argv = argv_field(&value)?;
        collector_available()?;
        let path = db_path(state)?;
        let mut target = target_for(caller, &value, "launch", 0, Some(&argv))?;
        let ticket = random_secret("r-").ok_or_else(|| {
            error_response(503, "random_unavailable", "the OS random source failed")
        })?;
        insert_session(&path, &mut target)?;
        let response = created(
            &target,
            json!({ "ticket": ticket, "adopt_timeout_ms": ADOPT_TIMEOUT_NS / 1_000_000 }),
        );
        state.pending_launches.insert(
            target.public_id.clone(),
            PendingLaunch {
                ticket,
                deadline_ns: now_ns().saturating_add(ADOPT_TIMEOUT_NS),
                target,
            },
        );
        Ok(response)
    };
    match inner() {
        Ok(response) | Err(response) => response,
    }
}

/// `POST /sessions/{sid}/adopt` with `{ticket, pid}`.
pub(super) fn adopt(state: &mut ApiState, caller: &Caller, sid: &str, body: &[u8]) -> ApiResponse {
    let inner = |state: &mut ApiState| -> Result<ApiResponse, ApiResponse> {
        let value = parse(body)?;
        let not_found = || error_response(404, "not_found", "no launch is waiting for adopt");
        let pending = state.pending_launches.get(sid).ok_or_else(not_found)?;
        if pending.target.user_id != caller.user_id && !caller.admin {
            return Err(not_found());
        }
        if opt_text(&value, "ticket").as_deref() != Some(pending.ticket.as_str()) {
            return Err(error_response(
                403,
                "forbidden",
                "adopt ticket does not match",
            ));
        }
        if pending.deadline_ns <= now_ns() {
            return Err(error_response(
                410,
                "adopt_timeout",
                "adopt arrived after the timeout; the session was closed",
            ));
        }
        let pid = pid_field(&value)?;
        // Never `allow_admin`: an administrator cannot adopt another account's pid.
        let adopted_uid = check_pid_owner(caller, pid, false)?;
        let root_hint =
            crate::sample::root_hint(pid, argv0_basename(pending.target.argv_json.as_deref()))
                .filter(|hint| hint.uid == adopted_uid)
                .ok_or_else(|| {
                    error_response(
                        400,
                        "no_such_process",
                        "pid changed while adoption was being recorded",
                    )
                })?;
        let path = db_path(state)?;
        require_writable_database(&path)?;
        let root_proc_uid = i64::from_ne_bytes(root_hint.uid.0.to_ne_bytes());
        aw_store::open_connection(&path)
            .and_then(|conn| {
                conn.execute(
                    "UPDATE sessions SET root_proc_uid = ?1 WHERE id = ?2",
                    rusqlite::params![root_proc_uid, pending.target.db_id],
                )
            })
            .map_err(|err| {
                tracing::warn!(session = sid, pid, error = %err, "adopted root identity was not written");
                error_response(500, "store", "cannot record the adopted root identity")
            })?;
        let Some(mut pending) = state.pending_launches.remove(sid) else {
            return Err(not_found());
        };
        pending.target.root_pid = pid;
        pending.target.root_hint = Some(root_hint);
        pending.target.root_identity = pending.target.root_hint.as_ref().map(|hint| hint.uid);
        // Write the root's row now, while `aw run` still holds it at the gate:
        // the foreground loop starts the sampler up to a poll later, and a
        // root that exits (and posts `/exit`) before then would otherwise be
        // zero processes with no exit code. The sampler's row is the same id.
        if !crate::sample::HostSampler::for_target(path, pending.target.clone()).persist_root_hint()
        {
            tracing::warn!(
                session = sid,
                pid,
                "adopted root process row was not written"
            );
        }
        let response = ApiResponse::json(200, &json!({ "id": sid, "root_pid": pid }));
        state.watch_requests.push(WatchRequest::Start {
            target: Box::new(pending.target),
            child: None,
            deadline_ns: None,
        });
        Ok(response)
    };
    match inner(state) {
        Ok(response) | Err(response) => response,
    }
}

/// `POST /sessions/{sid}/exit` with `{exit_code}`. The caller-created child is
/// reaped by `aw run`, so it reports its numeric status separately. A code the
/// daemon already recorded is authoritative and is never replaced.
pub(super) fn record_exit(
    state: &mut ApiState,
    caller: &Caller,
    sid: &str,
    body: &[u8],
) -> ApiResponse {
    let inner = || -> Result<ApiResponse, ApiResponse> {
        let value = parse(body)?;
        let exit_code = value
            .get("exit_code")
            .and_then(Value::as_i64)
            .and_then(|code| i32::try_from(code).ok())
            .ok_or_else(|| {
                error_response(400, "bad_argument", "exit_code: expected a signed integer")
            })?;
        let path = db_path(state)?;
        require_writable_database(&path)?;
        let conn = aw_store::open_connection(&path)
            .map_err(|_| error_response(500, "store", "cannot open the database"))?;
        let row: Option<(i64, String, Option<i64>)> = conn
            .query_row(
                "SELECT id, user_id, root_proc_uid FROM sessions WHERE public_id = ?1",
                [sid],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .ok();
        let Some((db_id, owner, root_proc_uid)) = row else {
            return Err(error_response(404, "not_found", "session not found"));
        };
        // This status comes from the unprivileged caller that created the
        // child. Do not allow another caller, including an administrator, to
        // write it for a session it did not launch.
        if owner != caller.user_id {
            return Err(error_response(404, "not_found", "session not found"));
        }
        conn.execute(
            "UPDATE sessions SET exit_code = COALESCE(exit_code, ?1) WHERE id = ?2",
            rusqlite::params![exit_code, db_id],
        )
        .map_err(|_| error_response(500, "store", "cannot update the session"))?;
        // The launched root carries the same status. Its stored `proc_uid`
        // includes pid plus start time, so a reused pid cannot receive it.
        let updated = conn
            .execute(
                "UPDATE processes SET exit_code = ?1 \
             WHERE session_id = ?2 AND proc_uid = ?3 AND exit_code IS NULL",
                rusqlite::params![exit_code, db_id, root_proc_uid],
            )
            .map_err(|_| error_response(500, "store", "cannot update the root process"))?;
        if updated == 0 {
            tracing::warn!(session = db_id, "exit did not update a root process row");
        }
        let stored: i32 = conn
            .query_row(
                "SELECT exit_code FROM sessions WHERE id = ?1",
                [db_id],
                |row| row.get(0),
            )
            .map_err(|_| error_response(500, "store", "cannot read the session exit code"))?;
        Ok(ApiResponse::json(
            200,
            &json!({ "id": sid, "exit_code": stored }),
        ))
    };
    match inner() {
        Ok(response) | Err(response) => response,
    }
}

/// `POST /sessions/{sid}/attach` with `{pid}`: watch one more root in an open
/// session the caller owns.
pub(super) fn attach(state: &mut ApiState, caller: &Caller, sid: &str, body: &[u8]) -> ApiResponse {
    let inner = |state: &mut ApiState| -> Result<ApiResponse, ApiResponse> {
        let value = parse(body)?;
        let path = db_path(state)?;
        let pid = pid_field(&value)?;
        let conn =
            aw_store::open_connection_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .map_err(|_| error_response(500, "store", "cannot open the database"))?;
        type Row = (
            i64,
            String,
            String,
            Option<i64>,
            Option<String>,
            Option<String>,
        );
        let row: Option<Row> = conn
            .query_row(
                "SELECT id, user_id, mode, ended_ns, name, agent FROM sessions WHERE public_id = ?1",
                [sid],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .ok();
        let Some((db_id, owner, mode, ended, name, agent)) = row else {
            return Err(error_response(404, "not_found", "session not found"));
        };
        if owner != caller.user_id && !caller.admin {
            return Err(error_response(404, "not_found", "session not found"));
        }
        if ended.is_some() || db_id == 1 {
            return Err(error_response(
                409,
                "session_ended",
                "session is not open for attach",
            ));
        }
        let root_identity = check_pid_owner(caller, pid, true)?;
        let root_hint =
            crate::sample::root_hint(pid, None).filter(|hint| hint.uid == root_identity);
        let target = SampleTarget {
            db_id,
            public_id: sid.to_owned(),
            name,
            mode: if mode == "launch" { "launch" } else { "attach" },
            root_pid: pid,
            user_id: owner,
            argv_json: None,
            agent,
            write_session_row: false,
            root_hint,
            root_identity: Some(root_identity),
        };
        state.watch_requests.push(WatchRequest::Start {
            target: Box::new(target),
            child: None,
            deadline_ns: None,
        });
        Ok(ApiResponse::json(
            200,
            &json!({ "id": sid, "root_pid": pid }),
        ))
    };
    match inner(state) {
        Ok(response) | Err(response) => response,
    }
}

/// After `POST /sessions/{sid}/stop` marked the row ended: stop its samplers.
pub(super) fn stopped(state: &mut ApiState, sid: &str) {
    state.pending_launches.remove(sid);
    let Some(path) = state.query.db_path.clone() else {
        return;
    };
    let Ok(conn) =
        aw_store::open_connection_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
    else {
        return;
    };
    if let Ok(db_id) = conn.query_row(
        "SELECT id FROM sessions WHERE public_id = ?1",
        [sid],
        |row| row.get::<_, i64>(0),
    ) {
        state.watch_requests.push(WatchRequest::Stop { db_id });
    }
}

/// The route created a session but its success response could not reach the
/// peer (for example, the CLI was killed while SQLite was busy).  Do not leave
/// that unacknowledged recording session open: mark it as an attach failure,
/// remove its pending work, and stop an already-started sampler if necessary.
///
/// This is called only by transport writers after a failed write of a 201.
pub(super) fn reply_delivery_failed(
    state: &mut ApiState,
    request: &super::routes::HttpRequest,
    response: &ApiResponse,
) {
    if request.method != "POST"
        || !matches!(
            request.path.as_str(),
            "/api/v1/sessions" | "/api/v1/sessions/run"
        )
        || response.status != 201
    {
        return;
    }
    let Some(public_id) = serde_json::from_slice::<Value>(&response.body)
        .ok()
        .and_then(|body| body.get("id").and_then(Value::as_str).map(str::to_owned))
    else {
        return;
    };
    state.pending_scans.remove(&public_id);
    state.pending_launches.remove(&public_id);
    // Prevent a queued scan from starting after the client has gone away.
    state.watch_requests.retain(|pending| {
        !matches!(pending, WatchRequest::Start { target, .. } if target.public_id == public_id)
    });
    state.undelivered_sessions.insert(public_id.clone());
    close_undelivered_session(state, &public_id);
}

/// Retry every failed-delivery close that a temporary database lock delayed.
/// The foreground watcher calls this every tick; daemon restart recovery is a
/// final backstop if the daemon stops before a retry can succeed.
pub(crate) fn retry_undelivered_sessions(state: &mut ApiState) {
    let pending: Vec<String> = state.undelivered_sessions.iter().cloned().collect();
    for public_id in pending {
        close_undelivered_session(state, &public_id);
    }
}

fn close_undelivered_session(state: &mut ApiState, public_id: &str) {
    let Some(path) = state.query.db_path.clone() else {
        return;
    };
    let Ok(conn) = aw_store::open_connection(&path) else {
        tracing::error!("could not open database to close undelivered session reply");
        return;
    };
    let db_id: Option<i64> = conn
        .query_row(
            "SELECT id FROM sessions WHERE public_id = ?1",
            [public_id],
            |row| row.get(0),
        )
        .ok();
    let Ok(updated) = conn.execute(
        "UPDATE sessions SET ended_ns = ?1, end_reason = 'attach_failed' \
         WHERE public_id = ?2 AND ended_ns IS NULL",
        rusqlite::params![now_ns(), public_id],
    ) else {
        tracing::error!("could not close undelivered session reply");
        return;
    };
    if updated == 1 {
        if let Some(db_id) = db_id {
            state.watch_requests.push(WatchRequest::Stop { db_id });
        }
        tracing::warn!(
            "session creation reply was not delivered; recording ended as attach_failed"
        );
    }
    // A row already ended is also resolved: do not retry it forever.
    state.undelivered_sessions.remove(public_id);
}

/// A failed `spawn` as an error the UI can word. The code says what went
/// wrong (`program_not_found` covers a missing program and a missing working
/// directory, which the OS reports alike); the message stays plain English for
/// API callers. It used to be `spawn_failed` with the raw `ErrorKind` text
/// ("entity not found"), which the page printed as is.
fn spawn_error(
    step: &str,
    cwd: Option<&str>,
    argv: &[String],
    err: &std::io::Error,
) -> ApiResponse {
    // The step comes from the child, after it switched identity. A missing
    // directory and a missing program are different sentences; the English
    // message stays for the log, and the code is what the UI words.
    if step == "chdir" {
        let dir = cwd.unwrap_or(".");
        return match err.kind() {
            std::io::ErrorKind::PermissionDenied => error_response(
                400,
                "program_not_permitted",
                &format!("没有权限进入工作目录「{dir}」，请换一个目录或检查权限。"),
            ),
            _ => error_response(400, "cwd_not_found", &format!("找不到工作目录「{dir}」")),
        };
    }
    let program = argv.first().map(String::as_str).unwrap_or("");
    match err.kind() {
        std::io::ErrorKind::NotFound => error_response(
            400,
            "program_not_found",
            &format!("找不到程序「{program}」，请检查名字或路径"),
        ),
        std::io::ErrorKind::PermissionDenied => error_response(
            400,
            "program_not_permitted",
            &format!("程序「{program}」没有执行权限，请检查文件权限后再试。"),
        ),
        _ => error_response(400, "spawn_failed", "the program could not be started"),
    }
}

#[cfg(test)]
mod spawn_error_tests {
    use super::spawn_error;

    fn code(kind: std::io::ErrorKind) -> String {
        let response = spawn_error(
            "exec",
            None,
            &["tool".to_owned()],
            &std::io::Error::from(kind),
        );
        let body: serde_json::Value =
            serde_json::from_slice(&response.body).unwrap_or(serde_json::Value::Null);
        body["error"]["code"].as_str().unwrap_or("").to_owned()
    }

    /// UI re-review #144 new-1: a wrong program showed
    /// 「could not start the program: entity not found」.
    #[test]
    fn spawn_failures_carry_a_code_the_ui_can_word() {
        assert_eq!(code(std::io::ErrorKind::NotFound), "program_not_found");
        assert_eq!(
            code(std::io::ErrorKind::PermissionDenied),
            "program_not_permitted"
        );
        assert_eq!(code(std::io::ErrorKind::Other), "spawn_failed");
        let response = spawn_error(
            "exec",
            None,
            &["tool".to_owned()],
            &std::io::Error::from(std::io::ErrorKind::NotFound),
        );
        assert_eq!(response.status, 400);
        let text = String::from_utf8_lossy(&response.body);
        assert!(!text.contains("entity"), "{text}");
        assert!(
            text.contains("找不到程序「tool」，请检查名字或路径"),
            "{text}"
        );
        // A missing working directory is a different sentence and a different code.
        let missing_dir = spawn_error(
            "chdir",
            Some("/no/such/work"),
            &["tool".to_owned()],
            &std::io::Error::from(std::io::ErrorKind::NotFound),
        );
        let body: serde_json::Value =
            serde_json::from_slice(&missing_dir.body).unwrap_or(serde_json::Value::Null);
        assert_eq!(body["error"]["code"], "cwd_not_found");
        assert_eq!(body["error"]["message"], "找不到工作目录「/no/such/work」");
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod database_busy_tests {
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use rusqlite::{Transaction, TransactionBehavior};

    use super::{insert_session, reply_delivery_failed, ApiResponse, ApiState, SampleTarget};

    #[test]
    fn lock_past_busy_timeout_returns_db_busy_with_measured_wait() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("aw-db-busy-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("test directory");
        let path = dir.join("agentwatch.db");
        drop(aw_store::Store::open_runtime(&path).expect("runtime store"));

        let (ready_tx, ready_rx) = mpsc::channel();
        let writer_path = path.clone();
        let writer = thread::spawn(move || {
            let conn = aw_store::open_connection(&writer_path).expect("writer connection");
            let tx = Transaction::new_unchecked(&conn, TransactionBehavior::Immediate)
                .expect("begin immediate");
            tx.execute(
                "INSERT INTO schema_meta (key, value) VALUES ('busy-test', '1')",
                [],
            )
            .expect("writer row");
            ready_tx.send(()).expect("signal writer");
            // Keep the lock well beyond the connection's busy timeout.  A
            // one-second margin raced on macOS, where setup before the write
            // can take long enough for the writer to release first.
            thread::sleep(aw_store::BUSY_TIMEOUT + Duration::from_secs(3));
            tx.commit().expect("writer commit");
        });
        ready_rx.recv().expect("writer ready");

        let mut target = SampleTarget {
            db_id: 0,
            public_id: "s-busy".to_owned(),
            name: None,
            mode: "attach",
            root_pid: 1,
            user_id: "test".to_owned(),
            argv_json: None,
            agent: None,
            write_session_row: true,
            root_hint: None,
            root_identity: None,
        };
        let response = insert_session(&path, &mut target).expect_err("busy response");
        assert_eq!(response.status, 503);
        let body: serde_json::Value = serde_json::from_slice(&response.body).expect("busy JSON");
        assert_eq!(body["error"]["code"], "db_busy");
        let waited = body["error"]["waited_seconds"]
            .as_u64()
            .expect("measured seconds");
        assert!(waited >= aw_store::BUSY_TIMEOUT.as_secs());
        assert_eq!(
            body["error"]["message"],
            format!("会话数据库正忙（后台在写入），等了 {waited} 秒还是没轮到，请稍后再试。")
        );
        assert!(body["error"]["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("database is locked")
                || detail.contains("database is busy")));
        writer.join().expect("writer thread");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn undelivered_creation_reply_ends_the_new_session_as_attach_failed() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("aw-undelivered-{nanos}"));
        std::fs::create_dir_all(&dir).expect("test directory");
        let path = dir.join("agentwatch.db");
        let mut state = ApiState::default();
        state.query = super::super::StoreQuery::open_path(path.clone());
        let mut target = SampleTarget {
            db_id: 0,
            public_id: "s-undelivered".to_owned(),
            name: None,
            mode: "attach",
            root_pid: 1,
            user_id: "test".to_owned(),
            argv_json: None,
            agent: None,
            write_session_row: true,
            root_hint: None,
            root_identity: None,
        };
        insert_session(&path, &mut target).expect("session row");
        state.pending_scans.insert(target.public_id.clone());
        let request = super::super::routes::HttpRequest {
            method: "POST".to_owned(),
            path: "/api/v1/sessions".to_owned(),
            ..super::super::routes::HttpRequest::default()
        };
        let response = ApiResponse::json(201, &serde_json::json!({ "id": target.public_id }));
        reply_delivery_failed(&mut state, &request, &response);

        let conn = aw_store::open_connection(&path).expect("connection");
        let ended: (Option<i64>, Option<String>) = conn
            .query_row(
                "SELECT ended_ns, end_reason FROM sessions WHERE public_id = 's-undelivered'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("ended session");
        assert!(ended.0.is_some());
        assert_eq!(ended.1.as_deref(), Some("attach_failed"));
        assert!(state.pending_scans.is_empty());
        assert!(state.undelivered_sessions.is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }
}

#[cfg(all(test, target_os = "linux"))]
#[allow(clippy::expect_used)]
mod ownership_tests {
    use super::{check_pid_owner, Caller};

    #[cfg(target_os = "linux")]
    #[test]
    fn adopted_pid_requires_all_uids_and_accepts_a_real_child() {
        let caller = Caller {
            user_id: crate::sample::current_user_id(),
            admin: false,
            peer: None,
        };
        let mut child = std::process::Command::new("sleep")
            .arg("5")
            .spawn()
            .expect("spawn child");
        assert!(check_pid_owner(&caller, child.id(), false).is_ok());
        let _ = child.kill();
        let _ = child.wait();

        let result = check_pid_owner(&caller, 1, false);
        if nix::unistd::geteuid().as_raw() == 0 {
            assert!(result.is_ok(), "root caller may adopt pid 1");
        } else {
            let response = result.expect_err("non-root caller must not adopt pid 1");
            assert_eq!(response.status, 403);
            let body: serde_json::Value = serde_json::from_slice(&response.body).expect("JSON");
            assert_eq!(body["error"]["code"], "not_your_process");
        }
    }
}
