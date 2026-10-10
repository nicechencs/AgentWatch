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
//! - Only Linux reads process identity for the poll sampler today; elsewhere
//!   these routes answer 503 `collector_unavailable` and create nothing.

use serde_json::{json, Value};

use super::auth::{random_secret, Caller};
use super::routes::{error_response, ApiResponse, ApiState};
use crate::sample::SampleTarget;
use crate::watch::{now_ns, PendingLaunch, WatchRequest, ADOPT_TIMEOUT_NS};

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

fn collector_available() -> Result<(), ApiResponse> {
    if cfg!(target_os = "linux") {
        Ok(())
    } else {
        Err(error_response(
            503,
            "collector_unavailable",
            "the poll sampler reads process identity only on Linux in this build",
        ))
    }
}

/// Real uid of `pid`: the first field of the `Uid:` line in
/// `/proc/<pid>/status` (real, not effective). Not the owner of the `/proc/<pid>`
/// directory, which is root for every process. `None` when the line cannot be read.
fn pid_owner(pid: u32) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        let line = status.lines().find(|line| line.starts_with("Uid:"))?;
        let real = line[4..].split_whitespace().next()?;
        real.parse::<u32>().ok().map(|uid| uid.to_string())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        None
    }
}

/// The pid must be running and identifiable, and its real uid must be the
/// caller's. `allow_admin` lets an administrator attach to another account's
/// process; adopt never does (`allow_admin` false), so an administrator cannot
/// take over a process that belongs to someone else.
fn check_pid_owner(caller: &Caller, pid: u32, allow_admin: bool) -> Result<(), ApiResponse> {
    collector_available()?;
    if crate::sample::proc_uid_of(pid).is_none() {
        return Err(error_response(
            400,
            "no_such_process",
            "pid is not running (or its identity cannot be read)",
        ));
    }
    let owner = pid_owner(pid);
    if owner.as_deref() == Some(caller.user_id.as_str()) || (allow_admin && caller.admin) {
        return Ok(());
    }
    let message = if allow_admin {
        "这个进程不属于你的账户；记录别的账户的进程需要管理员权限"
    } else {
        "这个进程不属于你的账户，不能接管"
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

/// Allocate `sessions.id` and insert the row. Id 1 stays the daemon sample's.
fn insert_session(path: &std::path::Path, target: &mut SampleTarget) -> Result<(), ApiResponse> {
    let store_error = |what: &str| error_response(500, "store", what);
    let mut store =
        aw_store::Store::open(path).map_err(|_| store_error("cannot open the database"))?;
    let max: i64 = store
        .connection()
        .query_row("SELECT COALESCE(MAX(id), 1) FROM sessions", [], |row| {
            row.get(0)
        })
        .map_err(|_| store_error("cannot read session ids"))?;
    target.db_id = max.max(1).saturating_add(1);
    let mut batch = aw_store::WriteBatch::default();
    batch.sessions.push(target.session_row(now_ns()));
    let mut sink =
        aw_store::SqliteSink::new(&mut store).map_err(|_| store_error("cannot open the writer"))?;
    use aw_store::RecordSink;
    sink.write_batch(&batch)
        .map_err(|_| store_error("cannot write the session row"))?;
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
    })
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
            check_pid_owner(caller, pid, true)?;
            let mut target = target_for(caller, &value, "attach", pid, None)?;
            insert_session(&path, &mut target)?;
            let response = created(&target, json!({}));
            state.watch_requests.push(WatchRequest::Start {
                target: Box::new(target),
                child: None,
            });
            Ok(response)
        }
        Some("launch") => {
            let argv = argv_field(&value)?;
            collector_available()?;
            // Whose account: only the OS-verified caller (see `launch_as`).
            // A `uid` / `user` in the body is never read.
            let who = super::launch_as::identity_for(&caller.user_id, daemon_uid())?;
            let cwd = opt_text(&value, "cwd");
            let env: Vec<(String, String)> = value
                .get("env")
                .and_then(Value::as_object)
                .map(|env| {
                    env.iter()
                        .filter_map(|(key, val)| val.as_str().map(|v| (key.clone(), v.to_owned())))
                        .collect()
                })
                .unwrap_or_default();
            #[allow(unused_mut)]
            let mut child = match &who {
                #[cfg(unix)]
                Some(who) => super::launch_as::spawn_as(who, &argv, cwd.as_deref(), &env)
                    .map_err(|err| match err {
                        super::launch_as::SpawnAsError::Program(err) => spawn_error(&err),
                        super::launch_as::SpawnAsError::Drop(step) => {
                            tracing::error!(uid = who.uid, step, "account switch failed");
                            error_response(
                                500,
                                "drop_failed",
                                "the program did not switch to the caller's account and was stopped",
                            )
                        }
                    })?,
                // No account switch here: never start it as the service account.
                #[cfg(not(unix))]
                Some(_) => return Err(super::launch_as::no_account_switch()),
                None => {
                    let mut command = std::process::Command::new(&argv[0]);
                    command
                        .args(&argv[1..])
                        .stdin(std::process::Stdio::null())
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null());
                    if let Some(cwd) = &cwd {
                        command.current_dir(cwd);
                    }
                    command.envs(env.iter().map(|(k, v)| (k, v)));
                    command.spawn().map_err(|err| spawn_error(&err))?
                }
            };
            let pid = child.id();
            #[cfg(target_os = "linux")]
            if let Some(who) = &who {
                if !super::launch_as::verify_dropped(pid, who) {
                    let _ = child.kill();
                    let _ = child.wait();
                    tracing::error!(
                        pid,
                        uid = who.uid,
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
            insert_session(&path, &mut target)?;
            let response = created(&target, json!({}));
            state.watch_requests.push(WatchRequest::Start {
                target: Box::new(target),
                child: Some(child),
            });
            Ok(response)
        }
        _ => Err(error_response(
            400,
            "bad_argument",
            "mode: expected \"attach\" or \"launch\"",
        )),
    }
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
        check_pid_owner(caller, pid, false)?;
        let root_hint = argv0_basename(pending.target.argv_json.as_deref())
            .and_then(|name| crate::sample::root_hint(pid, name));
        let Some(mut pending) = state.pending_launches.remove(sid) else {
            return Err(not_found());
        };
        pending.target.root_pid = pid;
        pending.target.root_hint = root_hint;
        // Write the root's row now, while `aw run` still holds it at the gate:
        // the foreground loop starts the sampler up to a poll later, and a
        // root that exits (and posts `/exit`) before then would otherwise be
        // zero processes with no exit code. The sampler's row is the same id.
        if pending.target.root_hint.is_some() {
            if let Ok(path) = db_path(state) {
                let _ = crate::sample::HostSampler::for_target(path, pending.target.clone())
                    .persist_root_hint();
            }
        }
        let response = ApiResponse::json(200, &json!({ "id": sid, "root_pid": pid }));
        state.watch_requests.push(WatchRequest::Start {
            target: Box::new(pending.target),
            child: None,
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
        let conn = rusqlite::Connection::open(&path)
            .map_err(|_| error_response(500, "store", "cannot open the database"))?;
        let row: Option<(i64, String)> = conn
            .query_row(
                "SELECT id, user_id FROM sessions WHERE public_id = ?1",
                [sid],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .ok();
        let Some((db_id, owner)) = row else {
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
        // The launched root (depth 0) carries the same status; children stay
        // NULL (not observed), never 0.
        let _ = conn.execute(
            "UPDATE processes SET exit_code = ?1 \
             WHERE session_id = ?2 AND depth = 0 AND exit_code IS NULL",
            rusqlite::params![exit_code, db_id],
        );
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
        let conn = rusqlite::Connection::open_with_flags(
            &path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
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
        check_pid_owner(caller, pid, true)?;
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
            root_hint: None,
        };
        state.watch_requests.push(WatchRequest::Start {
            target: Box::new(target),
            child: None,
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
        rusqlite::Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
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

/// A failed `spawn` as an error the UI can word. The code says what went
/// wrong (`program_not_found` covers a missing program and a missing working
/// directory, which the OS reports alike); the message stays plain English for
/// API callers. It used to be `spawn_failed` with the raw `ErrorKind` text
/// ("entity not found"), which the page printed as is.
fn spawn_error(err: &std::io::Error) -> ApiResponse {
    match err.kind() {
        std::io::ErrorKind::NotFound => error_response(
            400,
            "program_not_found",
            "the program or the working directory was not found",
        ),
        std::io::ErrorKind::PermissionDenied => error_response(
            400,
            "program_not_permitted",
            "the program or the working directory is not accessible to this account",
        ),
        _ => error_response(400, "spawn_failed", "the program could not be started"),
    }
}

#[cfg(test)]
mod spawn_error_tests {
    use super::spawn_error;

    fn code(kind: std::io::ErrorKind) -> String {
        let response = spawn_error(&std::io::Error::from(kind));
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
        let response = spawn_error(&std::io::Error::from(std::io::ErrorKind::NotFound));
        assert_eq!(response.status, 400);
        assert!(!String::from_utf8_lossy(&response.body).contains("entity"));
    }
}
