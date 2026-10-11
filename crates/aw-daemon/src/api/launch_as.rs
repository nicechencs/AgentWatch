//! Whose account a program started from the UI runs under.
//!
//! The identity is the caller's, and the caller comes only from the operating
//! system: the internal channel's peer credential (`SO_PEERCRED` on Linux), or
//! a UI token that was issued over that channel to that peer. Nothing in the
//! request body names a user; a `uid` / `user` field there is ignored.
//!
//! - Caller is the daemon's own account: started as is.
//! - Daemon runs as root, caller is another account (Linux): the daemon starts
//!   a short-lived copy of itself (`agentwatchd __launch-as`, the account and
//!   the program on its stdin, never on its command line). Still root, that
//!   helper sets the caller's groups as a login would (`getgrouplist` for the
//!   account's name and primary group: `setgroups(those)`), then `setgid`,
//!   then `setuid`. It then checks that real, effective and saved uid/gid are
//!   all the caller's, that its group list is exactly the login list, and
//!   that `setuid(0)` / `setgid(0)` now fail; only then does it `exec` the
//!   program with the caller's environment and `cwd` (the directory is entered
//!   as the caller). A failure before `exec` is reported back on a
//!   close-on-exec pipe, so the daemon sees "started" only once the program
//!   itself runs. The daemon then reads `/proc/<pid>/status` again and kills
//!   the program unless all four uids and gids and the group list are the
//!   caller's.
//! - Daemon runs as root on macOS: `aw-platform` forks the program and the
//!   child switches with `setgroups` / `setgid` / `setuid` before it execs,
//!   and only after the switch sticks (【待验证】, not run on a real Mac). The
//!   session route still answers 503 before reaching it, because the poll
//!   sampler is Linux-only.
//! - Unknown identity (not a number, no passwd entry, group list unreadable),
//!   a non-root daemon asked to start a program for another account, or any
//!   platform without a Unix account switch (Windows: no caller-token launch
//!   yet): refused with 403. There is never a fall back to the daemon's
//!   account.

use std::path::PathBuf;

use super::routes::{error_response, ApiResponse};

/// The account a launch drops to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Identity {
    pub uid: u32,
    pub gid: u32,
    /// Login group list: `gid` first, then the supplementary groups from the
    /// group database, no repeats.
    pub groups: Vec<u32>,
    pub name: String,
    pub home: PathBuf,
    pub shell: PathBuf,
}

#[cfg(unix)]
/// Default `PATH` for a dropped launch. Defined once, in the shared launch
/// code (`unix/hold.rs`): the caller's own shell `PATH` is not known to the
/// daemon, and the daemon's own `PATH` is not copied. A request that sets
/// `PATH` itself is refused (`env_reserved`), not applied over this.
pub(crate) const DEFAULT_PATH: &str = aw_platform::unix_default_path();

#[cfg(target_os = "linux")]
/// First argument of the helper copy of `agentwatchd` (Linux root launch).
pub(crate) const HELPER_ARG: &str = "__launch-as";

/// 403 where this build cannot start a program under the caller's account.
pub(crate) fn no_account_switch() -> ApiResponse {
    error_response(
        403,
        "launch_identity_unsupported",
        "this platform cannot start a program under the caller's account",
    )
}

/// `None`: start as the daemon (same account). `Some`: drop to that account.
pub(crate) fn identity_for(
    caller_user_id: &str,
    daemon_uid: u32,
) -> Result<Option<Identity>, ApiResponse> {
    if !cfg!(unix) {
        // No caller-token launch on this platform: refuse instead of letting a
        // "same account" match start the program as the service account.
        return Err(no_account_switch());
    }
    let uid = caller_uid(caller_user_id)?;
    if uid == daemon_uid {
        return Ok(None);
    }
    require_daemon_owner_uid(uid, daemon_uid)?;
    lookup(uid).map(Some)
}

/// Refuse a non-root daemon's request to create a launch session for a
/// different Unix account. This applies to both daemon-spawned launches and
/// `aw run`: the latter creates the program locally, but must not create a
/// session that a non-root daemon cannot own on behalf of another user.
pub(crate) fn require_daemon_owner(
    caller_user_id: &str,
    daemon_uid: u32,
) -> Result<(), ApiResponse> {
    require_daemon_owner_uid(caller_uid(caller_user_id)?, daemon_uid)
}

fn caller_uid(caller_user_id: &str) -> Result<u32, ApiResponse> {
    caller_user_id.parse::<u32>().map_err(|_| {
        error_response(
            403,
            "caller_unidentified",
            "the caller's account could not be identified",
        )
    })
}

fn require_daemon_owner_uid(caller_uid: u32, daemon_uid: u32) -> Result<(), ApiResponse> {
    if caller_uid == daemon_uid || daemon_uid == 0 {
        return Ok(());
    }
    Err(daemon_owner_only(daemon_uid))
}

fn daemon_owner_only(daemon_uid: u32) -> ApiResponse {
    let owner = daemon_owner_name(daemon_uid);
    daemon_owner_only_named(owner)
}

fn daemon_owner_only_named(owner: String) -> ApiResponse {
    let message = format!(
        "这个后台是「{owner}」自己运行的，只能替「{owner}」启动程序，已拒绝。请用你自己运行的后台，或者用管理员运行的后台。"
    );
    let response = error_response(403, "daemon_owner_only", &message);
    let Ok(mut body) = serde_json::from_slice::<serde_json::Value>(&response.body) else {
        return response;
    };
    body["error"]["detail"] = serde_json::json!({ "daemon_owner": owner });
    ApiResponse::json(403, &body)
}

#[cfg(unix)]
fn daemon_owner_name(daemon_uid: u32) -> String {
    daemon_owner_name_from(daemon_uid, || {
        nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(daemon_uid))
            .ok()
            .flatten()
            .map(|user| user.name)
    })
}

fn daemon_owner_name_from(daemon_uid: u32, lookup: impl FnOnce() -> Option<String>) -> String {
    lookup().unwrap_or_else(|| daemon_uid.to_string())
}

#[cfg(not(unix))]
fn daemon_owner_name(daemon_uid: u32) -> String {
    daemon_uid.to_string()
}

#[cfg(unix)]
/// Login group list from the primary group and the database answer:
/// primary first, the rest in database order, each group once.
pub(crate) fn login_groups(primary: u32, from_db: &[u32]) -> Vec<u32> {
    let mut groups = vec![primary];
    for gid in from_db {
        if !groups.contains(gid) {
            groups.push(*gid);
        }
    }
    groups
}

/// Supplementary groups of `name` as a login sets them (`getgrouplist`).
#[cfg(target_os = "linux")]
fn group_db(name: &str, gid: u32) -> Option<Vec<u32>> {
    let name = std::ffi::CString::new(name).ok()?;
    let list = nix::unistd::getgrouplist(&name, nix::unistd::Gid::from_raw(gid)).ok()?;
    Some(list.into_iter().map(|g| g.as_raw()).collect())
}

/// macOS: std clears supplementary groups on `uid()`; the list is the primary.
#[cfg(all(unix, not(target_os = "linux")))]
fn group_db(_name: &str, gid: u32) -> Option<Vec<u32>> {
    Some(vec![gid])
}

#[cfg(unix)]
fn lookup(uid: u32) -> Result<Identity, ApiResponse> {
    let unknown = || {
        error_response(
            403,
            "caller_unknown",
            "the caller's account has no entry in the user database",
        )
    };
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
        .ok()
        .flatten()
        .ok_or_else(unknown)?;
    let gid = user.gid.as_raw();
    let from_db = group_db(&user.name, gid).ok_or_else(|| {
        error_response(
            403,
            "caller_groups_unknown",
            "the caller's group list could not be read",
        )
    })?;
    Ok(Identity {
        uid,
        gid,
        groups: login_groups(gid, &from_db),
        name: user.name,
        home: user.dir,
        shell: user.shell,
    })
}

#[cfg(not(unix))]
fn lookup(_uid: u32) -> Result<Identity, ApiResponse> {
    Err(no_account_switch())
}

/// This daemon's own account, for a same-uid launch that still has to name a
/// home and a shell. macOS uses it; the caller id is the one the peer credential
/// already produced.
#[cfg(target_os = "macos")]
pub(crate) fn own_account(user_id: &str) -> Result<Identity, ApiResponse> {
    let uid = user_id.parse::<u32>().map_err(|_| {
        error_response(
            403,
            "caller_unidentified",
            "the caller's account could not be identified",
        )
    })?;
    lookup(uid)
}

/// This daemon's own account, read from the process's real uid. Linux uses it
/// when the caller is the daemon's own account: the launch still goes through
/// the helper, so the environment is the account's five basics rather than
/// whatever this process was started with.
#[cfg(target_os = "linux")]
pub(crate) fn own_account_of_self() -> Result<Identity, ApiResponse> {
    lookup(nix::unistd::getuid().as_raw())
}

/// A request that names one of the account-base environment variables. The
/// launch is refused rather than started with the name silently dropped or
/// quietly overridden.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ReservedEnvVar {
    pub name: String,
}

/// The first reserved name in `extra`, if the request sets one. `None` when
/// every name is one the request is allowed to add.
pub(crate) fn reserved_env_var(extra: &[(String, String)]) -> Option<ReservedEnvVar> {
    extra.iter().find_map(|(key, _)| {
        aw_platform::is_reserved_env_name(
            key,
            aw_platform::environment_names_are_case_insensitive(),
        )
        .then(|| ReservedEnvVar { name: key.clone() })
    })
}

/// 400 for a launch request that sets a reserved variable. The sentence names
/// the variable; the machine code carries it again under `detail.name`.
pub(crate) fn reserved_env_response(name: &str) -> ApiResponse {
    let mut response = error_response(
        400,
        "env_reserved",
        &format!("环境变量「{name}」由系统按你的账户来填，不能在请求里改。请去掉这个变量再试。"),
    );
    if let Ok(mut body) = serde_json::from_slice::<serde_json::Value>(&response.body) {
        body["error"]["detail"] = serde_json::json!({ "name": name });
        response = ApiResponse::json(response.status, &body);
    }
    response
}

/// Environment a dropped launch starts with, built from scratch: the target
/// account's `HOME`/`USER`/`LOGNAME`/`SHELL`, the fixed `PATH`, then the
/// request's `env`. The daemon's own environment is not read. A root daemon's
/// `HOME`, sockets, and tokens therefore cannot reach the child.  The App and
/// CLI may explicitly forward the caller's `LANG`/`LC_ALL`/`TZ` as request
/// values; they are ordinary, non-reserved additions.
///
/// `extra` must already have been checked with [`reserved_env_var`]: this
/// refuses to merge a reserved name rather than override the account's value.
#[cfg(unix)]
fn base_env(who: &Identity, extra: &[(String, String)]) -> Vec<(String, String)> {
    let path = |p: &std::path::Path| p.display().to_string();
    let mut env = vec![
        ("HOME".to_owned(), path(&who.home)),
        ("USER".to_owned(), who.name.clone()),
        ("LOGNAME".to_owned(), who.name.clone()),
        ("SHELL".to_owned(), path(&who.shell)),
        ("PATH".to_owned(), DEFAULT_PATH.to_owned()),
    ];
    for (key, val) in extra {
        // A reserved name never replaces the account's value. The route refuses
        // the request before it gets here; skipping is the backstop.
        if aw_platform::is_reserved_env_name(
            key,
            aw_platform::environment_names_are_case_insensitive(),
        ) {
            continue;
        }
        env.retain(|(k, _)| k != key);
        env.push((key.clone(), val.clone()));
    }
    env
}

#[cfg(unix)]
/// Why a dropped launch did not start.
#[derive(Debug)]
// macOS only ever builds `Program`; the match in the route covers both.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) enum SpawnAsError {
    /// The program or `cwd` (entered as the caller): the usual 400 codes.
    /// `step` is `chdir` or `exec`, so the two are not the same sentence.
    Program {
        step: &'static str,
        error: std::io::Error,
    },
    /// A Unix held child reported its `chdir`/`execve` failure through the
    /// close-on-exec pipe.  Preserve the classification to the route.
    TypedProgram(aw_platform::SpawnFailure),
    /// The account switch itself failed or could not be checked: 500.
    Drop(String),
}

/// Start `argv` as the current account with the from-scratch environment.
///
/// Used when the caller is already this account and this process is not root,
/// so there is no switch to make and `setgroups` would fail. The candidate
/// search is the same one the helper uses, and it runs as this account.
#[cfg(target_os = "linux")]
pub(crate) fn spawn_exact(
    who: &Identity,
    argv: &[String],
    cwd: Option<&str>,
    extra_env: &[(String, String)],
) -> Result<std::process::Child, SpawnAsError> {
    use std::process::{Command, Stdio};
    let env = base_env(who, extra_env);
    let dir = cwd.map_or_else(|| who.home.display().to_string(), str::to_owned);
    // Already the right account, so this check is the caller's and not root's.
    // It is what makes a missing directory a different error from a missing
    // program: `Command` reports both as one spawn error.
    if let Err(error) = std::fs::metadata(&dir) {
        return Err(SpawnAsError::Program {
            step: "chdir",
            error,
        });
    }
    let path = env
        .iter()
        .rev()
        .find(|(key, _)| key == "PATH")
        .map(|(_, value)| value.clone());
    let candidates = aw_platform::unix_program_candidates(&argv[0], path.as_deref());
    if candidates.is_empty() {
        return Err(SpawnAsError::Program {
            step: "exec",
            error: std::io::Error::from_raw_os_error(ENOENT),
        });
    }
    let mut last = std::io::Error::from_raw_os_error(ENOENT);
    for candidate in &candidates {
        match Command::new(candidate)
            .args(&argv[1..])
            .env_clear()
            .envs(env.iter().map(|(k, v)| (k, v)))
            .current_dir(&dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(child) => return Ok(child),
            Err(error) => {
                let errno = error.raw_os_error().unwrap_or(EIO);
                if matches!(errno, ENOENT | ENOTDIR | ESTALE | ENODEV | ETIMEDOUT) {
                    last = error;
                    continue;
                }
                return Err(SpawnAsError::Program {
                    step: "exec",
                    error,
                });
            }
        }
    }
    Err(SpawnAsError::Program {
        step: "exec",
        error: last,
    })
}

/// Start `argv` as `who` (Linux, root daemon) through the helper. Returns once
/// the program has been `exec`'d under the caller's ids, or with the reason
/// it was not.
#[cfg(target_os = "linux")]
pub(crate) fn spawn_as(
    who: &Identity,
    argv: &[String],
    cwd: Option<&str>,
    extra_env: &[(String, String)],
) -> Result<std::process::Child, SpawnAsError> {
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};
    let exe = helper_exe().map_err(|err| SpawnAsError::Drop(format!("helper path: {err}")))?;
    let spec = serde_json::json!({
        "uid": who.uid,
        "gid": who.gid,
        "groups": who.groups,
        "argv": argv,
        "cwd": cwd.map_or_else(|| who.home.display().to_string(), str::to_owned),
        "env": base_env(who, extra_env),
    });
    let mut child = Command::new(exe)
        .arg(HELPER_ARG)
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|err| SpawnAsError::Drop(format!("helper did not start: {err}")))?;
    let fail = |child: &mut std::process::Child, err: SpawnAsError| {
        let _ = child.kill();
        let _ = child.wait();
        Err(err)
    };
    let sent = child
        .stdin
        .take()
        .map(|mut stdin| stdin.write_all(spec.to_string().as_bytes()));
    if !matches!(sent, Some(Ok(()))) {
        return fail(&mut child, SpawnAsError::Drop("helper stdin".to_owned()));
    }
    let mut report = Vec::new();
    let read = child
        .stdout
        .take()
        .map(|mut out| out.read_to_end(&mut report));
    if !matches!(read, Some(Ok(_))) {
        return fail(&mut child, SpawnAsError::Drop("helper report".to_owned()));
    }
    if report.is_empty() {
        // The close-on-exec report pipe closed without a word: `exec` ran.
        return Ok(child);
    }
    let value: serde_json::Value = serde_json::from_slice(&report).unwrap_or_default();
    let err = match value.get("errno").and_then(serde_json::Value::as_i64) {
        Some(errno) => SpawnAsError::Program {
            step: if value.get("step").and_then(serde_json::Value::as_str) == Some("chdir") {
                "chdir"
            } else {
                "exec"
            },
            error: std::io::Error::from_raw_os_error(i32::try_from(errno).unwrap_or(EIO)),
        },
        None => SpawnAsError::Drop(
            value
                .get("drop")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("helper failed")
                .to_owned(),
        ),
    };
    let _ = child.wait();
    Err(err)
}

/// Errnos the candidate search uses. Same values `execvp` uses: "not here" tries
/// the next candidate, `EACCES` is remembered, anything else stops.
#[cfg(target_os = "linux")]
const ENOENT: i32 = 2;
#[cfg(target_os = "linux")]
const EIO: i32 = 5;
#[cfg(target_os = "linux")]
const EACCES: i32 = 13;
#[cfg(target_os = "linux")]
const ENOTDIR: i32 = 20;
#[cfg(target_os = "linux")]
const ENODEV: i32 = 19;
#[cfg(target_os = "linux")]
const ESTALE: i32 = 116;
#[cfg(target_os = "linux")]
const ETIMEDOUT: i32 = 110;

/// The helper binary: this `agentwatchd`. Unit tests run inside the test
/// harness, so they use the `agentwatchd` cargo built next to it.
#[cfg(target_os = "linux")]
fn helper_exe() -> std::io::Result<PathBuf> {
    let exe = std::env::current_exe()?;
    if cfg!(test) {
        let dir = exe.parent().and_then(std::path::Path::parent);
        return dir
            .map(|dir| dir.join("agentwatchd"))
            .ok_or_else(|| std::io::Error::other("no target dir"));
    }
    Ok(exe)
}

/// `agentwatchd __launch-as`: read the spec on stdin, switch account, check
/// the switch, `exec`. Any failure before `exec` is written as one JSON
/// object on a close-on-exec copy of stdout and the helper exits 126.
#[cfg(target_os = "linux")]
pub(crate) fn helper_main() -> std::process::ExitCode {
    use std::io::{Read, Write};
    use std::os::fd::AsFd;
    use std::process::ExitCode;

    // `try_clone_to_owned` duplicates with F_DUPFD_CLOEXEC: `exec` closes it,
    // which is how the daemon learns the program started.
    let Ok(report) = std::io::stdout().as_fd().try_clone_to_owned() else {
        return ExitCode::from(126);
    };
    let mut report = std::fs::File::from(report);
    let mut fail = |value: serde_json::Value| {
        let _ = report.write_all(value.to_string().as_bytes());
        ExitCode::from(126)
    };
    let mut input = String::new();
    if std::io::stdin().read_to_string(&mut input).is_err() {
        return fail(serde_json::json!({"drop": "spec unreadable"}));
    }
    let Ok(spec) = serde_json::from_str::<HelperSpec>(&input) else {
        return fail(serde_json::json!({"drop": "spec malformed"}));
    };
    if !valid_helper_spec(&spec) {
        return fail(serde_json::json!({"drop": "spec refused"}));
    }
    if let Err(step) = switch_account(&spec) {
        return fail(serde_json::json!({ "drop": step }));
    }
    // The switch stuck. Only now is the caller's directory entered and the
    // caller's environment applied, and only to the program being exec'd.
    // `execve` replaces the environment outright, so nothing this root stage
    // was started with (and nothing a caller put in `LD_PRELOAD`) is inherited.
    // The program name is not resolved until here: this process is already the
    // caller, so the search cannot see a directory the caller cannot see.
    let err = exec_as_caller(&spec);
    fail(serde_json::json!({"step": err.step, "errno": err.errno}))
}

/// Why the program did not start, after the account switch. `step` is `chdir`
/// or `exec`, so the caller can tell a missing directory from a missing program.
#[cfg(target_os = "linux")]
struct ExecFailure {
    step: &'static str,
    errno: i32,
}

/// `execve` of the caller's program with the caller's environment. Runs only
/// after [`switch_account`]. Does not return on success.
///
/// The candidate list is the same one the hold stage builds: strings only, no
/// filesystem access. Each candidate is tried after `chdir`, with `execvp`'s
/// errno rules.
#[cfg(target_os = "linux")]
fn exec_as_caller(spec: &HelperSpec) -> ExecFailure {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    // Already the caller's account. Enter the directory as that account, so a
    // directory the caller cannot see fails here and not as a missing program.
    if let Err(error) = std::env::set_current_dir(&spec.cwd) {
        return ExecFailure {
            step: "chdir",
            errno: error.raw_os_error().unwrap_or(ENOENT),
        };
    }
    let path = spec
        .env
        .iter()
        .rev()
        .find(|(key, _)| key == "PATH")
        .map(|(_, value)| value.as_str());
    let candidates = aw_platform::unix_program_candidates(&spec.argv[0], path);
    if candidates.is_empty() {
        return ExecFailure {
            step: "exec",
            errno: ENOENT,
        };
    }
    let mut saw_eacces = false;
    let mut last = ENOENT;
    for candidate in &candidates {
        let err = Command::new(candidate)
            .args(&spec.argv[1..])
            .env_clear()
            .envs(spec.env.iter().map(|(k, v)| (k, v)))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .exec();
        let errno = err.raw_os_error().unwrap_or(EIO);
        if matches!(errno, ENOENT | ENOTDIR | ESTALE | ENODEV | ETIMEDOUT) {
            last = errno;
            continue;
        }
        if errno == EACCES {
            saw_eacces = true;
            last = errno;
            continue;
        }
        return ExecFailure {
            step: "exec",
            errno,
        };
    }
    ExecFailure {
        step: "exec",
        errno: if saw_eacces { EACCES } else { last },
    }
}

#[cfg(target_os = "linux")]
#[derive(serde::Deserialize)]
struct HelperSpec {
    uid: u32,
    gid: u32,
    groups: Vec<u32>,
    argv: Vec<String>,
    cwd: String,
    env: Vec<(String, String)>,
}

/// `setgroups(login list)` → `setgid` → `setuid`, then prove it sticks.
#[cfg(target_os = "linux")]
fn switch_account(spec: &HelperSpec) -> Result<(), &'static str> {
    use nix::unistd::{Gid, Uid};
    let groups: Vec<Gid> = spec.groups.iter().map(|g| Gid::from_raw(*g)).collect();
    nix::unistd::setgroups(&groups).map_err(|_| "setgroups")?;
    nix::unistd::setgid(Gid::from_raw(spec.gid)).map_err(|_| "setgid")?;
    nix::unistd::setuid(Uid::from_raw(spec.uid)).map_err(|_| "setuid")?;
    let uids = nix::unistd::getresuid().map_err(|_| "getresuid")?;
    let gids = nix::unistd::getresgid().map_err(|_| "getresgid")?;
    let uid_ok = [uids.real, uids.effective, uids.saved]
        .iter()
        .all(|u| u.as_raw() == spec.uid);
    let gid_ok = [gids.real, gids.effective, gids.saved]
        .iter()
        .all(|g| g.as_raw() == spec.gid);
    if !uid_ok || !gid_ok {
        return Err("ids not switched");
    }
    let mut have: Vec<u32> = nix::unistd::getgroups()
        .map_err(|_| "getgroups")?
        .into_iter()
        .map(|g| g.as_raw())
        .collect();
    let mut want = spec.groups.clone();
    have.sort_unstable();
    have.dedup();
    want.sort_unstable();
    want.dedup();
    if have != want {
        return Err("groups not switched");
    }
    // A non-root account may legitimately have group 0 as its primary group.
    // Calling setgid(0) is then a no-op it is allowed to make, not a privilege
    // regain. A different primary gid must not be able to switch to gid 0.
    let regained_uid = nix::unistd::setuid(Uid::from_raw(0)).is_ok();
    let regained_gid = root_gid_regained(spec.gid, nix::unistd::setgid(Gid::from_raw(0)).is_ok());
    if regained_uid || regained_gid {
        return Err("root regained");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn valid_helper_spec(spec: &HelperSpec) -> bool {
    spec.uid != 0 && !spec.argv.is_empty() && spec.groups.first() == Some(&spec.gid)
}

#[cfg(target_os = "linux")]
fn root_gid_regained(primary_gid: u32, setgid_succeeded: bool) -> bool {
    primary_gid != 0 && setgid_succeeded
}

/// macOS: `aw-platform` forks and holds the child before exec. The child
/// blocks on a pipe. On release it switches with `setgroups` / `setgid` /
/// `setuid` (skipped when the caller is already this account), checks the
/// switch stuck and that `setuid(0)` fails, and only then enters `cwd` and
/// returns so the target is exec'd with the caller's environment. That
/// environment is applied at exec, never while the child is still root. A
/// failed step exits with its own code (121–127) and the program never runs
/// as root. The returned handle reaps only this child. 【待验证】not run on a
/// real Mac.
///
/// `peer` is the identity `getpeereid` returned for this connection. A caller
/// with no peer (a UI token) cannot be launched: rebuilding the account from
/// the stored user id would make the identity forgeable.
#[cfg(target_os = "macos")]
pub(crate) fn spawn_as(
    peer: aw_platform::PeerIdentity,
    who: &Identity,
    argv: &[String],
    cwd: Option<&str>,
    extra_env: &[(String, String)],
) -> Result<Box<dyn aw_platform::ReleasedChild>, SpawnAsError> {
    let caller = aw_platform::IdentifiedCaller::from_peer(peer);
    let request = aw_platform::SpawnRequest {
        command: argv.to_vec(),
        cwd: Some(cwd.map_or_else(|| who.home.clone(), PathBuf::from)),
        env: base_env(who, extra_env),
        // The daemon may be root. The target gets this list and nothing of the
        // daemon's own environment. `Inherit` is the `aw run` path, not this one.
        env_source: aw_platform::EnvSource::Exact,
    };
    let held = aw_platform::platform()
        .spawn_suspended(&caller, &request)
        .map_err(platform_spawn_error)?;
    // Release consumes the hold. A failure here aborts through Drop: the pipe
    // closes, the stage sees EOF and exits without exec.
    held.release().map_err(platform_spawn_error)
}

#[cfg(target_os = "macos")]
fn platform_spawn_error(error: aw_platform::PlatformError) -> SpawnAsError {
    match error {
        aw_platform::PlatformError::Spawn(kind) => SpawnAsError::TypedProgram(kind),
        aw_platform::PlatformError::Io(inner) => {
            let step = if inner.to_string().starts_with("chdir:") {
                "chdir"
            } else {
                "exec"
            };
            SpawnAsError::Program { step, error: inner }
        }
        other => SpawnAsError::Drop(other.to_string()),
    }
}

/// After a helper spawn: real, effective, saved and filesystem uid/gid of
/// `pid` are all `who`'s, and its group list is exactly `who.groups`. Linux
/// reads `/proc`.
#[cfg(target_os = "linux")]
pub(crate) fn verify_dropped(pid: u32, who: &Identity) -> bool {
    verify_identity(pid, who.uid, who.gid, &who.groups)
}

/// After a same-account direct spawn, verify the child retained this daemon's
/// active identity. In particular, its groups are compared with `getgroups`,
/// not a fresh account-database lookup: the latter may lag a live session or
/// differ under `sg` and containers.
#[cfg(target_os = "linux")]
pub(crate) fn verify_dropped_as_self(pid: u32) -> bool {
    let Ok(groups) = nix::unistd::getgroups() else {
        return false;
    };
    let groups: Vec<u32> = groups.into_iter().map(|group| group.as_raw()).collect();
    verify_identity(
        pid,
        nix::unistd::getuid().as_raw(),
        nix::unistd::getgid().as_raw(),
        &groups,
    )
}

#[cfg(target_os = "linux")]
fn verify_identity(pid: u32, uid: u32, gid: u32, expected_groups: &[u32]) -> bool {
    let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
        return false;
    };
    let ids = |key: &str| -> Option<Vec<u32>> {
        let line = status.lines().find(|line| line.starts_with(key))?;
        line[key.len()..]
            .split_whitespace()
            .map(|part| part.parse().ok())
            .collect()
    };
    let all = |list: Option<Vec<u32>>, want: u32| {
        list.is_some_and(|list| list.len() == 4 && list.iter().all(|id| *id == want))
    };
    let set = |mut list: Vec<u32>| {
        list.sort_unstable();
        list.dedup();
        list
    };
    let groups_ok = ids("Groups:").is_some_and(|groups| {
        // The kernel lists supplementary groups only; the primary may be absent.
        let mut want = expected_groups.to_vec();
        let mut have = groups;
        if !have.contains(&gid) {
            have.push(gid);
        }
        want.push(gid);
        set(have) == set(want)
    });
    all(ids("Uid:"), uid) && all(ids("Gid:"), gid) && groups_ok
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{daemon_owner_name_from, daemon_owner_only_named, identity_for};

    fn code(result: Result<Option<super::Identity>, super::ApiResponse>) -> String {
        match result {
            Err(response) => {
                let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
                body["error"]["code"].as_str().unwrap_or("").to_owned()
            }
            Ok(Some(_)) => "drop".to_owned(),
            Ok(None) => "self".to_owned(),
        }
    }

    #[cfg(unix)]
    #[test]
    fn same_account_starts_as_is() {
        assert_eq!(code(identity_for("1000", 1000)), "self");
        assert_eq!(code(identity_for("0", 0)), "self");
    }

    #[cfg(unix)]
    #[test]
    fn unknown_identity_is_refused_never_root() {
        // Not a uid (an unverified peer, a Windows SID on a Unix build).
        assert_eq!(code(identity_for("", 0)), "caller_unidentified");
        assert_eq!(
            code(identity_for("unverified-peer", 0)),
            "caller_unidentified"
        );
        assert_eq!(code(identity_for("S-1-5-21-1", 0)), "caller_unidentified");
        // A number with no passwd entry.
        assert_eq!(code(identity_for("4294967000", 0)), "caller_unknown");
    }

    #[cfg(unix)]
    #[test]
    fn ordinary_daemon_does_not_start_programs_for_others() {
        assert_eq!(code(identity_for("1001", 1000)), "daemon_owner_only");
        assert_eq!(code(identity_for("0", 1000)), "daemon_owner_only");
    }

    #[test]
    fn daemon_owner_only_uses_the_passwd_username_in_the_refusal() {
        let owner = daemon_owner_name_from(1000, || Some("daemon-owner".to_owned()));
        let response = daemon_owner_only_named(owner);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["error"]["code"], "daemon_owner_only");
        assert_eq!(body["error"]["detail"]["daemon_owner"], "daemon-owner");
        assert_eq!(
            body["error"]["message"],
            "这个后台是「daemon-owner」自己运行的，只能替「daemon-owner」启动程序，已拒绝。请用你自己运行的后台，或者用管理员运行的后台。"
        );
    }

    #[test]
    fn daemon_owner_only_falls_back_to_the_numeric_uid_without_passwd_entry() {
        assert_eq!(daemon_owner_name_from(424_242, || None), "424242");
    }

    /// `verify_dropped` reads a real process: a child of this account passes
    /// for this account with this process's group list, and fails for any
    /// other uid, gid or group list, so a child that kept root (or any other
    /// id or group) is caught.
    #[cfg(target_os = "linux")]
    #[test]
    fn verify_dropped_checks_all_ids_of_a_real_process() {
        let me = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();
        let mine: Vec<u32> = nix::unistd::getgroups()
            .unwrap()
            .into_iter()
            .map(|g| g.as_raw())
            .collect();
        let mut child = std::process::Command::new("sleep")
            .arg("5")
            .spawn()
            .expect("spawn sleep");
        let who = super::Identity {
            uid: me,
            gid,
            groups: super::login_groups(gid, &mine),
            name: "t".to_owned(),
            home: "/".into(),
            shell: "/bin/sh".into(),
        };
        assert!(super::verify_dropped(child.id(), &who));
        let extra_group = super::Identity {
            groups: super::login_groups(gid, &[4_294_960_000]),
            ..who.clone()
        };
        assert!(!super::verify_dropped(child.id(), &extra_group));
        if mine.iter().any(|g| *g != gid) {
            // A child that kept a group the account does not have is caught.
            let primary_only = super::Identity {
                groups: vec![gid],
                ..who.clone()
            };
            assert!(!super::verify_dropped(child.id(), &primary_only));
        }
        let other_uid = super::Identity {
            uid: me.wrapping_add(1),
            ..who.clone()
        };
        assert!(!super::verify_dropped(child.id(), &other_uid));
        let other_gid = super::Identity {
            gid: gid.wrapping_add(1),
            ..who.clone()
        };
        assert!(!super::verify_dropped(child.id(), &other_gid));
        let _ = child.kill();
        let _ = child.wait();
        assert!(!super::verify_dropped(u32::MAX, &who), "no such pid");
    }

    #[cfg(unix)]
    #[test]
    fn login_groups_put_the_primary_first_without_repeats() {
        assert_eq!(super::login_groups(1000, &[]), vec![1000]);
        assert_eq!(super::login_groups(1000, &[1000]), vec![1000]);
        assert_eq!(
            super::login_groups(1000, &[27, 1000, 998, 27]),
            vec![1000, 27, 998]
        );
    }

    /// The group list computed for this account is the one `id -G` reports
    /// for it (the group database, as a login reads it).
    #[cfg(target_os = "linux")]
    #[test]
    fn lookup_reads_the_accounts_login_groups() {
        let me = nix::unistd::getuid().as_raw();
        let who = super::lookup(me).unwrap();
        let out = std::process::Command::new("id")
            .args(["-G", &who.name])
            .output()
            .expect("id -G");
        assert!(out.status.success());
        let mut want: Vec<u32> = String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .map(|g| g.parse().unwrap())
            .collect();
        let mut have = who.groups.clone();
        assert_eq!(have.first(), Some(&who.gid));
        have.sort_unstable();
        want.sort_unstable();
        want.dedup();
        assert_eq!(have, want);
    }

    /// No Unix account switch: every launch identity is refused, including a
    /// caller id that happens to equal the daemon placeholder.
    #[cfg(not(unix))]
    #[test]
    fn without_an_account_switch_launch_is_refused() {
        assert_eq!(
            code(identity_for(&u32::MAX.to_string(), u32::MAX)),
            "launch_identity_unsupported"
        );
        assert_eq!(
            code(identity_for("S-1-5-21-1", u32::MAX)),
            "launch_identity_unsupported"
        );
    }

    /// Root daemon, caller is this test's account: the drop target is that
    /// account with its own home and primary group.
    #[cfg(unix)]
    #[test]
    fn root_daemon_drops_to_the_callers_account() {
        let me = nix::unistd::getuid().as_raw();
        if me == 0 {
            // Root caller of a root daemon is "same account".
            assert_eq!(code(identity_for("0", 0)), "self");
            return;
        }
        let who = identity_for(&me.to_string(), 0).unwrap().unwrap();
        assert_eq!(who.uid, me);
        assert_eq!(who.gid, nix::unistd::getgid().as_raw());
        assert!(!who.name.is_empty());
        assert!(who.home.is_absolute());
        assert_eq!(who.groups.first(), Some(&who.gid));
    }

    /// The helper's own environment is empty: `spawn_as` starts it with
    /// `env_clear`. A caller's `LD_PRELOAD` is data in the spec, not an
    /// environment the root stage runs with.
    ///
    /// The program the helper execs gets exactly the spec's `env` — the base
    /// five plus what the request added — and nothing else. This used to assert
    /// only that the root stage had no preload line; the assertion is now the
    /// whole set, so a leaked daemon variable fails it.
    #[cfg(target_os = "linux")]
    #[test]
    fn caller_preload_does_not_reach_the_root_stage() {
        let preload = "/no/such/libaw-preload.so";
        let me = nix::unistd::getuid().as_raw();
        if me == 0 {
            return;
        }
        std::env::set_var("AW_HOLD_SENTINEL", "present-in-daemon");
        let gid = nix::unistd::getgid().as_raw();
        let groups = nix::unistd::getgroups()
            .unwrap()
            .into_iter()
            .map(|g| g.as_raw())
            .collect::<Vec<_>>();
        // The helper is started with a cleared environment. The caller's
        // preload is in the spec on stdin, which the helper reads as data and
        // does not apply to itself. It then blocks in setgroups (this test is
        // not root), so its environ can be read while it is still the
        // privileged stage. The env the spec carries is the whole set the
        // target would be exec'd with: the base five, plus the two loader
        // names, and nothing of this process.
        let who = super::lookup(me).expect("this account");
        std::env::set_var("LANG", "daemon-lang");
        let mut env = super::base_env(&who, &[]);
        env.push(("LD_PRELOAD".to_owned(), preload.to_owned()));
        env.push(("DYLD_INSERT_LIBRARIES".to_owned(), preload.to_owned()));
        let spec = serde_json::json!({
            "uid": me,
            "gid": gid,
            "groups": super::login_groups(gid, &groups),
            "argv": ["/bin/true"],
            "cwd": "/",
            "env": env,
        });
        let exe = super::helper_exe().unwrap();
        let mut stage = std::process::Command::new(exe);
        stage
            .arg(super::HELPER_ARG)
            .env_clear()
            .current_dir("/")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        let mut stage = stage.spawn().expect("stage");
        use std::io::Write as _;
        stage
            .stdin
            .take()
            .unwrap()
            .write_all(spec.to_string().as_bytes())
            .unwrap();
        // The stage reads the spec, then blocks in setgroups. Reading earlier
        // would race the read and could observe it before the spec arrived.
        std::thread::sleep(std::time::Duration::from_millis(200));
        let environ = std::fs::read(format!("/proc/{}/environ", stage.id())).unwrap_or_default();
        let text = String::from_utf8_lossy(&environ);
        assert!(
            !text.contains("LD_PRELOAD") && !text.contains("DYLD_"),
            "the root stage is running with a caller preload: {text:?}"
        );
        // The stage is started with a cleared environment, so the whole set is
        // empty: one leaked line would be one line too many.
        assert!(
            environ.is_empty(),
            "the root stage was started with an environment: {environ:?}"
        );
        // And the set it would exec is exactly the base five plus the two
        // loader names the request asked for. A sentinel set in this process,
        // and the daemon's own LANG, are not in it.
        let mut got: Vec<String> = env
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect();
        got.sort();
        let path = |p: &std::path::Path| p.display().to_string();
        let mut want = vec![
            format!("HOME={}", path(&who.home)),
            format!("USER={}", who.name),
            format!("LOGNAME={}", who.name),
            format!("SHELL={}", path(&who.shell)),
            format!("PATH={}", super::DEFAULT_PATH),
            format!("LD_PRELOAD={preload}"),
            format!("DYLD_INSERT_LIBRARIES={preload}"),
        ];
        want.sort();
        assert_eq!(
            got, want,
            "the exec env is not exactly the base plus the request"
        );
        assert!(!got.iter().any(|line| line.starts_with("AW_HOLD_SENTINEL=")));
        assert!(!got.iter().any(|line| line.starts_with("LANG=")));
        std::env::remove_var("AW_HOLD_SENTINEL");
        std::env::remove_var("LANG");
        let _ = stage.kill();
        let _ = stage.wait();
    }

    /// What the helper execs is exactly `base_env`: the account's five basics
    /// plus the names the request added, and not one line of anything else.
    /// A sentinel set in this process must be absent, and the comparison is the
    /// whole set.
    #[cfg(unix)]
    #[test]
    fn dropped_env_is_exactly_the_base_plus_the_request() {
        std::env::set_var("AW_HOLD_SENTINEL", "present-in-daemon");
        std::env::set_var("LANG", "daemon-lang");
        let me = nix::unistd::getuid().as_raw();
        let who = super::lookup(me).expect("this account");
        let extra = [
            ("AW_RV".to_owned(), "1".to_owned()),
            ("LANG".to_owned(), "zh_TW.UTF-8".to_owned()),
            ("TZ".to_owned(), "Asia/Taipei".to_owned()),
        ];
        let got = super::base_env(&who, &extra);
        let mut got_lines: Vec<String> = got
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect();
        got_lines.sort();
        let path = |p: &std::path::Path| p.display().to_string();
        let mut want = vec![
            format!("HOME={}", path(&who.home)),
            format!("USER={}", who.name),
            format!("LOGNAME={}", who.name),
            format!("SHELL={}", path(&who.shell)),
            format!("PATH={}", super::DEFAULT_PATH),
            "AW_RV=1".to_owned(),
            "LANG=zh_TW.UTF-8".to_owned(),
            "TZ=Asia/Taipei".to_owned(),
        ];
        want.sort();
        assert_eq!(
            got_lines, want,
            "base env is not exactly the five plus requested values"
        );
        assert!(!got.iter().any(|(key, _)| key == "AW_HOLD_SENTINEL"));
        assert_eq!(
            got.iter().find(|(key, _)| key == "LANG"),
            Some(&("LANG".to_owned(), "zh_TW.UTF-8".to_owned()))
        );
        std::env::remove_var("AW_HOLD_SENTINEL");
        std::env::remove_var("LANG");
    }

    /// A launch request that sets one of the five account variables is refused,
    /// naming that variable. A name the request is allowed to add is not, and on
    /// Unix the comparison is case-sensitive: `Home` is a different variable.
    #[cfg(unix)]
    #[test]
    fn reserved_env_names_are_refused_and_named() {
        for name in ["HOME", "USER", "LOGNAME", "SHELL", "PATH"] {
            let found = super::reserved_env_var(&[
                ("AW_RV".to_owned(), "1".to_owned()),
                (name.to_owned(), "caller-value".to_owned()),
            ]);
            assert_eq!(found.map(|reserved| reserved.name), Some(name.to_owned()));
            let response = super::reserved_env_response(name);
            assert_eq!(response.status, 400);
            let body: serde_json::Value = serde_json::from_slice(&response.body).expect("json");
            assert_eq!(body["error"]["code"], "env_reserved");
            assert_eq!(body["error"]["detail"]["name"], name);
            assert_eq!(
                body["error"]["message"],
                format!(
                    "环境变量「{name}」由系统按你的账户来填，不能在请求里改。请去掉这个变量再试。"
                )
            );
        }
        // An ordinary requested variable is not reserved, and neither is a
        // different case of a reserved name: Unix environment names are
        // case-sensitive, so `Path` is not `PATH`.
        assert!(super::reserved_env_var(&[("AW_RV".to_owned(), "1".to_owned())]).is_none());
        assert!(super::reserved_env_var(&[("Home".to_owned(), "/tmp".to_owned())]).is_none());
        assert!(super::reserved_env_var(&[("Path".to_owned(), "/bin".to_owned())]).is_none());
    }

    /// Windows environment keys are case-insensitive. Keep the spelling the
    /// caller supplied so the response can identify the rejected request.
    #[cfg(windows)]
    #[test]
    fn windows_reserved_env_names_are_case_insensitive_and_named() {
        for name in ["Path", "path", "PATH", "Home"] {
            let found = super::reserved_env_var(&[(name.to_owned(), "value".to_owned())]);
            assert_eq!(found.map(|reserved| reserved.name), Some(name.to_owned()));
            let response = super::reserved_env_response(name);
            let body: serde_json::Value = serde_json::from_slice(&response.body).expect("json");
            assert_eq!(response.status, 400);
            assert_eq!(body["error"]["code"], "env_reserved");
            assert_eq!(body["error"]["detail"]["name"], name);
        }
        assert!(super::reserved_env_var(&[("LANG".to_owned(), "x".to_owned())]).is_none());
    }

    /// A bare `sh` is a candidate list, not a failure. This test is not root, so
    /// the helper stops at the account switch and never execs; what it must not
    /// do is report the program missing. A root run would exec it.
    #[cfg(target_os = "linux")]
    #[test]
    fn bare_sh_is_not_reported_missing() {
        if nix::unistd::geteuid().as_raw() == 0 {
            return;
        }
        let me = nix::unistd::getuid().as_raw();
        let who = super::lookup(me).expect("this account");
        let error = super::spawn_as(
            &who,
            &["sh".to_owned(), "-c".to_owned(), "exit 0".to_owned()],
            Some("/"),
            &[],
        )
        .expect_err("not root, so the switch fails");
        match error {
            super::SpawnAsError::Program { .. } => {
                panic!("a bare sh was reported as a program error; the search did not find it")
            }
            super::SpawnAsError::TypedProgram(_) => {
                panic!("a bare sh was reported as a typed program error")
            }
            super::SpawnAsError::Drop(step) => {
                assert!(
                    step.contains("setgroups")
                        || step.contains("setuid")
                        || step.contains("setgid"),
                    "the switch is what stopped it, not the program: {step}"
                );
            }
        }
    }

    /// Even if a reserved name reached `base_env`, it would not replace the
    /// account's value. The route refuses first; this is the backstop.
    #[cfg(unix)]
    #[test]
    fn base_env_does_not_let_a_reserved_name_override_the_account() {
        let me = nix::unistd::getuid().as_raw();
        let who = super::lookup(me).expect("this account");
        let extra = [
            ("HOME".to_owned(), "/not/the/account/home".to_owned()),
            ("PATH".to_owned(), "/not/the/base/path".to_owned()),
            ("AW_RV".to_owned(), "1".to_owned()),
        ];
        let got = super::base_env(&who, &extra);
        let path = |p: &std::path::Path| p.display().to_string();
        assert_eq!(
            got.iter().find(|(key, _)| key == "HOME").map(|(_, v)| v),
            Some(&path(&who.home))
        );
        assert_eq!(
            got.iter()
                .find(|(key, _)| key == "PATH")
                .map(|(_, v)| v.as_str()),
            Some(super::DEFAULT_PATH)
        );
        assert!(got
            .iter()
            .any(|(key, value)| key == "AW_RV" && value == "1"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn non_root_user_with_primary_group_zero_is_valid() {
        let spec = super::HelperSpec {
            uid: 1000,
            gid: 0,
            groups: vec![0],
            argv: vec!["true".to_owned()],
            cwd: "/".to_owned(),
            env: Vec::new(),
        };
        assert!(super::valid_helper_spec(&spec));
        assert!(
            !super::root_gid_regained(spec.gid, true),
            "setgid(0) is a permitted no-op for primary gid 0"
        );
        assert!(super::root_gid_regained(1000, true));
        assert!(!super::valid_helper_spec(&super::HelperSpec {
            uid: 0,
            ..spec
        }));
    }
}
