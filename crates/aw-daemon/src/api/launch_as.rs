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
//! - Daemon runs as root on macOS: std's `uid`/`gid` (supplementary groups are
//!   cleared, `nix` has no `setgroups` there); a program that needs a
//!   supplementary group does not get it on macOS.
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
/// Default `PATH` for a dropped launch. The caller's own shell `PATH` is not
/// known to the daemon; the request's `env` can override it.
pub(crate) const DEFAULT_PATH: &str =
    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

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
    let Ok(uid) = caller_user_id.parse::<u32>() else {
        return Err(error_response(
            403,
            "caller_unidentified",
            "the caller's account could not be identified",
        ));
    };
    if uid == daemon_uid {
        return Ok(None);
    }
    if daemon_uid != 0 {
        return Err(error_response(
            403,
            "launch_other_user",
            "the service runs under an ordinary account and cannot start programs for another account",
        ));
    }
    lookup(uid).map(Some)
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

/// Environment a dropped launch starts with: `LANG`/`LC_ALL`/`TZ` from the
/// daemon, the account's basics, then the request's `env`. Nothing else of the
/// daemon's environment (root's HOME, sockets, tokens) leaks in.
#[cfg(unix)]
fn base_env(who: &Identity, extra: &[(String, String)]) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = ["LANG", "LC_ALL", "TZ"]
        .iter()
        .filter_map(|key| std::env::var(key).ok().map(|val| ((*key).to_owned(), val)))
        .collect();
    let path = |p: &std::path::Path| p.display().to_string();
    env.push(("HOME".to_owned(), path(&who.home)));
    env.push(("USER".to_owned(), who.name.clone()));
    env.push(("LOGNAME".to_owned(), who.name.clone()));
    env.push(("SHELL".to_owned(), path(&who.shell)));
    env.push(("PATH".to_owned(), DEFAULT_PATH.to_owned()));
    for (key, val) in extra {
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
    Program(std::io::Error),
    /// The account switch itself failed or could not be checked: 500.
    Drop(String),
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
        Some(errno) => SpawnAsError::Program(std::io::Error::from_raw_os_error(
            i32::try_from(errno).unwrap_or(EIO),
        )),
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

/// `EIO`: the errno reported when the OS gave none.
#[cfg(target_os = "linux")]
const EIO: i32 = 5;

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
    use std::os::unix::process::CommandExt;
    use std::process::{Command, ExitCode, Stdio};

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
    let err = Command::new(&spec.argv[0])
        .args(&spec.argv[1..])
        .env_clear()
        .envs(spec.env.iter().map(|(k, v)| (k, v)))
        .current_dir(&spec.cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .exec();
    fail(serde_json::json!({"errno": err.raw_os_error().unwrap_or(EIO)}))
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

/// macOS (root daemon): std's `uid`/`gid` (std clears supplementary groups),
/// clean environment, `cwd` entered after the switch.
#[cfg(all(unix, not(target_os = "linux")))]
pub(crate) fn spawn_as(
    who: &Identity,
    argv: &[String],
    cwd: Option<&str>,
    extra_env: &[(String, String)],
) -> Result<std::process::Child, SpawnAsError> {
    use std::os::unix::process::CommandExt;
    let mut command = std::process::Command::new(&argv[0]);
    command
        .args(&argv[1..])
        .uid(who.uid)
        .gid(who.gid)
        .env_clear()
        .envs(base_env(who, extra_env))
        .current_dir(cwd.map_or_else(|| who.home.clone(), PathBuf::from))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    command.spawn().map_err(SpawnAsError::Program)
}

/// After spawn: real, effective, saved and filesystem uid/gid of `pid` are all
/// `who`'s, and its group list is exactly `who.groups`. Linux reads `/proc`.
#[cfg(target_os = "linux")]
pub(crate) fn verify_dropped(pid: u32, who: &Identity) -> bool {
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
        let mut want = who.groups.clone();
        let mut have = groups;
        if !have.contains(&who.gid) {
            have.push(who.gid);
        }
        want.push(who.gid);
        set(have) == set(want)
    });
    all(ids("Uid:"), who.uid) && all(ids("Gid:"), who.gid) && groups_ok
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::identity_for;

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
        assert_eq!(code(identity_for("1001", 1000)), "launch_other_user");
        assert_eq!(code(identity_for("0", 1000)), "launch_other_user");
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
