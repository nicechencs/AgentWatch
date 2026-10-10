//! Whose account a program started from the UI runs under.
//!
//! The identity is the caller's, and the caller comes only from the operating
//! system: the internal channel's peer credential (`SO_PEERCRED` on Linux), or
//! a UI token that was issued over that channel to that peer. Nothing in the
//! request body names a user; a `uid` / `user` field there is ignored.
//!
//! - Caller is the daemon's own account: started as is.
//! - Daemon runs as root, caller is another account: the child drops to the
//!   caller before `exec`. std does it in this order in the child:
//!   `setgid(gid)`, `setgroups(0)` (no supplementary groups; std ignores a
//!   failure here, so the parent check below also requires no foreign
//!   groups), `setuid(uid)`, then `chdir(cwd)` (so the directory is checked
//!   as the caller). Both group changes happen while still root. The parent
//!   then reads `/proc/<pid>/status` and kills the child unless real,
//!   effective, saved and filesystem ids are all the caller's: with all four
//!   non-root the child cannot become root again.
//! - Unknown identity (not a number, no passwd entry), or a non-root daemon
//!   asked to start a program for another account: refused. There is never a
//!   fall back to the daemon's account.
//!
//! Supplementary groups are dropped, not initialised (`initgroups` needs code
//! after `fork` that this crate cannot write without `unsafe`). A program that
//! needs a supplementary group's access does not get it.

use std::path::PathBuf;

use super::routes::{error_response, ApiResponse};

/// The account a launch drops to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Identity {
    pub uid: u32,
    pub gid: u32,
    pub name: String,
    pub home: PathBuf,
    pub shell: PathBuf,
}

/// Default `PATH` for a dropped launch. The caller's own shell `PATH` is not
/// known to the daemon; the request's `env` can override it.
pub(crate) const DEFAULT_PATH: &str =
    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// `None`: start as the daemon (same account). `Some`: drop to that account.
pub(crate) fn identity_for(
    caller_user_id: &str,
    daemon_uid: u32,
) -> Result<Option<Identity>, ApiResponse> {
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
    lookup(uid).map(Some).ok_or_else(|| {
        error_response(
            403,
            "caller_unknown",
            "the caller's account has no entry in the user database",
        )
    })
}

#[cfg(unix)]
fn lookup(uid: u32) -> Option<Identity> {
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid)).ok()??;
    Some(Identity {
        uid,
        gid: user.gid.as_raw(),
        name: user.name,
        home: user.dir,
        shell: user.shell,
    })
}

#[cfg(not(unix))]
fn lookup(_uid: u32) -> Option<Identity> {
    None
}

/// Set up `command` to run as `who`: ids, a clean environment with the
/// account's basics, and `cwd` (default: the account's home). The request's
/// `env` is applied by the caller afterwards.
#[cfg(unix)]
pub(crate) fn drop_to(command: &mut std::process::Command, who: &Identity, cwd: Option<&str>) {
    use std::os::unix::process::CommandExt;
    command.uid(who.uid).gid(who.gid);
    // The daemon's environment (root's HOME, sockets, tokens) does not leak in.
    let keep: Vec<(String, String)> = ["LANG", "LC_ALL", "TZ"]
        .iter()
        .filter_map(|key| std::env::var(key).ok().map(|val| ((*key).to_owned(), val)))
        .collect();
    command.env_clear();
    command.envs(keep);
    command
        .env("HOME", &who.home)
        .env("USER", &who.name)
        .env("LOGNAME", &who.name)
        .env("SHELL", &who.shell)
        .env("PATH", DEFAULT_PATH);
    match cwd {
        Some(dir) => command.current_dir(dir),
        None => command.current_dir(&who.home),
    };
}

/// After spawn: real, effective, saved and filesystem uid/gid of `pid` are all
/// `who`'s, and it has no supplementary groups. Linux reads `/proc`.
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
    let groups_ok = ids("Groups:").is_some_and(|groups| groups.iter().all(|g| *g == who.gid));
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

    #[test]
    fn same_account_starts_as_is() {
        assert_eq!(code(identity_for("1000", 1000)), "self");
        assert_eq!(code(identity_for("0", 0)), "self");
    }

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

    #[test]
    fn ordinary_daemon_does_not_start_programs_for_others() {
        assert_eq!(code(identity_for("1001", 1000)), "launch_other_user");
        assert_eq!(code(identity_for("0", 1000)), "launch_other_user");
    }

    /// `verify_dropped` reads a real process: a child of this account passes
    /// for this account and fails for any other uid or gid, so a child that
    /// kept root (or any other id) is caught.
    #[cfg(target_os = "linux")]
    #[test]
    fn verify_dropped_checks_all_ids_of_a_real_process() {
        let me = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();
        let mut child = std::process::Command::new("sleep")
            .arg("5")
            .spawn()
            .expect("spawn sleep");
        let who = super::Identity {
            uid: me,
            gid,
            name: "t".to_owned(),
            home: "/".into(),
            shell: "/bin/sh".into(),
        };
        let status = std::fs::read_to_string(format!("/proc/{}/status", child.id())).unwrap();
        let groups_line = status.lines().find(|l| l.starts_with("Groups:")).unwrap();
        let only_primary = groups_line[7..]
            .split_whitespace()
            .all(|g| g == gid.to_string());
        // The test runner may carry supplementary groups; the check must then refuse.
        assert_eq!(super::verify_dropped(child.id(), &who), only_primary);
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
    }
}
