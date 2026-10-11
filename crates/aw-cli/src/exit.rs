//! Process exit codes from api-and-cli §2.
//!
//! `0` success, `1` general error, `2` bad arguments, `3` daemon unreachable,
//! `4` permission denied, `5` a feature absent from this build, and `6` a
//! resource the daemon could not find. `aw run` adds the target's own status
//! on top of these.

/// Success.
pub const OK: i32 = 0;
/// A command failed for a reason that is not usage, reachability, or permission.
pub const GENERAL: i32 = 1;
/// The arguments do not match the command tree.
pub const USAGE: i32 = 2;
/// No daemon answered. The message names `aw daemon start` or `--no-daemon`.
pub const UNREACHABLE: i32 = 3;
/// The caller is authenticated but not allowed.
pub const PERMISSION: i32 = 4;
/// The command or switch exists, but is not connected in this build.
pub const NOT_IN_BUILD: i32 = 5;
/// The daemon answered, but the requested resource does not exist.
pub const NOT_FOUND: i32 = 6;

/// Map an HTTP status from the daemon onto a CLI exit code.
///
/// `401` and `403` are permission (`4`). `421` (foreign Host) is treated as
/// unreachable (`3`): the daemon refused the request before any handler ran.
/// `404` is a distinct not-found result (`6`). Other `4xx` are usage (`2`).
/// `5xx` and anything else are a general error (`1`).
#[must_use]
pub fn from_http_status(status: u16) -> i32 {
    match status {
        401 | 403 => PERMISSION,
        421 => UNREACHABLE,
        404 => NOT_FOUND,
        400..=499 => USAGE,
        _ => GENERAL,
    }
}

#[cfg(test)]
mod tests {
    use super::{from_http_status, NOT_FOUND, PERMISSION, UNREACHABLE, USAGE};

    #[test]
    fn daemon_status_mapping_keeps_not_found_distinct() {
        assert_eq!(from_http_status(404), NOT_FOUND);
        assert_eq!(from_http_status(401), PERMISSION);
        assert_eq!(from_http_status(403), PERMISSION);
        assert_eq!(from_http_status(421), UNREACHABLE);
        assert_eq!(from_http_status(400), USAGE);
    }
}
