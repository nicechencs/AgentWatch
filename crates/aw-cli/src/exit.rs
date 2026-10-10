//! Process exit codes from api-and-cli §2.
//!
//! `0` success, `1` general error, `2` bad arguments, `3` daemon unreachable,
//! `4` permission denied. `aw run` adds the target's own status on top of these.

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

/// Map an HTTP status from the daemon onto a CLI exit code.
///
/// `401` and `403` are permission (`4`). `421` (foreign Host) is treated as
/// unreachable (`3`): the daemon refused the request before any handler ran.
/// Other `4xx` are usage (`2`). `5xx` and anything else are a general error (`1`).
#[must_use]
pub fn from_http_status(status: u16) -> i32 {
    match status {
        401 | 403 => PERMISSION,
        421 => UNREACHABLE,
        400..=499 => USAGE,
        _ => GENERAL,
    }
}
