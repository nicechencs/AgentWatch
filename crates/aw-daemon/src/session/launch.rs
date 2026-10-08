//! Proxy environment for a launch-mode session (P3-PROXY-03).
//!
//! Attach mode cannot receive this map. [`prepare_proxy`] returns
//! [`LaunchProxyError::Attach`] and does not build a listener. Launch mode
//! asks [`aw_proxy::plan_injection`] for the variables and returns them with
//! the overwrite report. The child is not spawned here.

use std::path::PathBuf;

use aw_proxy::{hint_for_exe, plan_injection, Injection, ProxyOnReject, ATTACH_REFUSES_PROXY};

/// Why a launch did not get a proxy environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaunchProxyError {
    /// The session is attach. Injection is impossible.
    Attach,
    /// `--proxy-on-reject` was not `fail` or `tunnel`.
    BadPolicy,
}

impl std::fmt::Display for LaunchProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Attach => f.write_str(ATTACH_REFUSES_PROXY),
            Self::BadPolicy => f.write_str("`--proxy-on-reject` 只接受 fail 或 tunnel"),
        }
    }
}

/// What the launcher merges. Values are paths and the proxy URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchProxy {
    /// Port the session listener bound.
    pub port: u16,
    /// Parsed reject policy.
    pub on_reject: ProxyOnReject,
    /// Environment plan. `Debug` prints names, not values.
    pub injection: Injection,
    /// `<session_tmp>/ca.pem`.
    pub ca_pem: PathBuf,
    /// `<session_tmp>/bundle.pem`.
    pub bundle_pem: PathBuf,
}

/// Build the injection for a launch-mode `--proxy` session.
///
/// `attach` must be false. `policy` is the `--proxy-on-reject` text, or `None`
/// for the default `fail`. `user_env` is the environment the child would
/// inherit. `exe` is the target, used only for the static hint table.
///
/// # Errors
///
/// [`LaunchProxyError::Attach`] or [`LaunchProxyError::BadPolicy`].
pub fn prepare_proxy(
    attach: bool,
    port: u16,
    policy: Option<&str>,
    ca_pem: PathBuf,
    bundle_pem: PathBuf,
    user_env: &[(String, String)],
    exe: Option<&str>,
) -> Result<LaunchProxy, LaunchProxyError> {
    if attach {
        return Err(LaunchProxyError::Attach);
    }
    let on_reject = match policy {
        None => ProxyOnReject::Fail,
        Some(text) => ProxyOnReject::parse(text).ok_or(LaunchProxyError::BadPolicy)?,
    };
    let ca = ca_pem.to_string_lossy();
    let bundle = bundle_pem.to_string_lossy();
    let injection = plan_injection(port, &ca, &bundle, user_env, exe);
    Ok(LaunchProxy {
        port,
        on_reject,
        injection,
        ca_pem,
        bundle_pem,
    })
}

/// Hint lines for a command's argv0. Empty when the table has no row.
#[must_use]
pub fn launch_hints(exe: &str) -> Vec<&'static str> {
    hint_for_exe(exe).into_iter().collect()
}
