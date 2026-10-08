//! `aw daemon` (P1-CLI-04).
//!
//! Nothing here registers a service or deletes a database. [`DaemonControl`]
//! is the side-effect boundary. The default control records the request and
//! returns a stub status. `install` and `uninstall` check [`Privilege`] first
//! and exit 4 when it says the caller is not an administrator.

use serde_json::json;

use crate::exit;

use super::Outcome;

/// Whether the process may install or uninstall a system service.
pub(crate) trait Privilege {
    /// `true` when the caller holds an administrator token (or root).
    fn is_admin(&self) -> bool;
}

/// Production check. This card does not query the OS token: a real install is
/// out of scope, and tests inject the answer. Treated as not privileged so a
/// live `install` cannot proceed by accident.
#[derive(Debug, Default)]
pub(crate) struct NotAdmin;

impl Privilege for NotAdmin {
    fn is_admin(&self) -> bool {
        false
    }
}

/// One daemon operation. Applied only through [`DaemonControl`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DaemonOp {
    /// `status`.
    Status,
    /// `start`.
    Start,
    /// `stop`.
    Stop,
    /// `restart`.
    Restart,
    /// `install`.
    Install,
    /// `uninstall`. `purge` would delete the database and CA; the control decides.
    Uninstall {
        /// `--purge`.
        purge: bool,
        /// `--check`: report leftovers, do not remove anything.
        check: bool,
    },
    /// `logs`.
    Logs {
        /// `--follow`.
        follow: bool,
    },
}

/// What the control reports back. No paths that contain a username.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DaemonEffect {
    /// `stopped`, `running`, `planned`, `checked`, …
    pub state: String,
    /// One line for the operator. No secrets.
    pub detail: String,
}

/// Side effects. The default does not touch the service manager.
pub(crate) trait DaemonControl {
    /// Apply `op` and describe the result.
    ///
    /// # Errors
    ///
    /// A control failure. The message must not contain a token or a path with
    /// a username.
    fn apply(&mut self, op: &DaemonOp) -> Result<DaemonEffect, String>;
}

/// Control that only describes the operation. Used when no test double is set.
#[derive(Debug, Default)]
pub(crate) struct PlannedControl;

impl DaemonControl for PlannedControl {
    fn apply(&mut self, op: &DaemonOp) -> Result<DaemonEffect, String> {
        let (state, detail) = match op {
            DaemonOp::Status => ("unknown", "daemon status is not observed in this build"),
            DaemonOp::Start => ("planned", "start was recorded; no service was launched"),
            DaemonOp::Stop => ("planned", "stop was recorded; no service was signalled"),
            DaemonOp::Restart => ("planned", "restart was recorded; no service was signalled"),
            DaemonOp::Install => (
                "planned",
                "install plan was rendered; nothing was registered",
            ),
            DaemonOp::Uninstall { purge, check } => {
                if *check {
                    (
                        "checked",
                        "uninstall --check found nothing to remove in this build",
                    )
                } else if *purge {
                    (
                        "planned",
                        "uninstall --purge was recorded; the database was not deleted",
                    )
                } else {
                    (
                        "planned",
                        "uninstall was recorded; the service was not removed",
                    )
                }
            }
            DaemonOp::Logs { follow } => {
                if *follow {
                    ("empty", "log follow is not attached in this build")
                } else {
                    ("empty", "no daemon log is available in this build")
                }
            }
        };
        Ok(DaemonEffect {
            state: state.to_owned(),
            detail: detail.to_owned(),
        })
    }
}

/// Run one daemon subcommand.
pub(crate) fn run(
    op: DaemonOp,
    json: bool,
    privilege: &dyn Privilege,
    control: &mut dyn DaemonControl,
) -> Outcome {
    if needs_admin(&op) && !privilege.is_admin() {
        return super::error_outcome(
            exit::PERMISSION,
            "permission",
            "administrator required; re-run in an administrator terminal or with sudo",
            json,
        );
    }
    match control.apply(&op) {
        Ok(effect) => ok_outcome(&effect, json),
        Err(detail) => super::error_outcome(exit::GENERAL, "daemon", &detail, json),
    }
}

fn needs_admin(op: &DaemonOp) -> bool {
    matches!(op, DaemonOp::Install | DaemonOp::Uninstall { .. })
}

fn ok_outcome(effect: &DaemonEffect, json: bool) -> Outcome {
    let text = if json {
        format!(
            "{}\n",
            json!({ "state": effect.state, "detail": effect.detail })
        )
    } else {
        format!("{}: {}\n", effect.state, effect.detail)
    };
    Outcome {
        code: exit::OK,
        stdout: text.into_bytes(),
        stderr: Vec::new(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{run, DaemonControl, DaemonEffect, DaemonOp, PlannedControl, Privilege};
    use crate::exit;

    struct Admin(bool);

    impl Privilege for Admin {
        fn is_admin(&self) -> bool {
            self.0
        }
    }

    struct Recording {
        seen: Vec<DaemonOp>,
    }

    impl DaemonControl for Recording {
        fn apply(&mut self, op: &DaemonOp) -> Result<DaemonEffect, String> {
            self.seen.push(op.clone());
            PlannedControl.apply(op)
        }
    }

    #[test]
    fn install_without_admin_is_exit_4_and_does_not_apply() {
        let mut control = Recording { seen: Vec::new() };
        let outcome = run(DaemonOp::Install, false, &Admin(false), &mut control);
        assert_eq!(outcome.code, exit::PERMISSION);
        let err = String::from_utf8(outcome.stderr).expect("utf8");
        assert!(
            err.contains("administrator") || err.contains("sudo"),
            "{err}"
        );
        assert!(control.seen.is_empty());
    }

    #[test]
    fn uninstall_purge_with_admin_is_planned_not_deleted() {
        let mut control = Recording { seen: Vec::new() };
        let outcome = run(
            DaemonOp::Uninstall {
                purge: true,
                check: false,
            },
            true,
            &Admin(true),
            &mut control,
        );
        assert_eq!(outcome.code, exit::OK);
        let text = String::from_utf8(outcome.stdout).expect("utf8");
        assert!(text.contains("planned"), "{text}");
        assert!(text.contains("not deleted"), "{text}");
        assert_eq!(
            control.seen,
            vec![DaemonOp::Uninstall {
                purge: true,
                check: false
            }]
        );
    }

    #[test]
    fn status_does_not_need_admin() {
        let mut control = Recording { seen: Vec::new() };
        let outcome = run(DaemonOp::Status, false, &Admin(false), &mut control);
        assert_eq!(outcome.code, exit::OK);
        assert_eq!(control.seen, vec![DaemonOp::Status]);
    }
}
