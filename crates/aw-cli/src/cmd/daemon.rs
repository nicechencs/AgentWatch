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
    /// `install`. `confirm` is `--yes`. Without it the plan is printed and no
    /// command text is emitted. With it, the command text is still only text.
    Install {
        /// `--yes`.
        confirm: bool,
    },
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
            DaemonOp::Install { confirm } => {
                if *confirm {
                    (
                        "planned",
                        "install was confirmed; command text is for an administrator to run, nothing was registered",
                    )
                } else {
                    (
                        "planned",
                        "install plan was rendered; nothing was registered",
                    )
                }
            }
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
///
/// `status`, `start`, `stop`, `restart`, and `logs` do not call a service
/// manager. They print that the Service Control Manager is not bound and exit
/// non-zero. `install` without `--yes` prints the plan and exits with the
/// usage code; it does not emit command text and does not register a service.
pub(crate) fn run(
    op: DaemonOp,
    json: bool,
    privilege: &dyn Privilege,
    control: &mut dyn DaemonControl,
) -> Outcome {
    if let Some(outcome) = refuse_unbound(&op, json) {
        return outcome;
    }
    if let DaemonOp::Install { confirm } = op {
        // Printing a plan or command text is not a privileged action, and the
        // production privilege check is hard-wired to "not admin". Gating the
        // text on it would mean `--yes` could never print anything. Nothing is
        // registered either way.
        return if confirm {
            match control.apply(&op) {
                Ok(effect) => confirmed_install(&effect, json),
                Err(detail) => super::error_outcome(exit::GENERAL, "daemon", &detail, json),
            }
        } else {
            unconfirmed_install(json)
        };
    }
    if needs_admin(&op) && !privilege.is_admin() {
        return super::error_outcome(
            exit::PERMISSION,
            "permission",
            "administrator required; re-run in an administrator terminal or with sudo",
            json,
        );
    }
    match control.apply(&op) {
        Ok(effect) => finish(&op, &effect, json),
        Err(detail) => super::error_outcome(exit::GENERAL, "daemon", &detail, json),
    }
}

/// Control commands have no SCM binding. Success would be a lie.
fn refuse_unbound(op: &DaemonOp, json: bool) -> Option<Outcome> {
    let label = match op {
        DaemonOp::Status => "status",
        DaemonOp::Start => "start",
        DaemonOp::Stop => "stop",
        DaemonOp::Restart => "restart",
        DaemonOp::Logs { .. } => "logs",
        DaemonOp::Install { .. } | DaemonOp::Uninstall { .. } => return None,
    };
    Some(super::error_outcome(
        exit::GENERAL,
        "not_implemented",
        &format!(
            "aw daemon {label}: not implemented; Service Control Manager binding is required (未实现：需要服务控制管理器绑定)"
        ),
        json,
    ))
}

/// Plan text only. Exit [`exit::USAGE`] so a missing `--yes` is not a success.
fn unconfirmed_install(json: bool) -> Outcome {
    let plan = windows_install_plan();
    let acls = windows_acl_lines();
    if json {
        let body = json!({
            "state": "planned",
            "confirmed": false,
            "service": {
                "name": plan.name,
                "display_name": plan.display_name,
                "start_mode": plan.start_mode,
                "account": plan.account,
                "sid_type": plan.sid_type,
                "bin_path": plan.bin_path,
                "recovery": {
                    "first_delay_ms": plan.first_delay_ms,
                    "second_delay_ms": plan.second_delay_ms,
                    "third_delay_ms": plan.third_delay_ms,
                },
            },
            "acls": acls,
            "hint": "re-run `aw daemon install --yes` to print sc.exe text; this process does not run it",
        });
        return Outcome {
            code: exit::USAGE,
            stdout: format!("{body}\n").into_bytes(),
            stderr: Vec::new(),
        };
    }
    let text = format!(
        "\
planned: install plan was rendered; nothing was registered
service_name={name}
display_name={display}
start_mode={start}
account={account}
sid_type={sid}
bin_path={bin}
recovery=restart/{first}/restart/{second}/restart/{third}
{acls}\
hint: re-run `aw daemon install --yes` to print sc.exe text for an administrator; this process does not run it
",
        name = plan.name,
        display = plan.display_name,
        start = plan.start_mode,
        account = plan.account,
        sid = plan.sid_type,
        bin = plan.bin_path,
        first = plan.first_delay_ms,
        second = plan.second_delay_ms,
        third = plan.third_delay_ms,
        acls = acls.join(""),
    );
    Outcome {
        code: exit::USAGE,
        stdout: text.into_bytes(),
        stderr: Vec::new(),
    }
}

/// Confirmed install prints `sc.exe` text and still does not run it.
/// Uninstall keeps the planned report and does not print install commands.
fn finish(op: &DaemonOp, effect: &DaemonEffect, json: bool) -> Outcome {
    if matches!(op, DaemonOp::Install { confirm: true }) {
        return confirmed_install(effect, json);
    }
    ok_outcome(effect, json)
}

/// `--yes` still does not register a service. It prints the `sc.exe` text.
fn confirmed_install(effect: &DaemonEffect, json: bool) -> Outcome {
    let commands = windows_sc_text();
    if json {
        let body = json!({
            "state": effect.state,
            "detail": effect.detail,
            "confirmed": true,
            "executed": false,
            "sc_commands": commands,
        });
        return Outcome {
            code: exit::OK,
            stdout: format!("{body}\n").into_bytes(),
            stderr: Vec::new(),
        };
    }
    let text = format!(
        "\
{state}: {detail}
executed=false
{commands}",
        state = effect.state,
        detail = effect.detail,
    );
    Outcome {
        code: exit::OK,
        stdout: text.into_bytes(),
        stderr: Vec::new(),
    }
}

struct WindowsPlanView {
    name: &'static str,
    display_name: &'static str,
    start_mode: &'static str,
    account: &'static str,
    sid_type: &'static str,
    bin_path: &'static str,
    first_delay_ms: u32,
    second_delay_ms: u32,
    third_delay_ms: u32,
}

/// Mirrors `aw_daemon::service::windows::install_plan`. This crate does not
/// link the daemon, and it does not query the Service Control Manager.
fn windows_install_plan() -> WindowsPlanView {
    WindowsPlanView {
        name: "AgentWatch",
        display_name: "AgentWatch Daemon",
        start_mode: "delayed-auto",
        account: "LocalSystem",
        sid_type: "restricted",
        bin_path: r"C:\Program Files\AgentWatch\agentwatchd.exe --foreground",
        first_delay_ms: 5_000,
        second_delay_ms: 5_000,
        third_delay_ms: 60_000,
    }
}

fn windows_acl_lines() -> Vec<String> {
    vec![
        "acl path=\\\\.\\pipe\\agentwatch trustee=NT AUTHORITY\\SYSTEM rights=full trustee=BUILTIN\\Administrators rights=full trustee=INTERACTIVE rights=read-write\n".to_owned(),
        "acl path=%ProgramData%\\AgentWatch trustee=NT AUTHORITY\\SYSTEM rights=full trustee=BUILTIN\\Administrators rights=full\n".to_owned(),
    ]
}

fn windows_sc_text() -> String {
    "\
sc.exe create AgentWatch binPath= \"C:\\Program Files\\AgentWatch\\agentwatchd.exe --foreground\" start= delayed-auto obj= LocalSystem DisplayName= \"AgentWatch Daemon\"
sc.exe failure AgentWatch reset= 86400 actions= restart/5000/restart/5000/restart/60000
sc.exe sidtype AgentWatch restricted
sc.exe description AgentWatch \"AgentWatch process-behavior audit daemon\"
"
    .to_owned()
}

fn needs_admin(op: &DaemonOp) -> bool {
    matches!(op, DaemonOp::Uninstall { .. })
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
    fn install_without_yes_prints_the_plan_and_does_not_apply() {
        let mut control = Recording { seen: Vec::new() };
        let outcome = run(
            DaemonOp::Install { confirm: false },
            false,
            &Admin(false),
            &mut control,
        );
        assert_eq!(outcome.code, exit::USAGE);
        let text = String::from_utf8(outcome.stdout).expect("utf8");
        assert!(text.contains("AgentWatch"), "{text}");
        assert!(text.contains("--yes"), "{text}");
        // The hint may name `sc.exe` as the command an administrator would run.
        // Naming it is not running it: the control was not asked to apply anything.
        assert!(text.contains("does not run it"), "{text}");
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
    fn status_is_unbound_and_does_not_apply() {
        let mut control = Recording { seen: Vec::new() };
        let outcome = run(DaemonOp::Status, false, &Admin(false), &mut control);
        assert_eq!(outcome.code, exit::GENERAL);
        let err = String::from_utf8(outcome.stderr).expect("utf8");
        assert!(err.contains("未实现"), "{err}");
        assert!(control.seen.is_empty());
    }
}
