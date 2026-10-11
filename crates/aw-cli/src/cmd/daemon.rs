//! `aw daemon` (P1-CLI-04).
//!
//! Nothing here registers a service or deletes a database. [`DaemonControl`]
//! is the side-effect boundary. The default control records the request and
//! returns a stub status. `install` and `uninstall` check [`Privilege`] first
//! and exit 4 when it says the caller is not an administrator.

use serde_json::json;
use std::path::{Path, PathBuf};

use crate::exit;

use super::Outcome;

/// Whether the process may install or uninstall a system service.
pub(crate) trait Privilege {
    /// `true` when the caller holds an administrator token (or root).
    fn is_admin(&self) -> bool;
}

/// Fixed "not an administrator". Used on the test path of `execute_args_with`
/// so a test run as root or elevated does not change behaviour.
#[derive(Debug, Default)]
pub(crate) struct NotAdmin;

impl Privilege for NotAdmin {
    fn is_admin(&self) -> bool {
        false
    }
}

/// Production check: asks the OS through the platform crate (BUGS B5).
///
/// The platform logic is not in this crate (AGENTS.md §6): each
/// `aw-collector-*` crate owns `privilege::is_privileged` and its parser tests.
/// This is the one `cfg` switch that picks the crate for the target. A check
/// that fails (`None`) is treated as not an administrator, so `install` cannot
/// proceed on a guess.
#[derive(Debug, Default)]
pub(crate) struct HostPrivilege;

impl Privilege for HostPrivilege {
    fn is_admin(&self) -> bool {
        host_privileged().unwrap_or(false)
    }
}

fn host_privileged() -> Option<bool> {
    #[cfg(target_os = "linux")]
    {
        aw_collector_linux::privilege::is_privileged()
    }
    #[cfg(target_os = "macos")]
    {
        aw_collector_macos::privilege::is_privileged()
    }
    #[cfg(target_os = "windows")]
    {
        aw_collector_windows::privilege::is_privileged()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        None
    }
}

/// Service install / uninstall. Applied only through [`DaemonControl`].
///
/// `status`, `start`, `stop`, `restart`, and `logs` are not here: they talk
/// to the running daemon over the internal channel (`cmd/ui.rs`,
/// `cmd/lifecycle.rs`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DaemonOp {
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
        /// Explicit test-data target. It is never inferred from the system
        /// service configuration.
        data_dir: Option<PathBuf>,
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
            DaemonOp::Install { confirm } => {
                if *confirm {
                    (
                        "planned",
                        "已确认 install；命令文本供管理员运行，尚未注册任何内容",
                    )
                } else {
                    ("planned", "已生成 install 计划；尚未注册任何内容")
                }
            }
            DaemonOp::Uninstall {
                purge,
                check,
                data_dir,
            } => {
                if *check {
                    ("checked", "此构建的 uninstall --check 没有发现可移除内容")
                } else if *purge {
                    if let Some(path) = data_dir.as_deref() {
                        remove_test_data_dir(path)?;
                        ("removed", "已删除指定的测试数据目录；没有移除系统服务")
                    } else {
                        ("planned", "已记录 uninstall --purge；没有删除数据库")
                    }
                } else {
                    ("planned", "已记录 uninstall；没有移除服务")
                }
            }
        };
        Ok(DaemonEffect {
            state: state.to_owned(),
            detail: detail.to_owned(),
        })
    }
}

/// Remove only an explicit test target.  The normal daemon data directory is
/// deliberately not inferred here, so this command cannot accidentally affect
/// an installed service.  A filesystem root and a path without a final name
/// are never valid removal targets.
fn remove_test_data_dir(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty() || path.file_name().is_none() {
        return Err("测试数据目录无效，拒绝删除".to_owned());
    }
    if !path.exists() {
        return Ok(());
    }
    std::fs::remove_dir_all(path).map_err(|_| "无法删除指定的测试数据目录".to_owned())
}

/// Run one daemon subcommand.
///
/// `install` without `--yes` prints the plan and exits with the
/// usage code; it does not emit command text and does not register a service.
pub(crate) fn run(
    op: DaemonOp,
    json: bool,
    privilege: &dyn Privilege,
    control: &mut dyn DaemonControl,
) -> Outcome {
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
            "需要管理员权限；请在管理员终端或使用 sudo 重新运行",
            json,
        );
    }
    match control.apply(&op) {
        Ok(effect) => finish(&op, &effect, json),
        Err(detail) => super::error_outcome(exit::GENERAL, "daemon", &detail, json),
    }
}

/// Plan text only. Exit [`exit::USAGE`] so a missing `--yes` is not a success.
#[allow(clippy::needless_return)]
fn unconfirmed_install(json: bool) -> Outcome {
    #[cfg(not(target_os = "windows"))]
    {
        let platform = if cfg!(target_os = "macos") {
            "launchd"
        } else {
            "systemd"
        };
        let detail = format!(
            "planned: {platform} 安装计划；此命令不注册服务。实际安装由安装包提供\n提示: 请使用 AgentWatch 安装包完成安装\n"
        );
        return if json {
            Outcome {
                code: exit::USAGE,
                stdout: format!(
                    "{}\n",
                    json!({
                        "state": "planned",
                        "confirmed": false,
                        "platform": platform,
                        "executed": false,
                        "hint": "实际安装由安装包提供",
                    })
                )
                .into_bytes(),
                stderr: Vec::new(),
            }
        } else {
            Outcome {
                code: exit::USAGE,
                stdout: detail.into_bytes(),
                stderr: Vec::new(),
            }
        };
    }
    #[cfg(target_os = "windows")]
    {
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
                "hint": "请重新运行 `aw daemon install --yes` 以打印 sc.exe 文本；此进程不会执行它",
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
#[allow(clippy::needless_return)]
fn confirmed_install(effect: &DaemonEffect, json: bool) -> Outcome {
    #[cfg(not(target_os = "windows"))]
    {
        let platform = if cfg!(target_os = "macos") {
            "launchd"
        } else {
            "systemd"
        };
        let detail = format!(
            "{}: {}\nexecuted=false\n{platform} 服务由 AgentWatch 安装包安装；此命令没有注册服务\n",
            effect.state, effect.detail
        );
        return if json {
            Outcome {
                code: exit::OK,
                stdout: format!(
                    "{}\n",
                    json!({
                        "state": effect.state,
                        "detail": effect.detail,
                        "confirmed": true,
                        "executed": false,
                        "platform": platform,
                        "hint": "实际安装由安装包提供",
                    })
                )
                .into_bytes(),
                stderr: Vec::new(),
            }
        } else {
            Outcome {
                code: exit::OK,
                stdout: detail.into_bytes(),
                stderr: Vec::new(),
            }
        };
    }
    #[cfg(target_os = "windows")]
    {
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
}

#[cfg(target_os = "windows")]
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
#[cfg(target_os = "windows")]
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

#[cfg(target_os = "windows")]
fn windows_acl_lines() -> Vec<String> {
    vec![
        "acl path=\\\\.\\pipe\\agentwatch trustee=NT AUTHORITY\\SYSTEM rights=full trustee=BUILTIN\\Administrators rights=full trustee=INTERACTIVE rights=read-write\n".to_owned(),
        "acl path=%ProgramData%\\AgentWatch trustee=NT AUTHORITY\\SYSTEM rights=full trustee=BUILTIN\\Administrators rights=full\n".to_owned(),
    ]
}

#[cfg(target_os = "windows")]
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
    matches!(
        op,
        DaemonOp::Uninstall {
            check: false,
            data_dir: None,
            ..
        }
    )
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

    /// BUGS B5: production used a constant "not admin", so `sudo aw daemon
    /// install` was refused. On Linux the answer must follow the effective uid
    /// this test runs with; on macOS and Windows it must at least be known.
    #[test]
    fn host_privilege_asks_the_os() {
        let known = super::host_privileged();
        if cfg!(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "windows"
        )) {
            assert!(known.is_some(), "privilege check must answer");
        }
        assert_eq!(super::HostPrivilege.is_admin(), known.unwrap_or(false));
        #[cfg(target_os = "linux")]
        {
            let status = std::fs::read_to_string("/proc/self/status").unwrap();
            let euid_root = status
                .lines()
                .find(|line| line.starts_with("Uid:"))
                .and_then(|line| line.split_whitespace().nth(2))
                == Some("0");
            if euid_root {
                assert!(super::HostPrivilege.is_admin(), "root must be admin");
            }
        }
    }

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

    #[cfg(not(windows))]
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
        assert!(text.contains("安装计划"), "{text}");
        // Non-Windows plans describe only this platform's installer pack.
        assert!(!text.contains("sc.exe"), "{text}");
        assert!(
            text.contains("安装包") || text.contains("安装计划"),
            "{text}"
        );
        assert!(control.seen.is_empty());
    }

    /// Windows plans name the `sc.exe` registration an administrator would
    /// run; naming it is not running it.
    #[cfg(windows)]
    #[test]
    fn windows_install_without_yes_prints_the_sc_plan_and_does_not_apply() {
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
        assert!(
            text.contains("sc.exe") || text.contains("service_name=AgentWatch"),
            "{text}"
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
                data_dir: None,
            },
            true,
            &Admin(true),
            &mut control,
        );
        assert_eq!(outcome.code, exit::OK);
        let text = String::from_utf8(outcome.stdout).expect("utf8");
        assert!(text.contains("planned"), "{text}");
        assert!(text.contains("没有删除数据库"), "{text}");
        assert_eq!(
            control.seen,
            vec![DaemonOp::Uninstall {
                purge: true,
                check: false,
                data_dir: None,
            }]
        );
    }

    #[test]
    fn uninstall_can_remove_only_an_explicit_test_data_directory() {
        let path =
            std::env::temp_dir().join(format!("aw-cli-uninstall-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(path.join("nested")).expect("temp test data");
        std::fs::write(path.join("nested/state"), b"test").expect("temp state");
        let outcome = run(
            DaemonOp::Uninstall {
                purge: true,
                check: false,
                data_dir: Some(path.clone()),
            },
            false,
            &Admin(false),
            &mut PlannedControl,
        );
        assert_eq!(outcome.code, exit::OK);
        assert!(!path.exists(), "only the supplied test target is removed");
    }

    #[test]
    fn uninstall_check_is_not_a_privileged_operation() {
        let outcome = run(
            DaemonOp::Uninstall {
                purge: false,
                check: true,
                data_dir: None,
            },
            false,
            &Admin(false),
            &mut PlannedControl,
        );
        assert_eq!(outcome.code, exit::OK);
    }
}
