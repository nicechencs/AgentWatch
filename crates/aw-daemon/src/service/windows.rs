//! Windows service plan (P4-WIN-01).
//!
//! This module describes a service. It does not register one. There is no
//! `windows-service` crate and no Service Control Manager binding, so nothing
//! here calls `sc.exe`, `net`, `Set-Service`, `icacls`, or an ETW API.
//! [`install`] returns the commands an administrator can run later, and only
//! when the caller has already confirmed that.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// SCM service name. Fixed; not taken from the environment.
pub const SERVICE_NAME: &str = "AgentWatch";

/// Display name shown in the Services snap-in.
pub const DISPLAY_NAME: &str = "AgentWatch Daemon";

/// How the service is asked to start. Delayed automatic, not a boot driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartMode {
    /// `sc start= delayed-auto`.
    DelayedAuto,
}

impl StartMode {
    /// Token used in the plan and in the rendered `sc` text.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DelayedAuto => "delayed-auto",
        }
    }
}

/// One failure action. The plan describes a restart; it does not apply it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestartAction {
    /// Delay before this restart, in milliseconds.
    pub delay_ms: u32,
}

/// Recovery policy from the task card: the first two failures restart after
/// 5 seconds, the third after 60 seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryPlan {
    /// First failure.
    pub first: RestartAction,
    /// Second failure.
    pub second: RestartAction,
    /// Third failure.
    pub third: RestartAction,
}

impl RecoveryPlan {
    /// The policy named by P4-WIN-01 (NFR-06).
    pub const fn task_card() -> Self {
        Self {
            first: RestartAction { delay_ms: 5_000 },
            second: RestartAction { delay_ms: 5_000 },
            third: RestartAction { delay_ms: 60_000 },
        }
    }

    /// `actions=` argument for `sc failure`, without the `actions=` prefix.
    pub fn actions_arg(self) -> String {
        format!(
            "restart/{}/restart/{}/restart/{}",
            self.first.delay_ms, self.second.delay_ms, self.third.delay_ms
        )
    }
}

/// What an administrator would register. Building this touches nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServicePlan {
    /// SCM service name. Always [`SERVICE_NAME`].
    pub name: &'static str,
    /// Services snap-in display name.
    pub display_name: &'static str,
    /// Start type. Always delayed automatic.
    pub start_mode: StartMode,
    /// Three-restart recovery policy.
    pub recovery: RecoveryPlan,
    /// Account the service would run as. Described, not impersonated.
    pub account: &'static str,
    /// Binary path the plan would pass as `binPath=`. Not launched.
    pub bin_path: String,
    /// Restricted service SID. Described; `ChangeServiceConfig2` is not called.
    pub sid_type: &'static str,
}

/// A trustee named in an ACL description. Well-known names only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trustee {
    /// `NT AUTHORITY\SYSTEM`.
    System,
    /// `BUILTIN\Administrators`.
    Administrators,
    /// The interactive logon, not a named user.
    InteractiveUsers,
}

impl Trustee {
    /// SDDL-style account name. No real username is ever substituted.
    pub const fn account(self) -> &'static str {
        match self {
            Self::System => r"NT AUTHORITY\SYSTEM",
            Self::Administrators => r"BUILTIN\Administrators",
            Self::InteractiveUsers => "INTERACTIVE",
        }
    }

    /// Rights the plan would grant. Not applied.
    pub const fn rights(self) -> &'static str {
        match self {
            Self::System | Self::Administrators => "full",
            Self::InteractiveUsers => "read-write",
        }
    }
}

/// An ACL that would be applied later. [`AclPlan`] does not call `icacls`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclPlan {
    /// Path the ACL describes. May contain `%ProgramData%`; never a username.
    pub path: String,
    /// Who would be granted access, in a fixed order.
    pub trustees: Vec<Trustee>,
}

/// Why [`install`] did not produce commands.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ServiceError {
    /// `confirmed` was false. No command text was produced and nothing ran.
    #[error(
        "service install was not confirmed; pass an explicit confirmation before any command is emitted"
    )]
    NotConfirmed,
}

/// Commands an administrator can copy. Nothing in this process has run them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallOutcome {
    /// The plan that was confirmed.
    pub plan: ServicePlan,
    /// `sc create` / `sc failure` / `sc sidtype` text. Not executed.
    pub sc_commands: String,
    /// Pipe and database ACL descriptions. Not applied.
    pub acls: Vec<AclPlan>,
}

/// Files [`rotate`] renamed or removed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RotateReport {
    /// Files renamed because they were larger than the threshold.
    pub renamed: Vec<PathBuf>,
    /// Files removed because they were past `keep`.
    pub removed: Vec<PathBuf>,
}

/// The service an administrator would register. Does not contact the SCM.
#[must_use]
pub fn install_plan() -> ServicePlan {
    ServicePlan {
        name: SERVICE_NAME,
        display_name: DISPLAY_NAME,
        start_mode: StartMode::DelayedAuto,
        recovery: RecoveryPlan::task_card(),
        account: "LocalSystem",
        bin_path: r"C:\Program Files\AgentWatch\agentwatchd.exe --foreground".to_owned(),
        sid_type: "restricted",
    }
}

/// Named-pipe ACL. SYSTEM, Administrators, and the interactive logon.
///
/// The path is the well-known pipe name, not a user profile path. This does
/// not create the pipe and does not call `icacls`.
#[must_use]
pub fn pipe_acl_plan() -> AclPlan {
    AclPlan {
        path: r"\\.\pipe\agentwatch".to_owned(),
        trustees: vec![
            Trustee::System,
            Trustee::Administrators,
            Trustee::InteractiveUsers,
        ],
    }
}

/// Database-directory ACL. SYSTEM and Administrators only (REQ-07.5).
///
/// Uses the `%ProgramData%` placeholder so a real username never appears.
/// This does not create the directory and does not call `icacls`.
#[must_use]
pub fn data_dir_acl_plan() -> AclPlan {
    AclPlan {
        path: r"%ProgramData%\AgentWatch".to_owned(),
        trustees: vec![Trustee::System, Trustee::Administrators],
    }
}

/// Turn a confirmed plan into command text.
///
/// When `confirmed` is false this returns [`ServiceError::NotConfirmed`] and
/// writes nothing. When it is true the returned text is still only text: this
/// function does not spawn `sc.exe`, `net`, or PowerShell.
///
/// # Errors
///
/// [`ServiceError::NotConfirmed`] when `confirmed` is false.
pub fn install(plan: &ServicePlan, confirmed: bool) -> Result<InstallOutcome, ServiceError> {
    if !confirmed {
        return Err(ServiceError::NotConfirmed);
    }
    Ok(InstallOutcome {
        plan: plan.clone(),
        sc_commands: render_sc_commands(plan),
        acls: vec![pipe_acl_plan(), data_dir_acl_plan()],
    })
}

/// `sc` text for a human to run. Not passed to a shell.
fn render_sc_commands(plan: &ServicePlan) -> String {
    // Quotes are part of the text. Nothing here is executed.
    format!(
        "\
sc.exe create {name} binPath= \"{bin}\" start= {start} obj= {account} DisplayName= \"{display}\"
sc.exe failure {name} reset= 86400 actions= {actions}
sc.exe sidtype {name} {sid}
sc.exe description {name} \"AgentWatch process-behavior audit daemon\"
",
        name = plan.name,
        bin = plan.bin_path,
        start = plan.start_mode.as_str(),
        account = plan.account,
        display = plan.display_name,
        actions = plan.recovery.actions_arg(),
        sid = plan.sid_type,
    )
}

/// Rotate `*.log` files in `log_dir` once they exceed `max_bytes`.
///
/// A file at or under the threshold is left alone. A file over it is renamed
/// to `<name>.log.1`, shifting older generations up. Only a generation past
/// `keep` is deleted. `keep == 0` deletes the oversized file instead of
/// keeping a generation. This does not open an ETW session and does not read
/// the log contents.
///
/// # Errors
///
/// A directory read, rename, or remove failed. The error is returned as-is.
pub fn rotate(log_dir: &Path, max_bytes: u64, keep: usize) -> io::Result<RotateReport> {
    let mut report = RotateReport::default();
    let entries = match fs::read_dir(log_dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(report),
        Err(err) => return Err(err),
    };
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let Some(text) = name.to_str() else {
            continue;
        };
        if text.ends_with(".log") {
            names.push(text.to_owned());
        }
    }
    names.sort();
    for name in names {
        rotate_one(log_dir, &name, max_bytes, keep, &mut report)?;
    }
    Ok(report)
}

fn rotate_one(
    log_dir: &Path,
    name: &str,
    max_bytes: u64,
    keep: usize,
    report: &mut RotateReport,
) -> io::Result<()> {
    let current = log_dir.join(name);
    let len = match fs::metadata(&current) {
        Ok(meta) => meta.len(),
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
    };
    if len <= max_bytes {
        return Ok(());
    }
    if keep == 0 {
        fs::remove_file(&current)?;
        report.removed.push(current);
        return Ok(());
    }
    // Drop the generation past `keep` first, then shift keep-1 .. 1 upward.
    let expired = log_dir.join(format!("{name}.{keep}"));
    if expired.is_file() {
        fs::remove_file(&expired)?;
        report.removed.push(expired);
    }
    for generation in (1..keep).rev() {
        let from = log_dir.join(format!("{name}.{generation}"));
        if from.is_file() {
            let to = log_dir.join(format!("{name}.{}", generation + 1));
            fs::rename(&from, &to)?;
            report.renamed.push(to);
        }
    }
    let first = log_dir.join(format!("{name}.1"));
    fs::rename(&current, &first)?;
    report.renamed.push(first);
    Ok(())
}

/// One-line description of an ACL plan. No `icacls` invocation.
pub fn describe_acl(plan: &AclPlan) -> String {
    let mut out = format!("acl path={}", plan.path);
    for trustee in &plan.trustees {
        out.push_str(&format!(
            " trustee={} rights={}",
            trustee.account(),
            trustee.rights()
        ));
    }
    out.push('\n');
    out
}
