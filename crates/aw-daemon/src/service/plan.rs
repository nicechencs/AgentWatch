//! Idempotent install and uninstall plans.
//!
//! A plan is a value. Building it does not touch the service manager, the
//! filesystem, or a certificate store. [`MachineState`] says what is already
//! true; each step is either [`StepEffect::Apply`] or
//! [`StepEffect::AlreadySatisfied`].

use super::render::{
    render_launchd_plist, render_systemd_unit, LaunchdPlistParams, SystemdUnitParams,
    WindowsServiceDef,
};

/// Operating system the plan is for. Chosen by the caller, not by `cfg`,
/// so one test binary can render all three.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// systemd unit `agentwatchd.service`.
    Linux,
    /// Service `AgentWatch` running as LocalSystem.
    Windows,
    /// LaunchDaemon `dev.agentwatch.daemon`.
    Macos,
}

impl Platform {
    /// Stable token used in rendered plans.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Windows => "windows",
            Self::Macos => "macos",
        }
    }
}

/// What the machine looks like before the plan runs.
///
/// Booleans are observations the caller already made. This module does not
/// query scm, systemd, or launchd to fill them in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MachineState {
    /// Target platform.
    pub platform: Platform,
    /// The service unit / SCM service / LaunchDaemon is registered.
    pub service_registered: bool,
    /// The service process is running.
    pub service_running: bool,
    /// `agentwatch` (Linux) or `AgentWatch Users` (Windows) exists.
    /// macOS has no such group; leave this `false`.
    pub group_present: bool,
    /// The platform data directory exists.
    pub data_dir_present: bool,
    /// `--purge` was requested. Ignored by install.
    pub purge: bool,
}

/// What a step will do when an administrator applies the plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepEffect {
    /// Not true yet; applying the plan performs the step.
    Apply,
    /// Already true. Applying the plan skips the side effect.
    /// The step stays in the list so two renders of one state match.
    AlreadySatisfied,
}

impl StepEffect {
    /// Stable token used in rendered plans.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Apply => "apply",
            Self::AlreadySatisfied => "already",
        }
    }
}

/// Stable step identity. The order inside a plan is fixed per platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepId {
    /// `groupadd --system agentwatch` (Linux only).
    CreateAgentwatchGroup,
    /// `net localgroup "AgentWatch Users" /add` (Windows only). Described, not run.
    CreateUsersGroup,
    /// Write `agentwatchd.service`.
    WriteSystemdUnit,
    /// `systemctl enable --now agentwatchd.service`. Described, not run.
    EnableSystemdUnit,
    /// Describe stopping leftover ETW sessions named `AgentWatch-*`.
    StopLeftoverEtwSessions,
    /// Register service `AgentWatch` as LocalSystem. Described, not sent to SCM.
    RegisterWindowsService,
    /// `sc failure AgentWatch ...` three restarts. Described, not run.
    ConfigureFailureRestart,
    /// Write `/Library/LaunchDaemons/dev.agentwatch.daemon.plist`.
    WriteLaunchDaemon,
    /// `launchctl bootstrap system <plist>`. Described, not run.
    BootstrapLaunchDaemon,
    /// Describe removal of leftover children under `agentwatch.slice`.
    CleanLeftoverCgroups,
    /// `systemctl disable --now` and delete the unit. Described, not run.
    RemoveSystemdUnit,
    /// Delete the `agentwatch` group. Described, not run.
    RemoveAgentwatchGroup,
    /// Stop and delete service `AgentWatch`. Described, not sent to SCM.
    RemoveWindowsService,
    /// Delete the `AgentWatch Users` group. Described, not run.
    RemoveUsersGroup,
    /// `launchctl bootout` and delete the plist. Described, not run.
    RemoveLaunchDaemon,
    /// Delete the platform data directory. Only present when `purge` is set.
    DeleteDataDir,
    /// P3 hook. P1 always reports [`CaHookResult::NoCa`].
    RemoveProxyCa,
}

impl StepId {
    /// Stable token used in rendered plans.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CreateAgentwatchGroup => "create_agentwatch_group",
            Self::CreateUsersGroup => "create_users_group",
            Self::WriteSystemdUnit => "write_systemd_unit",
            Self::EnableSystemdUnit => "enable_systemd_unit",
            Self::StopLeftoverEtwSessions => "stop_leftover_etw_sessions",
            Self::RegisterWindowsService => "register_windows_service",
            Self::ConfigureFailureRestart => "configure_failure_restart",
            Self::WriteLaunchDaemon => "write_launch_daemon",
            Self::BootstrapLaunchDaemon => "bootstrap_launch_daemon",
            Self::CleanLeftoverCgroups => "clean_leftover_cgroups",
            Self::RemoveSystemdUnit => "remove_systemd_unit",
            Self::RemoveAgentwatchGroup => "remove_agentwatch_group",
            Self::RemoveWindowsService => "remove_windows_service",
            Self::RemoveUsersGroup => "remove_users_group",
            Self::RemoveLaunchDaemon => "remove_launch_daemon",
            Self::DeleteDataDir => "delete_data_dir",
            Self::RemoveProxyCa => "remove_proxy_ca",
        }
    }
}

/// One line of a plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanStep {
    /// What the step is.
    pub id: StepId,
    /// Whether applying it changes the machine.
    pub effect: StepEffect,
    /// Human-readable description. No secrets. Not a shell command to run here.
    pub detail: String,
}

/// What [`remove_proxy_ca`] returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaHookResult {
    /// P1 has no proxy CA. Nothing was deleted.
    NoCa,
}

impl CaHookResult {
    /// Stable token used in rendered plans.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoCa => "no_ca",
        }
    }
}

/// P3 will delete the proxy CA here.
///
/// P1 has no CA, so this is a no-op and returns [`CaHookResult::NoCa`].
/// It does not open a certificate store.
pub fn remove_proxy_ca() -> CaHookResult {
    CaHookResult::NoCa
}

/// Errors from plan construction. Paths and unit text are static, so this
/// is currently only a platform/state mismatch guard.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ServicePlanError {
    /// `state.platform` does not match the function that was called.
    #[error("machine state platform does not match the requested plan")]
    PlatformMismatch,
}

/// An install plan for one platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallPlan {
    /// Platform this plan targets.
    pub platform: Platform,
    /// Steps in apply order.
    pub steps: Vec<PlanStep>,
    /// Always [`CaHookResult::NoCa`] in P1. Install does not create a CA.
    pub ca: CaHookResult,
    /// Rendered unit / plist / service definition included for the caller.
    pub unit_text: String,
}

/// An uninstall plan for one platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UninstallPlan {
    /// Platform this plan targets.
    pub platform: Platform,
    /// `true` when the data directory deletion step is present.
    pub purge: bool,
    /// Steps in apply order.
    pub steps: Vec<PlanStep>,
    /// Result of the CA hook. P1 is always [`CaHookResult::NoCa`].
    pub ca: CaHookResult,
}

fn effect(present: bool) -> StepEffect {
    if present {
        StepEffect::AlreadySatisfied
    } else {
        StepEffect::Apply
    }
}

fn step(id: StepId, effect: StepEffect, detail: impl Into<String>) -> PlanStep {
    PlanStep {
        id,
        effect,
        detail: detail.into(),
    }
}

/// Linux install plan.
///
/// # Errors
///
/// [`ServicePlanError::PlatformMismatch`] when `state.platform` is not Linux.
pub fn install_linux(state: MachineState) -> Result<InstallPlan, ServicePlanError> {
    if state.platform != Platform::Linux {
        return Err(ServicePlanError::PlatformMismatch);
    }
    let params = SystemdUnitParams::default();
    let unit = render_systemd_unit(&params);
    let steps = vec![
        step(
            StepId::CreateAgentwatchGroup,
            effect(state.group_present),
            "Create the system group `agentwatch` (groupadd --system agentwatch). Members of this group may read the local audit socket. Describe only; do not run groupadd.",
        ),
        step(
            StepId::WriteSystemdUnit,
            effect(state.service_registered),
            "Write /etc/systemd/system/agentwatchd.service with the rendered unit (User=root, Group=agentwatch, Restart=on-failure, Slice=agentwatch.slice).",
        ),
        step(
            StepId::CleanLeftoverCgroups,
            StepEffect::Apply,
            "On startup, describe cleanup of leftover child cgroups under agentwatch.slice (/sys/fs/cgroup/agentwatch.slice/session-*). Do not rmdir them from the planner.",
        ),
        step(
            StepId::EnableSystemdUnit,
            effect(state.service_running),
            "systemctl enable --now agentwatchd.service. Describe only; do not call systemctl.",
        ),
    ];
    Ok(InstallPlan {
        platform: Platform::Linux,
        steps,
        ca: remove_proxy_ca(),
        unit_text: unit,
    })
}

/// Windows install plan. Does not call the Service Control Manager.
///
/// # Errors
///
/// [`ServicePlanError::PlatformMismatch`] when `state.platform` is not Windows.
pub fn install_windows(state: MachineState) -> Result<InstallPlan, ServicePlanError> {
    if state.platform != Platform::Windows {
        return Err(ServicePlanError::PlatformMismatch);
    }
    let def = WindowsServiceDef::default();
    let unit = def.render();
    let steps = vec![
        step(
            StepId::CreateUsersGroup,
            effect(state.group_present),
            "Create the local group `AgentWatch Users`. Describe only; do not run net localgroup.",
        ),
        step(
            StepId::StopLeftoverEtwSessions,
            StepEffect::Apply,
            "On startup, stop leftover ETW sessions whose names begin with `AgentWatch-` (ControlTrace STOP by name). Describe only; do not call logman or the ETW API.",
        ),
        step(
            StepId::RegisterWindowsService,
            effect(state.service_registered),
            "Register service name `AgentWatch`, account LocalSystem, start delayed-auto, binPath the agentwatchd binary. Describe only; do not call the Service Control Manager or sc.exe.",
        ),
        step(
            StepId::ConfigureFailureRestart,
            effect(state.service_registered),
            "sc failure AgentWatch reset= 86400 actions= restart/5000/restart/10000/restart/30000. Three restarts. Describe only; do not run sc.exe.",
        ),
    ];
    Ok(InstallPlan {
        platform: Platform::Windows,
        steps,
        ca: remove_proxy_ca(),
        unit_text: unit,
    })
}

/// macOS install plan. Unsigned, not notarized.
///
/// # Errors
///
/// [`ServicePlanError::PlatformMismatch`] when `state.platform` is not macOS.
pub fn install_macos(state: MachineState) -> Result<InstallPlan, ServicePlanError> {
    if state.platform != Platform::Macos {
        return Err(ServicePlanError::PlatformMismatch);
    }
    let params = LaunchdPlistParams::default();
    let unit = render_launchd_plist(&params);
    let steps = vec![
        step(
            StepId::WriteLaunchDaemon,
            effect(state.service_registered),
            "Write /Library/LaunchDaemons/dev.agentwatch.daemon.plist (Label dev.agentwatch.daemon, UserName root). Do not sign or notarize.",
        ),
        step(
            StepId::BootstrapLaunchDaemon,
            effect(state.service_running),
            "launchctl bootstrap system /Library/LaunchDaemons/dev.agentwatch.daemon.plist. Describe only; do not call launchctl.",
        ),
    ];
    Ok(InstallPlan {
        platform: Platform::Macos,
        steps,
        ca: remove_proxy_ca(),
        unit_text: unit,
    })
}

fn data_dir_detail(platform: Platform) -> &'static str {
    match platform {
        Platform::Linux => {
            "Delete data directory /var/lib/agentwatch. Only when --purge is set. Describe only; do not remove it here."
        }
        Platform::Windows => {
            "Delete data directory %ProgramData%\\AgentWatch. Only when --purge is set. Describe only; do not remove it here."
        }
        Platform::Macos => {
            "Delete data directory /Library/Application Support/AgentWatch. Only when --purge is set. Describe only; do not remove it here."
        }
    }
}

fn purge_steps(state: MachineState) -> Vec<PlanStep> {
    let mut steps = Vec::new();
    if state.purge {
        steps.push(step(
            StepId::DeleteDataDir,
            effect(!state.data_dir_present),
            data_dir_detail(state.platform),
        ));
    }
    // The hook always runs so the plan records "no CA" even without --purge.
    // It does not delete anything in P1.
    let ca = remove_proxy_ca();
    steps.push(step(
        StepId::RemoveProxyCa,
        StepEffect::AlreadySatisfied,
        format!(
            "CA hook returned {ca}. P1 has no proxy CA; nothing to delete.",
            ca = ca.as_str()
        ),
    ));
    steps
}

/// Linux uninstall plan. `--purge` adds the data-directory step.
///
/// # Errors
///
/// [`ServicePlanError::PlatformMismatch`] when `state.platform` is not Linux.
pub fn uninstall_linux(state: MachineState) -> Result<UninstallPlan, ServicePlanError> {
    if state.platform != Platform::Linux {
        return Err(ServicePlanError::PlatformMismatch);
    }
    let mut steps = vec![
        step(
            StepId::RemoveSystemdUnit,
            effect(state.service_registered || state.service_running),
            "systemctl disable --now agentwatchd.service and delete /etc/systemd/system/agentwatchd.service. Describe only; do not call systemctl.",
        ),
        step(
            StepId::CleanLeftoverCgroups,
            StepEffect::Apply,
            "Describe cleanup of leftover child cgroups under agentwatch.slice. Do not rmdir them from the planner.",
        ),
        step(
            StepId::RemoveAgentwatchGroup,
            effect(state.group_present),
            "Delete the system group `agentwatch`. Describe only; do not run groupdel.",
        ),
    ];
    steps.extend(purge_steps(state));
    Ok(UninstallPlan {
        platform: Platform::Linux,
        purge: state.purge,
        steps,
        ca: remove_proxy_ca(),
    })
}

/// Windows uninstall plan. Does not call the Service Control Manager.
///
/// # Errors
///
/// [`ServicePlanError::PlatformMismatch`] when `state.platform` is not Windows.
pub fn uninstall_windows(state: MachineState) -> Result<UninstallPlan, ServicePlanError> {
    if state.platform != Platform::Windows {
        return Err(ServicePlanError::PlatformMismatch);
    }
    let mut steps = vec![
        step(
            StepId::StopLeftoverEtwSessions,
            StepEffect::Apply,
            "Stop leftover ETW sessions whose names begin with `AgentWatch-`. Describe only; do not call logman.",
        ),
        step(
            StepId::RemoveWindowsService,
            effect(state.service_registered || state.service_running),
            "Stop and delete service `AgentWatch` (LocalSystem). Describe only; do not call the Service Control Manager or sc.exe.",
        ),
        step(
            StepId::RemoveUsersGroup,
            effect(state.group_present),
            "Delete the local group `AgentWatch Users`. Describe only; do not run net localgroup.",
        ),
    ];
    steps.extend(purge_steps(state));
    Ok(UninstallPlan {
        platform: Platform::Windows,
        purge: state.purge,
        steps,
        ca: remove_proxy_ca(),
    })
}

/// macOS uninstall plan. Does not call launchctl.
///
/// # Errors
///
/// [`ServicePlanError::PlatformMismatch`] when `state.platform` is not macOS.
pub fn uninstall_macos(state: MachineState) -> Result<UninstallPlan, ServicePlanError> {
    if state.platform != Platform::Macos {
        return Err(ServicePlanError::PlatformMismatch);
    }
    let mut steps = vec![
        step(
            StepId::RemoveLaunchDaemon,
            effect(state.service_registered || state.service_running),
            "launchctl bootout system /Library/LaunchDaemons/dev.agentwatch.daemon.plist and delete the plist. Describe only; do not call launchctl. Do not sign or notarize.",
        ),
    ];
    steps.extend(purge_steps(state));
    Ok(UninstallPlan {
        platform: Platform::Macos,
        purge: state.purge,
        steps,
        ca: remove_proxy_ca(),
    })
}
