//! Unit-file and service-definition text.
//!
//! Strings here match the checked-in files under `packaging/`. Tests assert
//! the names the task card calls out: service name, LocalSystem, Restart,
//! the launchd Label, and the `agentwatch` group.

use std::fmt::Write as _;

/// Linux unit parameters from linux.md §5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemdUnitParams {
    /// Unit and binary name. P1 uses `agentwatchd`.
    pub service_name: &'static str,
    /// Absolute path of the daemon binary inside the unit.
    pub exec_start: &'static str,
    /// Group created at install and named by `Group=` / `SupplementaryGroups=`.
    pub group: &'static str,
    /// Slice whose leftover children startup cleanup describes.
    pub slice: &'static str,
}

impl Default for SystemdUnitParams {
    fn default() -> Self {
        Self {
            service_name: "agentwatchd",
            exec_start: "/usr/bin/agentwatchd",
            group: "agentwatch",
            slice: "agentwatch.slice",
        }
    }
}

/// Render `agentwatchd.service`.
///
/// Runs as root (linux.md §5) and keeps the capability list from that section
/// as documentation inside the unit. `Restart=on-failure` is the unit-level
/// counterpart of the Windows `sc failure` policy.
pub fn render_systemd_unit(params: &SystemdUnitParams) -> String {
    // Byte-identical to packaging/systemd/agentwatchd.service for the defaults.
    format!(
        "\
# Rendered by aw-daemon (P1-DAEMON-05). Do not edit by hand.
# Install creates the `{group}` group (groupadd --system). The daemon runs as
# root (linux.md §5). AmbientCapabilities documents the reduced set; fanotify
# and cgroup setup still need CAP_SYS_ADMIN.
# Startup describes cleanup of leftover children under {slice}. This
# unit does not perform that cleanup. Applying this file is an administrator
# action; this repository does not call systemctl.

[Unit]
Description=AgentWatch process-behavior audit daemon
Documentation=https://github.com/agentwatch/agentwatch
After=network.target
AssertGroup={group}

[Service]
Type=simple
ExecStart={exec} --foreground
Restart=on-failure
RestartSec=5s
# root, per linux.md §5. The {group} group is supplementary so local readers
# of the audit socket can be members without the daemon dropping to that user.
User=root
Group={group}
SupplementaryGroups={group}
AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_SYS_RESOURCE CAP_SYS_ADMIN CAP_SYS_PTRACE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/agentwatch
Slice={slice}

[Install]
WantedBy=multi-user.target
",
        group = params.group,
        slice = params.slice,
        exec = params.exec_start,
    )
}

/// One `sc failure` action. Three of these match windows.md §5 ("3 次重启").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowsFailureAction {
    /// `restart`, `run`, or `reboot`. P1 only describes `restart`.
    pub action: &'static str,
    /// Delay before this action, in milliseconds.
    pub delay_ms: u32,
}

/// Windows service definition. A description, not an SCM call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsServiceDef {
    /// SCM service name.
    pub service_name: &'static str,
    /// Account the service runs as. P1 is `LocalSystem`.
    pub account: &'static str,
    /// `auto`, `delayed-auto`, or `demand`.
    pub start: &'static str,
    /// Binary path including the `--foreground` argument.
    pub bin_path: &'static str,
    /// Local group created at install (`AgentWatch Users`).
    pub users_group: &'static str,
    /// Failure actions, in order. Three restarts.
    pub failure_actions: [WindowsFailureAction; 3],
    /// Seconds before the failure counter resets. `sc failure reset=`.
    pub failure_reset_sec: u32,
    /// Name prefix of leftover ETW sessions startup describes stopping.
    pub etw_session_prefix: &'static str,
}

impl Default for WindowsServiceDef {
    fn default() -> Self {
        Self {
            service_name: "AgentWatch",
            account: "LocalSystem",
            start: "delayed-auto",
            bin_path: r"C:\Program Files\AgentWatch\agentwatchd.exe --foreground",
            users_group: "AgentWatch Users",
            failure_actions: [
                WindowsFailureAction {
                    action: "restart",
                    delay_ms: 5_000,
                },
                WindowsFailureAction {
                    action: "restart",
                    delay_ms: 10_000,
                },
                WindowsFailureAction {
                    action: "restart",
                    delay_ms: 30_000,
                },
            ],
            failure_reset_sec: 86_400,
            etw_session_prefix: "AgentWatch-",
        }
    }
}

impl WindowsServiceDef {
    /// Stable, line-oriented description. Not passed to `sc.exe`.
    ///
    /// The default value is byte-identical to `packaging/windows/AgentWatch.service.txt`.
    pub fn render(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "# Windows service definition (P1-DAEMON-05).");
        let _ = writeln!(
            out,
            "# A description only. Nothing in this repository calls sc.exe, net.exe, or the"
        );
        let _ = writeln!(
            out,
            "# Service Control Manager. An administrator applies it by hand or from CI."
        );
        let _ = writeln!(out, "service_name={}", self.service_name);
        let _ = writeln!(out, "account={}", self.account);
        let _ = writeln!(out, "obj={}", self.account);
        let _ = writeln!(out, "start={}", self.start);
        let _ = writeln!(out, "bin_path={}", self.bin_path);
        let _ = writeln!(out, "users_group={}", self.users_group);
        let _ = writeln!(out, "failure_reset_sec={}", self.failure_reset_sec);
        let _ = writeln!(out, "etw_session_prefix={}", self.etw_session_prefix);
        for (index, action) in self.failure_actions.iter().enumerate() {
            let _ = writeln!(out, "failure.{index}.action={}", action.action);
            let _ = writeln!(out, "failure.{index}.delay_ms={}", action.delay_ms);
        }
        let _ = writeln!(
            out,
            "# sc failure {name} reset= {reset} actions= restart/{d0}/restart/{d1}/restart/{d2}",
            name = self.service_name,
            reset = self.failure_reset_sec,
            d0 = self.failure_actions[0].delay_ms,
            d1 = self.failure_actions[1].delay_ms,
            d2 = self.failure_actions[2].delay_ms,
        );
        let _ = writeln!(
            out,
            "# Startup describes stopping leftover ETW sessions named {prefix}* (ControlTrace STOP by name).",
            prefix = self.etw_session_prefix,
        );
        let _ = writeln!(
            out,
            "# Install describes creating the local group \"{group}\".",
            group = self.users_group,
        );
        let _ = writeln!(
            out,
            "# --purge describes deleting %ProgramData%\\AgentWatch. P1 has no proxy CA."
        );
        out
    }
}

/// launchd plist parameters (macos.md §5, M1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchdPlistParams {
    /// `Label`. P1 uses `dev.agentwatch.daemon`.
    pub label: &'static str,
    /// Absolute path of the daemon binary.
    pub program: &'static str,
    /// Installed path of the plist itself.
    pub plist_path: &'static str,
}

impl Default for LaunchdPlistParams {
    fn default() -> Self {
        Self {
            label: "dev.agentwatch.daemon",
            program: "/usr/local/bin/agentwatchd",
            plist_path: "/Library/LaunchDaemons/dev.agentwatch.daemon.plist",
        }
    }
}

/// Render the LaunchDaemon plist. It runs as root (`UserName` root) and does
/// not request a signature or notarization (P4).
pub fn render_launchd_plist(params: &LaunchdPlistParams) -> String {
    // Byte-identical to packaging/launchd/dev.agentwatch.daemon.plist for the defaults.
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- Rendered by aw-daemon (P1-DAEMON-05). Unsigned and not notarized (P4). -->
<!-- Installed at {plist} -->
<!-- Applying this file is an administrator action; this repository does not call launchctl. -->
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{program}</string>
        <string>--foreground</string>
    </array>
    <key>UserName</key>
    <string>root</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>ThrottleInterval</key>
    <integer>5</integer>
    <key>ProcessType</key>
    <string>Interactive</string>
</dict>
</plist>
"#,
        plist = params.plist_path,
        label = params.label,
        program = params.program,
    )
}

/// Install plan as stable text. Sorting is the caller's job; this writes
/// `steps` in the order given.
pub fn render_install(plan: &super::plan::InstallPlan) -> String {
    render_plan("install", plan.platform, &plan.steps, plan.ca.as_str())
}

/// Uninstall plan as stable text.
pub fn render_uninstall(plan: &super::plan::UninstallPlan) -> String {
    render_plan("uninstall", plan.platform, &plan.steps, plan.ca.as_str())
}

fn render_plan(
    kind: &str,
    platform: super::plan::Platform,
    steps: &[super::plan::PlanStep],
    ca: &str,
) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "kind={kind}");
    let _ = writeln!(out, "platform={}", platform.as_str());
    let _ = writeln!(out, "ca_hook={ca}");
    let _ = writeln!(out, "steps={}", steps.len());
    for (index, step) in steps.iter().enumerate() {
        let _ = writeln!(
            out,
            "{index}\t{}\t{}\t{}",
            step.id.as_str(),
            step.effect.as_str(),
            step.detail,
        );
    }
    out
}
