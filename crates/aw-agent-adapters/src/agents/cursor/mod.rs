//! Cursor adapter (P5-AGENT-06): process shape, launch hint, proxy argv plan.
//!
//! This module does not enumerate processes, does not write Cursor's install
//! directory or user settings, and does not install a CA into a system or user
//! trust store. Whether an instance is already running is an input from the
//! caller. Proxy coverage and Electron's handling of `NODE_EXTRA_CA_CERTS` are
//! 【待验证】: SPIKE-04 and SPIKE-07 are not finished, and this crate has not
//! been checked against a real Cursor binary.
//!
//! `self_report` on the profile stays empty. SPIKE-07's index is still "未开始".
//! The document survey mentions hooks, but this card does not wire an E3 channel.

mod launch;
mod proxy;
mod roles;

pub use launch::{plan_launch, AttributionBreak, ExistingInstance, LaunchChoice, LaunchPlan};
pub use proxy::{plan_proxy, CaInjection, ProxyPlan, NA_DIRECT_BYPASS_PROXY};
pub use roles::{classify_role, CursorRole, PROFILE_ID};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{identify, load_profiles, ProcInfo};

    fn proc(exe: &str, argv: &[&str]) -> ProcInfo {
        ProcInfo {
            pid: 1,
            exe_name: exe.to_owned(),
            argv: argv.iter().map(|arg| (*arg).to_owned()).collect(),
            env_keys: Vec::new(),
        }
    }

    fn must_match(proc: &ProcInfo) -> crate::AgentMatch {
        match identify(proc, &[]) {
            Some(hit) => hit,
            None => panic!("expected a cursor match for {}", proc.exe_name),
        }
    }

    #[test]
    fn main_process_matches_cursor_and_not_helper_or_node() {
        let hit = must_match(&proc("Cursor", &["/usr/bin/cursor"]));
        assert_eq!(hit.profile_id, PROFILE_ID);
        assert_eq!(hit.evidence.as_str(), "I");

        let win = must_match(&proc("Cursor.exe", &["Cursor.exe"]));
        assert_eq!(win.profile_id, PROFILE_ID);

        let lower = must_match(&proc("cursor", &["cursor"]));
        assert_eq!(lower.profile_id, PROFILE_ID);

        assert!(identify(&proc("Cursor Helper", &["Cursor Helper"]), &[]).is_none());
        assert!(identify(&proc("node", &["node", "/opt/cursor/app.js"]), &[]).is_none());
        assert!(identify(&proc("python", &["python"]), &[]).is_none());
    }

    #[test]
    fn child_roles_cover_electron_types_and_terminal_shells() {
        let cases = [
            (
                proc("Cursor", &["cursor", "--type=renderer"]),
                Some(CursorRole::Renderer),
            ),
            (
                proc("Cursor Helper", &["--type=utility"]),
                Some(CursorRole::Utility),
            ),
            (
                proc(
                    "Cursor Helper (Plugin)",
                    &["/app/cursor", "--type=extensionHost"],
                ),
                Some(CursorRole::ExtensionHost),
            ),
            (
                proc("bash", &["/bin/bash"]),
                Some(CursorRole::TerminalShell),
            ),
            (
                proc("zsh", &["/bin/zsh", "-l"]),
                Some(CursorRole::TerminalShell),
            ),
            (
                proc("pwsh.exe", &[r"C:\Windows\pwsh.exe"]),
                Some(CursorRole::TerminalShell),
            ),
            (
                proc("cmd.exe", &["cmd.exe"]),
                Some(CursorRole::TerminalShell),
            ),
            (
                proc("node", &["node", "/opt/mcp-server-filesystem"]),
                Some(CursorRole::McpServer),
            ),
            (proc("Cursor", &["cursor"]), None),
            (proc("git", &["git", "status"]), None),
        ];
        for (child, expected) in cases {
            assert_eq!(classify_role(&child), expected, "argv={:?}", child.argv);
        }
    }

    #[test]
    fn profile_self_report_is_empty() {
        let set = match load_profiles(None) {
            Ok(set) => set,
            Err(err) => panic!("built-in profiles failed to load: {err}"),
        };
        let profile = match set.get(PROFILE_ID) {
            Some(profile) => profile,
            None => panic!("cursor profile missing"),
        };
        assert!(profile.self_report.is_empty());
    }

    #[test]
    fn existing_instance_asks_to_quit_or_attach_until_user_insists() {
        let hinted = plan_launch(ExistingInstance::AlreadyRunning, LaunchChoice::Ask);
        assert!(hinted.attribution_break().is_none());
        let message = hinted.message();
        assert!(message.contains("请退出后重启"));
        assert!(message.contains("附着模式"));
        assert!(hinted.extra_args().is_empty());

        let forced = plan_launch(ExistingInstance::AlreadyRunning, LaunchChoice::Insist);
        assert_eq!(
            forced.attribution_break(),
            Some(AttributionBreak::SecondInstanceHandoff)
        );
        assert!(forced.message().contains("attribution_break"));

        let fresh = plan_launch(ExistingInstance::None, LaunchChoice::Ask);
        assert!(fresh.attribution_break().is_none());
        assert!(fresh.message().is_empty());
    }

    #[test]
    fn proxy_plan_appends_proxy_server_and_marks_ca_unverified() {
        let plan = plan_proxy("http://127.0.0.1:9");
        assert_eq!(
            plan.extra_args(),
            &["--proxy-server=http://127.0.0.1:9".to_owned()]
        );
        assert_eq!(plan.ca(), CaInjection::Unverified);
        assert!(plan.note().contains("待验证"));
        assert!(plan.note().contains("NODE_EXTRA_CA_CERTS"));
        assert!(!plan.installs_system_ca());
        assert_eq!(NA_DIRECT_BYPASS_PROXY, "direct_bypass_proxy");
    }
}
