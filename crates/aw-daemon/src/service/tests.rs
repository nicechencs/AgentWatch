//! Plan rendering tests. No service manager is contacted.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::plan::{
    install_linux, install_macos, install_windows, remove_proxy_ca, uninstall_linux,
    uninstall_macos, uninstall_windows, CaHookResult, MachineState, Platform, StepEffect, StepId,
};
use super::render::{render_install, render_uninstall};

fn fresh(platform: Platform) -> MachineState {
    MachineState {
        platform,
        service_registered: false,
        service_running: false,
        group_present: false,
        data_dir_present: false,
        purge: false,
    }
}

fn installed(platform: Platform) -> MachineState {
    MachineState {
        platform,
        service_registered: true,
        service_running: true,
        group_present: true,
        data_dir_present: true,
        purge: false,
    }
}

fn assert_has(text: &str, needle: &str) {
    assert!(text.contains(needle), "missing `{needle}` in:\n{text}");
}

fn packaging_file(relative: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("packaging")
        .join(relative);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    text.replace("\r\n", "\n").replace('\r', "\n")
}

#[test]
fn systemd_unit_names_the_group_and_restart() {
    let plan = install_linux(fresh(Platform::Linux)).expect("linux plan");
    assert_has(&plan.unit_text, "agentwatch");
    assert_has(&plan.unit_text, "Restart=on-failure");
    assert_has(&plan.unit_text, "Group=agentwatch");
    assert_has(&plan.unit_text, "User=root");
    assert_has(&plan.unit_text, "agentwatch.slice");
    let group = plan
        .steps
        .iter()
        .find(|step| step.id == StepId::CreateAgentwatchGroup)
        .expect("group step");
    assert_eq!(group.effect, StepEffect::Apply);
    assert_has(&group.detail, "agentwatch");
}

#[test]
fn windows_def_is_localsystem_with_three_restarts() {
    let plan = install_windows(fresh(Platform::Windows)).expect("windows plan");
    assert_has(&plan.unit_text, "service_name=AgentWatch");
    assert_has(&plan.unit_text, "account=LocalSystem");
    assert_has(&plan.unit_text, "obj=LocalSystem");
    assert_has(&plan.unit_text, "users_group=AgentWatch Users");
    assert_has(&plan.unit_text, "etw_session_prefix=AgentWatch-");
    assert_has(&plan.unit_text, "failure.0.action=restart");
    assert_has(&plan.unit_text, "failure.1.action=restart");
    assert_has(&plan.unit_text, "failure.2.action=restart");
    let etw = plan
        .steps
        .iter()
        .find(|step| step.id == StepId::StopLeftoverEtwSessions)
        .expect("etw step");
    assert_has(&etw.detail, "AgentWatch-");
    let failure = plan
        .steps
        .iter()
        .find(|step| step.id == StepId::ConfigureFailureRestart)
        .expect("failure step");
    assert_has(&failure.detail, "restart/5000/restart/10000/restart/30000");
}

#[test]
fn launchd_plist_has_label() {
    let plan = install_macos(fresh(Platform::Macos)).expect("macos plan");
    assert_has(&plan.unit_text, "<key>Label</key>");
    assert_has(&plan.unit_text, "<string>dev.agentwatch.daemon</string>");
    assert_has(
        &plan.unit_text,
        "/Library/LaunchDaemons/dev.agentwatch.daemon.plist",
    );
    assert_has(&plan.unit_text, "<string>root</string>");
    assert_has(&plan.unit_text, "Unsigned and not notarized");
}

#[test]
fn rendering_twice_is_byte_identical() {
    let cases = [
        fresh(Platform::Linux),
        installed(Platform::Linux),
        fresh(Platform::Windows),
        installed(Platform::Windows),
        fresh(Platform::Macos),
        installed(Platform::Macos),
    ];
    for state in cases {
        let (a, b) = match state.platform {
            Platform::Linux => {
                let a = install_linux(state).expect("linux");
                let b = install_linux(state).expect("linux");
                (render_install(&a), render_install(&b))
            }
            Platform::Windows => {
                let a = install_windows(state).expect("windows");
                let b = install_windows(state).expect("windows");
                (render_install(&a), render_install(&b))
            }
            Platform::Macos => {
                let a = install_macos(state).expect("macos");
                let b = install_macos(state).expect("macos");
                (render_install(&a), render_install(&b))
            }
        };
        assert_eq!(a.as_bytes(), b.as_bytes());
    }
}

#[test]
fn installed_state_marks_steps_already_satisfied() {
    let linux = install_linux(installed(Platform::Linux)).expect("linux");
    let group = linux
        .steps
        .iter()
        .find(|step| step.id == StepId::CreateAgentwatchGroup)
        .expect("group");
    assert_eq!(group.effect, StepEffect::AlreadySatisfied);
    // Leftover cgroup cleanup is described on every start, even when installed.
    let cgroup = linux
        .steps
        .iter()
        .find(|step| step.id == StepId::CleanLeftoverCgroups)
        .expect("cgroup");
    assert_eq!(cgroup.effect, StepEffect::Apply);
    assert_has(&cgroup.detail, "agentwatch.slice");

    let windows = install_windows(installed(Platform::Windows)).expect("windows");
    let register = windows
        .steps
        .iter()
        .find(|step| step.id == StepId::RegisterWindowsService)
        .expect("register");
    assert_eq!(register.effect, StepEffect::AlreadySatisfied);
    assert_has(&register.detail, "LocalSystem");
}

#[test]
fn fresh_and_installed_renders_differ_only_in_effect() {
    let fresh_text = render_install(&install_linux(fresh(Platform::Linux)).expect("fresh"));
    let installed_text =
        render_install(&install_linux(installed(Platform::Linux)).expect("installed"));
    assert_ne!(fresh_text, installed_text);
    assert_has(&fresh_text, "create_agentwatch_group\tapply");
    assert_has(&installed_text, "create_agentwatch_group\talready");
    // Same step ids, same order.
    let fresh_ids: Vec<_> = fresh_text
        .lines()
        .filter(|line| line.contains('\t'))
        .map(|line| line.split('\t').nth(1).unwrap_or(""))
        .collect();
    let installed_ids: Vec<_> = installed_text
        .lines()
        .filter(|line| line.contains('\t'))
        .map(|line| line.split('\t').nth(1).unwrap_or(""))
        .collect();
    assert_eq!(fresh_ids, installed_ids);
}

#[test]
fn purge_deletes_data_dir_and_ca_hook_reports_no_ca() {
    assert_eq!(remove_proxy_ca(), CaHookResult::NoCa);

    let mut state = installed(Platform::Windows);
    state.purge = true;
    let plan = uninstall_windows(state).expect("uninstall");
    assert!(plan.purge);
    assert_eq!(plan.ca, CaHookResult::NoCa);
    let data = plan
        .steps
        .iter()
        .find(|step| step.id == StepId::DeleteDataDir)
        .expect("data dir step");
    assert_has(&data.detail, "ProgramData");
    // Data dir is present, so purge still has work to do.
    assert_eq!(data.effect, StepEffect::Apply);
    let ca = plan
        .steps
        .iter()
        .find(|step| step.id == StepId::RemoveProxyCa)
        .expect("ca step");
    assert_eq!(ca.effect, StepEffect::AlreadySatisfied);
    assert_has(&ca.detail, "no_ca");

    let text_a = render_uninstall(&plan);
    let text_b = render_uninstall(&uninstall_windows(state).expect("again"));
    assert_eq!(text_a.as_bytes(), text_b.as_bytes());
    assert_has(&text_a, "delete_data_dir");
    assert_has(&text_a, "ca_hook=no_ca");
}

#[test]
fn purge_absent_when_not_requested() {
    let plan = uninstall_linux(fresh(Platform::Linux)).expect("uninstall");
    assert!(!plan.purge);
    assert!(plan
        .steps
        .iter()
        .all(|step| step.id != StepId::DeleteDataDir));
    assert!(plan
        .steps
        .iter()
        .any(|step| step.id == StepId::RemoveProxyCa));
    assert_eq!(plan.ca, CaHookResult::NoCa);
    let cgroup = plan
        .steps
        .iter()
        .find(|step| step.id == StepId::CleanLeftoverCgroups)
        .expect("cgroup");
    assert_has(&cgroup.detail, "agentwatch.slice");
}

#[test]
fn macos_purge_names_application_support() {
    let mut state = fresh(Platform::Macos);
    state.purge = true;
    let plan = uninstall_macos(state).expect("uninstall");
    let data = plan
        .steps
        .iter()
        .find(|step| step.id == StepId::DeleteDataDir)
        .expect("data dir");
    assert_has(&data.detail, "/Library/Application Support/AgentWatch");
    // Data dir already absent: the step is a no-op, still listed.
    assert_eq!(data.effect, StepEffect::AlreadySatisfied);
    assert_eq!(plan.ca, CaHookResult::NoCa);
}

#[test]
fn linux_purge_names_var_lib() {
    let mut state = fresh(Platform::Linux);
    state.purge = true;
    state.data_dir_present = true;
    let plan = uninstall_linux(state).expect("uninstall");
    let data = plan
        .steps
        .iter()
        .find(|step| step.id == StepId::DeleteDataDir)
        .expect("data dir");
    assert_has(&data.detail, "/var/lib/agentwatch");
    assert_eq!(data.effect, StepEffect::Apply);
}

#[test]
fn platform_mismatch_is_an_error() {
    let err = install_linux(fresh(Platform::Windows)).expect_err("mismatch");
    let _ = err;
}

#[test]
fn rendered_units_match_packaging_files() {
    let linux = install_linux(fresh(Platform::Linux)).expect("linux");
    assert_eq!(
        linux.unit_text,
        packaging_file("systemd/agentwatchd.service")
    );
    let windows = install_windows(fresh(Platform::Windows)).expect("windows");
    assert_eq!(
        windows.unit_text,
        packaging_file("windows/AgentWatch.service.txt")
    );
    let macos = install_macos(fresh(Platform::Macos)).expect("macos");
    assert_eq!(
        macos.unit_text,
        packaging_file("launchd/dev.agentwatch.daemon.plist")
    );
}
