//! Assertions for Codex identification, sandbox roles, hook mapping, and the
//! OTEL plan. Fixtures under `fixtures/agents/codex/` are synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use serde_json::Value;

use aw_core::ToolPhase;

use super::identify::{codex_match, is_codex, proc_info, CODEX_EXE_NAMES};
use super::otel::{otel_child_env, otel_injection_plan, OtelEnvPlan, OtelInjection};
use crate::channel::SelfReportSource;
use crate::{identify, load_profiles, parse_hook, Inference, MatchHit, ProcInfo};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/agents/codex")
        .join(name)
}

fn proc_from(value: &Value) -> ProcInfo {
    let argv = value["argv"]
        .as_array()
        .expect("argv")
        .iter()
        .map(|item| item.as_str().expect("argv str").to_owned())
        .collect();
    let env_keys = value["env_keys"]
        .as_array()
        .expect("env_keys")
        .iter()
        .map(|item| item.as_str().expect("env str").to_owned())
        .collect();
    ProcInfo {
        pid: u32::try_from(value["pid"].as_u64().expect("pid")).expect("pid fits"),
        exe_name: value["exe_name"].as_str().expect("exe").to_owned(),
        argv,
        env_keys,
    }
}

#[test]
fn profile_lists_codex_exe_and_sandbox_roles() {
    let set = load_profiles(None).expect("builtins");
    let profile = set.get("codex").expect("codex profile");
    assert_eq!(profile.display, "Codex CLI");
    assert_eq!(profile.match_rules.exe_names, ["codex", "codex.exe"]);
    assert!(profile.match_rules.argv_regex.is_empty());
    assert!(profile.match_rules.env_keys.is_empty());
    assert_eq!(profile.self_report, ["hooks", "otel"]);
    let sandbox: Vec<&str> = profile
        .children
        .role_regex
        .iter()
        .filter(|role| role.role == "sandbox")
        .map(|role| role.regex.as_str())
        .collect();
    assert!(
        sandbox
            .iter()
            .any(|pattern| pattern.contains("sandbox-exec")),
        "{sandbox:?}"
    );
    assert!(
        sandbox.iter().any(|pattern| pattern.contains("bwrap")),
        "{sandbox:?}"
    );
    assert!(
        sandbox
            .iter()
            .any(|pattern| pattern.contains("codex-linux-sandbox")),
        "{sandbox:?}"
    );
}

#[test]
fn codex_exe_matches_as_inference() {
    for exe in CODEX_EXE_NAMES {
        let proc = proc_info(7, exe, &[exe], &[]);
        let (id, evidence, hits) = codex_match(&proc, &[]).expect("codex");
        assert_eq!(id, "codex");
        assert_eq!(evidence, "I");
        assert_eq!(evidence, Inference::I.as_str());
        assert_eq!(hits, vec![MatchHit::ExeName((*exe).to_owned())]);
        assert!(is_codex(&proc, &[]));
    }
}

#[test]
fn fixture_processes_match_expected_id_or_role() {
    let text = fs::read_to_string(fixture("processes.json")).expect("read fixture");
    let doc: Value = serde_json::from_str(&text).expect("json");
    let set = load_profiles(None).expect("builtins");
    let cases = doc["cases"].as_array().expect("cases");
    assert!(cases.len() >= 6, "fixture lost cases");
    for case in cases {
        let proc = proc_from(&case["proc"]);
        let ancestors: Vec<ProcInfo> = case["ancestors"]
            .as_array()
            .expect("ancestors")
            .iter()
            .map(proc_from)
            .collect();
        let case_id = case["id"].as_str().expect("id");
        if let Some(role) = case["expect_role"].as_str() {
            assert!(
                identify(&proc, &ancestors).is_none(),
                "{case_id} is a helper, not the agent"
            );
            assert_eq!(set.child_role("codex", &proc), Some(role), "{case_id} role");
        } else if case["expect"].is_null() {
            assert!(codex_match(&proc, &ancestors).is_none(), "{case_id}");
            assert!(set.child_role("codex", &proc).is_none(), "{case_id}");
        } else {
            let expected = case["expect"].as_str().expect("expect");
            let (id, evidence, _) = codex_match(&proc, &ancestors).expect(case_id);
            assert_eq!(id, expected, "{case_id}");
            assert_eq!(evidence, "I", "{case_id}");
        }
    }
}

#[test]
fn sandbox_helpers_are_children_not_agents() {
    let set = load_profiles(None).expect("builtins");
    // child_role tests each argv element on its own, so the helper is the
    // file name, not a directory prefix.
    let helpers = [
        ("sandbox-exec", "sandbox-exec"),
        ("bwrap", "bwrap"),
        ("codex-linux-sandbox", "codex-linux-sandbox"),
        ("SANDBOX-EXEC.EXE", "sandbox-exec.exe"),
    ];
    for (exe, arg) in helpers {
        let proc = proc_info(9, exe, &[arg], &[]);
        assert!(
            identify(&proc, &[]).is_none(),
            "{exe} must not identify as an agent"
        );
        assert_eq!(set.child_role("codex", &proc), Some("sandbox"), "{exe}");
    }
    let unrelated = proc_info(10, "bash", &["bash", "-lc", "true"], &[]);
    assert_eq!(set.child_role("codex", &unrelated), None);
}

#[test]
fn hook_fixture_maps_command_and_drops_body() {
    let text = fs::read_to_string(fixture("hook.json")).expect("read hook");
    let payload: Value = serde_json::from_str(&text).expect("json");
    let calls = parse_hook("codex", &payload);
    assert_eq!(calls.len(), 1);
    let call = &calls[0];
    assert_eq!(call.agent, "codex");
    assert_eq!(call.tool, "Bash");
    assert_eq!(call.phase, ToolPhase::Pre);
    assert_eq!(call.agent_session.as_deref(), Some("synthetic-session"));
    assert_eq!(call.call_id.as_deref(), Some("synthetic-call"));
    assert_eq!(
        call.summary.get("command").and_then(Value::as_str),
        Some("true")
    );
    let rendered = serde_json::to_string(&call.summary).expect("summary");
    assert!(
        !rendered.contains("synthetic-body-not-stored"),
        "{rendered}"
    );
    assert!(
        !rendered.contains("synthetic-output-not-stored"),
        "{rendered}"
    );
    assert!(call.summary.get("content").is_none());
    assert!(call.summary.get("output").is_none());
}

#[test]
fn otel_plan_keeps_user_endpoint_and_injects_nothing() {
    let mut env = BTreeMap::new();
    assert_eq!(otel_injection_plan(&env), OtelEnvPlan::NotInjected);
    assert!(otel_child_env(&OtelEnvPlan::NotInjected).is_empty());

    env.insert(
        "OTEL_EXPORTER_OTLP_ENDPOINT".to_owned(),
        "http://127.0.0.1:9/v1/logs".to_owned(),
    );
    env.insert("CODEX_HOME".to_owned(), "/tmp/placeholder-codex".to_owned());
    let plan = otel_injection_plan(&env);
    assert_eq!(
        plan,
        OtelEnvPlan::UserEndpointKept("http://127.0.0.1:9/v1/logs".to_owned())
    );
    let extra = otel_child_env(&plan);
    assert!(extra.is_empty(), "must not override or add an endpoint");
    assert_eq!(
        env.get("OTEL_EXPORTER_OTLP_ENDPOINT").map(String::as_str),
        Some("http://127.0.0.1:9/v1/logs")
    );

    env.insert("OTEL_EXPORTER_OTLP_ENDPOINT".to_owned(), String::new());
    assert_eq!(otel_injection_plan(&env), OtelEnvPlan::NotInjected);
}

#[test]
fn otel_source_starts_without_writing_config() {
    let mut source = OtelInjection::new();
    assert_eq!(source.id(), "codex/otel");
    assert!(!source.is_started());
    let session = crate::channel::SessionHandle::new("synthetic-session");
    source.start(&session).expect("start");
    assert!(source.is_started());
    assert_eq!(source.plan(), Some(&OtelEnvPlan::NotInjected));
    source.stop().expect("stop");
    assert!(!source.is_started());
    // stop must leave the plan in place: it records why nothing was injected.
    assert_eq!(source.plan(), Some(&OtelEnvPlan::NotInjected));
}
