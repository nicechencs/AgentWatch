//! Pipeline `consider_start` rules only.
//!
//! This is not the P5 matcher. Profile hits arrive as a precomputed
//! [`MatchBasis`]; nothing here loads profiles, reads `/proc`, or inspects a
//! live process table. Identities and paths are synthetic fixtures.

#![allow(clippy::expect_used)]

use aw_core::{Arg, Evidence, ProcUid};
use aw_pipeline::{
    argv_looks_like_mcp, consider_start, exe_file_name, AgentRole, AgentTree, Considered,
    MatchBasis, NotInstanceReason, ProcessObservation, EVIDENCE,
};

const SESSION: i64 = 1;
const PRIMARY: ProcUid = ProcUid(0xA001);
const INTERMEDIATE: ProcUid = ProcUid(0xA002);
const CHILD: ProcUid = ProcUid(0xA003);

fn obs<'a>(
    proc_uid: ProcUid,
    pid: u32,
    parent_uid: Option<ProcUid>,
    exe: Option<&'a str>,
    argv: Option<&'a [Arg]>,
    stdio_is_pipe: Option<bool>,
) -> ProcessObservation<'a> {
    ProcessObservation {
        proc_uid,
        pid,
        ppid: parent_uid.map(|_| 1).unwrap_or(0),
        parent_uid,
        exe,
        argv,
        stdio_is_pipe,
    }
}

fn child_role(token: &str) -> MatchBasis {
    MatchBasis {
        profile_id: None,
        hit_count: None,
        child_role: Some(token.to_owned()),
        mcp_argv_hint: None,
    }
}

fn mcp_hint(hint: Option<bool>) -> MatchBasis {
    MatchBasis {
        profile_id: None,
        hit_count: None,
        child_role: None,
        mcp_argv_hint: hint,
    }
}

fn seed_primary(tree: &mut AgentTree) {
    let start = obs(PRIMARY, 4100, None, Some("/opt/fixture/agent"), None, None);
    let outcome = consider_start(tree, &start, &MatchBasis::agent("fixture-agent", 1));
    assert_eq!(outcome, Considered::Instance);
}

fn assert_inference(tree: &AgentTree, uid: ProcUid, role: AgentRole) {
    let draft = tree.get(uid).expect("instance recorded");
    assert_eq!(draft.role, role);
    assert_eq!(draft.evidence, "I");
    assert_eq!(draft.evidence, EVIDENCE);
    // The stored letter is the inference variant, never a kernel fact.
    assert_eq!(draft.evidence, variant_name(&Evidence::I));
    assert_ne!(draft.evidence, variant_name(&Evidence::E1));
}

fn variant_name(evidence: &Evidence) -> &'static str {
    match evidence {
        Evidence::E1 => "E1",
        Evidence::E2 => "E2",
        Evidence::E3 => "E3",
        Evidence::S => "S",
        Evidence::I => "I",
        Evidence::NA(_) => "NA",
    }
}

#[test]
fn profile_match_without_ancestor_is_primary_inference() {
    let mut tree = AgentTree::new(SESSION);
    let start = obs(PRIMARY, 4100, None, Some("/opt/fixture/agent"), None, None);
    let outcome = consider_start(&mut tree, &start, &MatchBasis::agent("fixture-agent", 2));

    assert_eq!(outcome, Considered::Instance);
    assert_inference(&tree, PRIMARY, AgentRole::Primary);
    let draft = tree.get(PRIMARY).expect("primary");
    assert_eq!(draft.profile_id.as_deref(), Some("fixture-agent"));
    assert_eq!(draft.parent_proc_uid, None);
    assert_eq!(draft.session_id, SESSION);
    assert_eq!(draft.pid, 4100);
}

#[test]
fn profile_match_with_ancestor_is_sub_agent() {
    let mut tree = AgentTree::new(SESSION);
    seed_primary(&mut tree);

    let start = obs(
        CHILD,
        4101,
        Some(PRIMARY),
        Some("/opt/fixture/agent"),
        None,
        None,
    );
    let outcome = consider_start(&mut tree, &start, &MatchBasis::agent("fixture-agent", 1));

    assert_eq!(outcome, Considered::Instance);
    assert_inference(&tree, CHILD, AgentRole::SubAgent);
    assert_eq!(
        tree.get(CHILD).expect("sub-agent").parent_proc_uid,
        Some(PRIMARY)
    );
}

#[test]
fn mcp_role_token_with_ancestor_is_mcp_server() {
    let mut tree = AgentTree::new(SESSION);
    seed_primary(&mut tree);

    // A non-agent process between the agent and the child does not break the walk.
    let hop = obs(
        INTERMEDIATE,
        4102,
        Some(PRIMARY),
        Some("/opt/fixture/node"),
        None,
        None,
    );
    assert_eq!(
        consider_start(&mut tree, &hop, &MatchBasis::none()),
        Considered::Skipped(NotInstanceReason::NotAnAgent)
    );

    let start = obs(
        CHILD,
        4103,
        Some(INTERMEDIATE),
        Some("/opt/fixture/node"),
        None,
        None,
    );
    let outcome = consider_start(&mut tree, &start, &child_role("mcp_server"));

    assert_eq!(outcome, Considered::Instance);
    assert_inference(&tree, CHILD, AgentRole::McpServer);
    let draft = tree.get(CHILD).expect("mcp server");
    // Inherited from the ancestor instance, not claimed as this process's profile.
    assert_eq!(draft.profile_id.as_deref(), Some("fixture-agent"));
    assert_eq!(draft.parent_proc_uid, Some(PRIMARY));
}

#[test]
fn tool_role_is_skipped_but_the_process_link_stays() {
    let mut tree = AgentTree::new(SESSION);
    seed_primary(&mut tree);

    let start = obs(
        INTERMEDIATE,
        4200,
        Some(PRIMARY),
        Some("/opt/fixture/sandbox"),
        None,
        None,
    );
    let outcome = consider_start(&mut tree, &start, &child_role("sandbox"));
    assert_eq!(
        outcome,
        Considered::Skipped(NotInstanceReason::RoleNotInstantiated)
    );
    assert!(tree.get(INTERMEDIATE).is_none());

    // The skipped process is still a parent link, so a later child can walk through it.
    let grandchild = obs(
        CHILD,
        4201,
        Some(INTERMEDIATE),
        Some("/opt/fixture/agent"),
        None,
        None,
    );
    let nested = consider_start(
        &mut tree,
        &grandchild,
        &MatchBasis::agent("fixture-agent", 1),
    );
    assert_eq!(nested, Considered::Instance);
    assert_eq!(
        tree.get(CHILD).expect("grandchild").parent_proc_uid,
        Some(PRIMARY)
    );
}

#[test]
fn mcp_argv_hint_needs_an_observed_pipe() {
    let argv = [
        Arg::new("npx"),
        Arg::new("-y"),
        Arg::new("@modelcontextprotocol/server-example"),
    ];

    let mut piped = AgentTree::new(SESSION);
    seed_primary(&mut piped);
    let with_pipe = obs(
        CHILD,
        4300,
        Some(PRIMARY),
        Some("/opt/fixture/npx"),
        Some(&argv),
        Some(true),
    );
    assert_eq!(
        consider_start(&mut piped, &with_pipe, &mcp_hint(Some(true))),
        Considered::Instance
    );
    assert_inference(&piped, CHILD, AgentRole::McpServer);

    let mut unknown = AgentTree::new(SESSION);
    seed_primary(&mut unknown);
    let without_pipe = obs(
        CHILD,
        4301,
        Some(PRIMARY),
        Some("/opt/fixture/npx"),
        Some(&argv),
        None,
    );
    assert_eq!(
        consider_start(&mut unknown, &without_pipe, &mcp_hint(Some(true))),
        Considered::Skipped(NotInstanceReason::NotAnAgent)
    );
    assert!(unknown.get(CHILD).is_none());
}

#[test]
fn second_consider_start_for_the_same_uid_is_duplicate() {
    let mut tree = AgentTree::new(SESSION);
    let start = obs(PRIMARY, 4100, None, Some("/opt/fixture/agent"), None, None);
    let basis = MatchBasis::agent("fixture-agent", 1);
    assert_eq!(
        consider_start(&mut tree, &start, &basis),
        Considered::Instance
    );

    let again = consider_start(&mut tree, &start, &basis);
    assert_eq!(again, Considered::Skipped(NotInstanceReason::Duplicate));
    assert_eq!(tree.instances().len(), 1);
    assert_eq!(
        tree.get(PRIMARY).expect("first draft").role,
        AgentRole::Primary
    );
}

#[test]
fn argv_looks_like_mcp_matches_package_and_server_binary_only() {
    let npx = [
        Arg::new("npx"),
        Arg::new("-y"),
        Arg::new("@modelcontextprotocol/server-example"),
    ];
    assert!(argv_looks_like_mcp(&npx));

    let binary = [Arg::new("/opt/fixture/mcp-server-filesystem")];
    assert!(argv_looks_like_mcp(&binary));

    assert!(!argv_looks_like_mcp(&[Arg::new("node")]));
    assert!(!argv_looks_like_mcp(&[Arg::new("npx"), Arg::new("-y")]));
}

#[test]
fn exe_file_name_splits_posix_and_windows_paths() {
    assert_eq!(exe_file_name("/opt/fixture/node"), Some("node"));
    assert_eq!(exe_file_name(r"C:\fixture\node.exe"), Some("node.exe"));
    assert_eq!(exe_file_name(""), None);
    assert_eq!(exe_file_name("   "), None);
}
