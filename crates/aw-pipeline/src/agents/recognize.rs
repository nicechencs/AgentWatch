//! Decide whether one process becomes an [`super::AgentInstanceDraft`].
//!
//! Not wired into Enrich. The caller runs the P5 matcher, fills
//! [`super::MatchBasis`], and calls [`consider_start`].

use super::observe::ProcessObservation;
use super::role::{is_agent_match, role_from_profile, AgentRole, MatchBasis};
use super::tree::{AgentInstanceDraft, AgentTree};

/// Why a process was not turned into an instance.
///
/// This is not a dropped event. The process is still recorded in the tree so
/// a later child can walk through it. `NotAnAgent` means the matcher did not
/// hit and no MCP/tool rule hit. It must not be used to hide a real match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotInstanceReason {
    /// No agent-profile match and no child-role / MCP hint that applies.
    NotAnAgent,
    /// The parent profile named a child role that is not an agent and not an
    /// MCP server (`sandbox`, `vcs`, `renderer`, …). The process link is kept.
    /// The match is not discarded: the reason names it.
    RoleNotInstantiated,
    /// `proc_uid` was already an instance. The first draft stands.
    Duplicate,
}

/// Outcome of one [`consider_start`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Considered {
    /// A new draft was appended to the tree.
    Instance,
    /// No instance. `reason` says why. The process link was still recorded.
    Skipped(NotInstanceReason),
}

/// Consider one process start.
///
/// `basis` is the precomputed matcher result. Pass [`MatchBasis::none`] when
/// the matcher ran and missed. Do not pass a guessed profile.
///
/// Parent instance = nearest ancestor **instance**, using parent links already
/// noted on `tree` plus this observation's `parent_uid`.
///
/// Role:
///
/// * agent profile, no ancestor instance → [`AgentRole::Primary`]
/// * agent profile, ancestor instance exists → [`AgentRole::SubAgent`]
/// * not an agent profile, but the walk finds an ancestor instance, and the
///   role token is `mcp_server` / `mcp` → [`AgentRole::McpServer`]
/// * same, but the token is some other profile role (`sandbox`, `vcs`,
///   `renderer`, …) → no instance. [`NotInstanceReason::RoleNotInstantiated`]
///   records that a role rule fired and was not dropped silently. The process
///   link stays, so a grandchild can still walk to the ancestor agent.
/// * same ancestry, role token absent, `mcp_argv_hint == Some(true)` **and**
///   `stdio_is_pipe == Some(true)` → [`AgentRole::McpServer`]
/// * otherwise → [`Considered::Skipped`] with [`NotInstanceReason::NotAnAgent`]
///
/// `stdio_is_pipe == None` never produces `mcp_server` by itself.
/// A child role without an ancestor instance does not invent a primary MCP
/// server: "spawned by an agent" is required.
///
/// This function does not read the event's own evidence and does not copy it.
/// The draft's evidence is always `"I"`.
pub fn consider_start(
    tree: &mut AgentTree,
    obs: &ProcessObservation<'_>,
    basis: &MatchBasis,
) -> Considered {
    tree.note_process(obs.proc_uid, obs.parent_uid);

    if tree.get(obs.proc_uid).is_some() {
        return Considered::Skipped(NotInstanceReason::Duplicate);
    }

    let ancestor = tree.nearest_ancestor_instance(obs.proc_uid);
    let agent = is_agent_match(basis);
    let from_role = basis.child_role.as_deref().and_then(role_from_profile);

    let role = match (agent, ancestor, from_role) {
        (true, None, _) => AgentRole::Primary,
        (true, Some(_), _) => AgentRole::SubAgent,
        (false, Some(_), Some(AgentRole::McpServer)) => AgentRole::McpServer,
        (false, Some(_), Some(AgentRole::Tool)) => {
            return Considered::Skipped(NotInstanceReason::RoleNotInstantiated);
        }
        (false, Some(_), Some(AgentRole::Primary | AgentRole::SubAgent | AgentRole::Unknown)) => {
            // role_from_profile does not return these. If it ever does, do not
            // pretend the process is a second primary.
            AgentRole::Unknown
        }
        (false, Some(_), None) if mcp_by_hint(obs, basis) => AgentRole::McpServer,
        _ => {
            return Considered::Skipped(NotInstanceReason::NotAnAgent);
        }
    };

    // A tool/mcp row inherits the ancestor's profile id when this process did
    // not match a profile of its own. That id is "which profile's role rule",
    // not a claim that the child is that agent.
    let profile_id = if agent {
        basis.profile_id.clone()
    } else {
        ancestor
            .and_then(|uid| tree.get(uid))
            .and_then(|parent| parent.profile_id.clone())
    };

    let draft = AgentInstanceDraft::new(
        tree.session_id(),
        obs.proc_uid,
        obs.pid,
        profile_id,
        role,
        ancestor,
    );
    if tree.insert(draft) {
        Considered::Instance
    } else {
        Considered::Skipped(NotInstanceReason::Duplicate)
    }
}

/// MCP without a role-table hit: both the hint and an observed pipe are required.
fn mcp_by_hint(obs: &ProcessObservation<'_>, basis: &MatchBasis) -> bool {
    basis.mcp_argv_hint == Some(true) && obs.stdio_is_pipe == Some(true)
}

/// File name of `path`, for callers that want to show an exe next to a draft.
///
/// Not used by [`consider_start`]. Exposed so a later card can fill a display
/// field without reimplementing the split. `None` when `path` is empty.
pub fn exe_file_name(path: &str) -> Option<&str> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return None;
    }
    match trimmed.rsplit(['/', '\\']).next() {
        Some(name) if !name.is_empty() => Some(name),
        _ => None,
    }
}

/// True when some argv element looks like the examples in the task card:
/// a command named `mcp-server-*`, or `npx` with a following
/// `@modelcontextprotocol/…` argument.
///
/// This is the hint a caller can put in [`MatchBasis::mcp_argv_hint`] when the
/// profile role table was not consulted. It does not match a bare `node`,
/// `npm`, or `npx` with no MCP package argument.
///
/// The function does not allocate a joined command line.
pub fn argv_looks_like_mcp(argv: &[aw_core::Arg]) -> bool {
    let mut saw_npx = false;
    for arg in argv {
        let text = arg.as_str();
        if text.is_empty() {
            continue;
        }
        if arg_is_mcp_server_bin(text) || arg_has_mcp_package(text) {
            return true;
        }
        if arg_is_npx(text) {
            saw_npx = true;
            continue;
        }
        if saw_npx && arg_has_mcp_package(text) {
            return true;
        }
        // Flags between npx and the package (`-y`) do not cancel the hint.
        if saw_npx && !text.starts_with('-') && !arg_has_mcp_package(text) {
            saw_npx = false;
        }
    }
    false
}

fn arg_is_npx(text: &str) -> bool {
    let name = file_name(text);
    let base = strip_exe(name);
    base.eq_ignore_ascii_case("npx")
}

fn arg_is_mcp_server_bin(text: &str) -> bool {
    let name = file_name(text);
    let base = strip_exe(name);
    let rest = match base
        .get(.."mcp-server-".len())
        .filter(|prefix| prefix.eq_ignore_ascii_case("mcp-server-"))
    {
        Some(_) => &base["mcp-server-".len()..],
        None => return false,
    };
    !rest.is_empty() && !rest.contains('/') && !rest.contains('\\')
}

fn arg_has_mcp_package(text: &str) -> bool {
    // ASCII case-insensitive substring. No allocation: argv may hold secrets,
    // and a lowered copy would be a second place those bytes sit.
    const NEEDLE: &[u8] = b"@modelcontextprotocol/";
    let bytes = text.as_bytes();
    if bytes.len() < NEEDLE.len() {
        return false;
    }
    bytes.windows(NEEDLE.len()).any(|window| {
        window
            .iter()
            .zip(NEEDLE.iter())
            .all(|(have, want)| have.to_ascii_lowercase() == *want)
    })
}

fn file_name(text: &str) -> &str {
    match text.rsplit(['/', '\\']).next() {
        Some(name) if !name.is_empty() => name,
        _ => text,
    }
}

fn strip_exe(name: &str) -> &str {
    match name.rsplit_once('.') {
        Some((base, ext)) if ext.eq_ignore_ascii_case("exe") => base,
        _ => name,
    }
}
