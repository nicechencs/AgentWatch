//! Role names and the caller's precomputed match.
//!
//! [`MatchBasis`] is what `aw-agent-adapters::identify` already decided, plus
//! the child `role_regex` hits the caller looked up. This module does not
//! compile those regexes and does not open profile files.

use std::fmt;

/// Source string written on every draft. Not a collector probe name.
pub(crate) const SOURCE_STR: &str = "pipeline.agents/identify";

/// Evidence letter. Always inference. Never E1, E2, E3, or S.
pub(crate) const EVIDENCE_STR: &str = "I";

/// Role stored on an [`super::AgentInstanceDraft`].
///
/// The string form matches `agent_instances.role` in the store:
/// `primary` / `sub_agent` / `mcp_server` / `tool` / `unknown`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentRole {
    /// Session root: an agent profile match with no ancestor instance.
    Primary,
    /// Nested process that itself matched an agent profile.
    SubAgent,
    /// Child the parent profile labels as an MCP server, or an explicit MCP hint
    /// plus a pipe when the role table does not.
    McpServer,
    /// Child the parent profile labels as a tool or helper (`sandbox`, `vcs`, …).
    /// Not an agent. Created only when the caller's role table hits.
    Tool,
    /// A real profile match whose role could not be decided.
    ///
    /// This is not "not an agent". Dropping the match would hide a hit.
    Unknown,
}

impl AgentRole {
    /// Wire value. Stable; the store compares these strings.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::SubAgent => "sub_agent",
            Self::McpServer => "mcp_server",
            Self::Tool => "tool",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for AgentRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One `children.role_regex` entry, already decided by the caller.
///
/// `role` is the profile's token (`mcp_server`, `sandbox`, `renderer`, …).
/// `regex` is the pattern text that fired, kept so a later audit can name the
/// rule. It is the profile's pattern, not an argv element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleRule {
    /// Profile role token.
    pub role: String,
    /// Pattern text that matched an argv element. Not the argv itself.
    pub regex: String,
}

/// Child-role rows for one parent profile. The caller copies them out of the
/// profile; this crate does not read TOML.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProfileRoleTable {
    /// Profile id these rows belong to (`claude-code`, …).
    pub profile_id: String,
    /// First hit wins, same order as the profile file.
    pub rules: Vec<RoleRule>,
}

/// What the P5 matcher (or the caller) already computed for this process.
///
/// `None` at the [`super::consider_start`] boundary means "matcher was not
/// run" and is different from `Some` with an empty profile: an empty
/// `profile_id` is not a match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchBasis {
    /// Profile id from `identify`, when this process is itself an agent.
    ///
    /// `None` means the matcher ran and did not hit. That is not an error.
    pub profile_id: Option<String>,
    /// How many match conditions fired. Not used to raise evidence.
    ///
    /// `None` when the caller did not count them. Never stored as `0` to mean
    /// "unknown": unknown is `None`, and `Some(0)` is refused as not a match.
    pub hit_count: Option<u32>,
    /// Child-role token the **parent** profile's `role_regex` assigned, if any.
    ///
    /// Examples from the built-in profiles: `mcp_server`, `sandbox`, `vcs`,
    /// `renderer`. This is the first matching rule, not a joined list.
    pub child_role: Option<String>,
    /// `true` only when the caller has a separate MCP hint (config name, tap
    /// wrapper, or an argv shape it already classified) and the role table did
    /// not say `mcp_server`.
    ///
    /// Combined with `stdio_is_pipe == Some(true)` this can label `mcp_server`.
    /// `None` is not a hint. `Some(false)` means
    /// the caller looked and the command is not an MCP shape.
    pub mcp_argv_hint: Option<bool>,
}

impl MatchBasis {
    /// A process the matcher did not identify, with no child-role hit.
    pub fn none() -> Self {
        Self {
            profile_id: None,
            hit_count: None,
            child_role: None,
            mcp_argv_hint: None,
        }
    }

    /// An agent-profile hit. `hit_count` must be `Some(n)` with `n >= 1`.
    pub fn agent(profile_id: impl Into<String>, hit_count: u32) -> Self {
        Self {
            profile_id: Some(profile_id.into()),
            hit_count: Some(hit_count),
            child_role: None,
            mcp_argv_hint: None,
        }
    }
}

/// Map a profile `children.role` token onto [`AgentRole`].
///
/// `mcp_server` and the legacy token `mcp` become [`AgentRole::McpServer`].
/// Any other token the profile named (`sandbox`, `vcs`, `renderer`, …) becomes
/// [`AgentRole::Tool`]. [`super::consider_start`] does **not** create an
/// instance for [`AgentRole::Tool`]: that child is not an agent. `None` means
/// the table had no hit.
pub fn role_from_profile(token: &str) -> Option<AgentRole> {
    if token.is_empty() {
        return None;
    }
    if token == "mcp_server" || token == "mcp" {
        return Some(AgentRole::McpServer);
    }
    Some(AgentRole::Tool)
}

/// `true` when `basis.profile_id` is a non-empty id with at least one hit.
pub(crate) fn is_agent_match(basis: &MatchBasis) -> bool {
    match (&basis.profile_id, basis.hit_count) {
        (Some(id), Some(n)) => !id.is_empty() && n >= 1,
        // A profile id with an unknown hit count is not treated as zero hits,
        // and it is not treated as a match either: the caller did not say.
        _ => false,
    }
}
