//! AgentInstance recognition (P6-PIPE-01).
//!
//! This module is a pure function. It is **not** called from [`crate::stage::EnrichStage`].
//! A later card wires [`consider_start`] into Enrich and writes the draft into
//! `aw-store`. Nothing here changes collection scope: there is no `ScopeFilter`
//! import and no collector configuration.
//!
//! Identification is always evidence level I ([`EVIDENCE`]). A profile hit is a
//! judgment, not a kernel fact. The source string is [`SOURCE`], not an eBPF or
//! ETW probe name.
//!
//! The P5 matcher lives in `aw-agent-adapters` and reads the filesystem. This
//! crate does not depend on that crate and does not load profiles. The caller
//! passes an already-computed [`MatchBasis`] and the parent's [`ProfileRoleTable`].
//!
//! A plain `node` child of an agent is not an instance. An MCP server is one
//! only when an agent spawned it **and** either the role table says `mcp_server`
//! or (`stdio_is_pipe == Some(true)` and the argv looks like an MCP command).
//! `stdio_is_pipe: None` means the collector did not say; it is not `false`.

mod observe;
mod recognize;
mod role;
mod tree;

pub use observe::ProcessObservation;
pub use recognize::{
    argv_looks_like_mcp, consider_start, exe_file_name, Considered, NotInstanceReason,
};
pub use role::{role_from_profile, AgentRole, MatchBasis, ProfileRoleTable, RoleRule};
pub use tree::{apply_label, AgentInstanceDraft, AgentTree, EVIDENCE, SOURCE};
