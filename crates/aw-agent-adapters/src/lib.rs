//! Agent profiles and process-shape identification (P5-AGENT-01).
//!
//! A match is an inference: [`Inference`] is this crate's name for evidence
//! level I. It is not `aw_core::Evidence`. Matching looks at the executable
//! name, argv, the immediate parent's name, and whether an environment
//! variable name exists. It does not read files, process memory, or env values.
//!
//! Built-in E3 hook parsers for `claude-code`, `codex`, and `cursor` are
//! installed on the first [`parse_hook`] call ([`install_builtin_parsers`]).
//! `aider` has no confirmed hook schema and is not registered. An unknown
//! agent id still parses to an empty list.

#![forbid(unsafe_code)]

mod channel;
mod identify;
pub mod mcp_tap;
mod profile;

pub use channel::{
    bound_tool_call, install_builtin_parsers, parse_hook, register_hook, ChannelError, HookParser,
    HookRegistry, SelfReportSource, SessionHandle, MAX_CALL_BYTES,
};
pub use mcp_tap::{
    extract, push_frames, ArgType, ExtractGap, FrameError, FrameOutcome, RpcExtract, Splitter,
    DIR_C2S, DIR_S2C, MAX_FRAME_BYTES, MAX_KEY_SCALARS,
};
pub use identify::{identify, identify_with, AgentMatch, Inference, MatchHit, ProcInfo};
pub use profile::{
    load_profiles, AgentProfile, ChildRole, ChildrenRules, MatchRules, ProfileError, ProfileSet,
};

/// Empty marker so `aw-daemon`'s collector wiring can name this crate.
///
/// `crates/aw-daemon/src/collectors.rs` references this type and is outside
/// this task's file scope, so the marker stays.
pub struct Placeholder;
