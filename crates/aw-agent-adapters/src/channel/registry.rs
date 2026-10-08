//! Agent-id → [`HookParser`] table.
//!
//! P5-AGENT-03 and later cards insert parsers. This card ships an empty table.
//! A miss is an empty `Vec`, never an error: the hook process must exit 0 even
//! when the agent id is unknown.

use std::sync::{OnceLock, RwLock};

use serde_json::Value;

use aw_core::AgentToolCall;

use super::HookParser;

/// Process-wide table. Registration is additive; a later parser for the same id
/// replaces the earlier one so a test (or a user adapter) can override a built-in.
fn table() -> &'static RwLock<Vec<Box<dyn HookParser>>> {
    static TABLE: OnceLock<RwLock<Vec<Box<dyn HookParser>>>> = OnceLock::new();
    TABLE.get_or_init(|| RwLock::new(Vec::new()))
}

/// Register `parser`. Replaces any parser already stored for the same agent id.
///
/// A poisoned lock is recovered: dropping a hook registration is worse than
/// reading the table after a panic in some other parser.
pub fn register_hook(parser: Box<dyn HookParser>) {
    let mut guard = match table().write() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let id = parser.agent_id().to_owned();
    if let Some(slot) = guard.iter_mut().find(|existing| existing.agent_id() == id) {
        *slot = parser;
    } else {
        guard.push(parser);
    }
}

/// Dispatch `payload` to the parser registered for `agent`.
///
/// Unknown agents, a poisoned lock, and a parser that returns nothing all yield
/// an empty `Vec`. The agent id comparison is exact and case-sensitive: profile
/// ids are already lowercase (`claude-code`).
pub fn parse_hook(agent: &str, payload: &Value) -> Vec<AgentToolCall> {
    let guard = match table().read() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    match guard.iter().find(|parser| parser.agent_id() == agent) {
        Some(parser) => parser.parse_hook(payload),
        None => Vec::new(),
    }
}

/// The table itself, named so daemon code can talk about "the registry" without
/// reaching into the static. It only forwards to the functions above.
#[derive(Debug, Default, Clone, Copy)]
pub struct HookRegistry;

impl HookRegistry {
    /// See [`parse_hook`].
    #[must_use]
    pub fn parse(&self, agent: &str, payload: &Value) -> Vec<AgentToolCall> {
        parse_hook(agent, payload)
    }
}
