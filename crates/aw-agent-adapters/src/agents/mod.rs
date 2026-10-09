//! Per-agent adapters. Each subdirectory owns one product.
//!
//! Claude Code (P5-AGENT-03, P5-AGENT-04) maps hook stdin and OTEL logs into
//! `AgentToolCall`. It does not write `~/.claude/` and does not read transcripts.
//!
//! Cursor (P5-AGENT-06) labels Electron child roles and plans a launch hint plus
//! a `--proxy-server=` argument. It does not attach an E3 channel.
//!
//! Codex (P5-AGENT-05) identifies the CLI and labels sandbox helpers. Its OTEL
//! plan does not write `~/.codex/`. A transcript channel is not implemented:
//! that needs an ADR first.
//!
//! Python (P5-AGENT-07) identifies Aider and plans CA variables for an explicit
//! `python-generic` selection. It does not edit a Python environment.

pub mod claude_code;
pub mod codex;
pub mod cursor;
pub mod python_generic;
