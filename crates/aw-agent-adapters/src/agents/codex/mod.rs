//! Codex CLI identification notes and the OTEL self-report placeholder (P5-AGENT-05).
//!
//! Process matching stays in the embedded `codex.toml` profile and
//! [`crate::identify`]. This module does not open `~/.codex/`, does not write
//! `config.toml`, and does not read a session transcript.
//!
//! A transcript channel (`source = agent.codex/transcript`) needs an ADR first:
//! SPIKE-07 §5.2 says the sessions-directory format is unverified, and the task
//! card says that path has to record the privacy tradeoff before any code reads
//! it. This card does not implement it and does not write that ADR.
//!
//! Docs checked 2026-10-09 (pages have no document version):
//! - <https://learn.chatgpt.com/docs/config-file/config-advanced> (`[otel]`
//!   defaults: `exporter = "none"`, `log_user_prompt = false`; project
//!   `.codex/config.toml` ignores `otel`; `--config` is a per-run override)
//! - <https://learn.chatgpt.com/docs/config-file/environment-variables> (no OTEL
//!   endpoint variable; `CODEX_HOME` only relocates the whole state root)
//! - <https://learn.chatgpt.com/docs/sandboxing> (macOS Seatbelt; Linux `bwrap`)
//! - <https://learn.chatgpt.com/docs/agent-approvals-security> (macOS runs
//!   commands with `sandbox-exec`)
//! - Codex `main` README `codex-rs/linux-sandbox` names the bundled helper
//!   `codex-linux-sandbox`. That name is not in the public sandbox page.

mod identify;
mod otel;

#[cfg(test)]
mod tests;

pub use identify::{codex_match, is_codex, proc_info, CODEX_EXE_NAMES};
pub use otel::{
    otel_child_env, otel_injection_plan, OtelEnvPlan, OtelInjection, CODEX_OTEL_CONFIG_KEY,
    CODEX_OTLP_ENDPOINT_ENV,
};
