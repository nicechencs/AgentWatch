//! Planned OTEL environment for a Codex child. Nothing here is applied.
//!
//! P5-AGENT-04 injects `OTEL_EXPORTER_OTLP_ENDPOINT` because Claude Code reads
//! that variable. Codex does not. The config reference and the environment
//! page (checked 2026-10-09) put the exporter endpoint in user-level
//! `[otel]` inside `config.toml`. The only OTEL variable Codex's own otel
//! README documents is `OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE`,
//! which does not choose an endpoint. `CODEX_HOME` would move the whole state
//! root, not add one exporter, so it is not an injection either.
//!
//! This module therefore reuses [`crate::channel::SelfReportSource`] as a
//! placeholder: [`OtelInjection::start`] records that the local receiver was
//! offered and returns. It does not spawn a process, set an environment, or
//! touch a file. The daemon applies [`otel_child_env`] later, and only to the
//! process it starts. An endpoint the user already put in the child
//! environment is left as-is.
//!
//! Prompts and model output are not accepted here. SPIKE-07 §5.2: a Codex
//! OTEL tool metric is an internal name (`shell`, `apply_patch`) without the
//! command text, and `codex.tool_result` is a duration, a success flag, and an
//! output summary. The summary is not kept.

use std::collections::BTreeMap;

use crate::channel::{ChannelError, SelfReportSource, SessionHandle};

/// Env var a user may already have pointed at their own collector.
///
/// Codex's documented config does not read this. It is still the variable
/// P5-AGENT-02 uses for the local receiver, so a value already in the child
/// environment is treated as "the user has telemetry" and is not replaced.
pub const CODEX_OTLP_ENDPOINT_ENV: &str = "OTEL_EXPORTER_OTLP_ENDPOINT";

/// User-level key that actually selects the Codex log exporter.
///
/// Present only so a comment and a test can name it. This module never writes it.
pub const CODEX_OTEL_CONFIG_KEY: &str = "otel.exporter";

/// What to pass to the child Codex process. Either a copy of the user's
/// endpoint, or nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OtelEnvPlan {
    /// `OTEL_EXPORTER_OTLP_ENDPOINT` is already set. Do not replace it.
    ///
    /// The string is the user's value, unchanged. It is not logged.
    UserEndpointKept(String),
    /// No endpoint variable was set. Do not invent one and do not write config.
    ///
    /// Codex would ignore a newly injected standard OTEL endpoint. Writing
    /// `[otel]` would edit the user's config, which this card does not do.
    NotInjected,
}

/// Decide the child environment from names and values the caller already has.
///
/// Only [`CODEX_OTLP_ENDPOINT_ENV`] is consulted. Any other variable, including
/// `CODEX_HOME`, is ignored. A missing key and an empty value are both "not
/// set": an empty endpoint is not a destination, and it is not overwritten
/// with one either (that would still be choosing an endpoint the user did not
/// ask for).
#[must_use]
pub fn otel_injection_plan(child_env: &BTreeMap<String, String>) -> OtelEnvPlan {
    match child_env.get(CODEX_OTLP_ENDPOINT_ENV) {
        Some(value) if !value.is_empty() => OtelEnvPlan::UserEndpointKept(value.clone()),
        _ => OtelEnvPlan::NotInjected,
    }
}

/// Environment entries to add for the child. Always empty.
///
/// [`OtelEnvPlan::UserEndpointKept`] means the caller's map already has the
/// variable, so there is nothing to add. [`OtelEnvPlan::NotInjected`] means
/// adding the standard variable would not make Codex export, and would look
/// like this tool had configured telemetry that Codex does not read.
#[must_use]
pub fn otel_child_env(plan: &OtelEnvPlan) -> BTreeMap<String, String> {
    match plan {
        OtelEnvPlan::UserEndpointKept(_) | OtelEnvPlan::NotInjected => BTreeMap::new(),
    }
}

/// Placeholder [`SelfReportSource`] for `agent.codex/otel`.
///
/// `start` does not open a socket and does not read the session id back out
/// into a file. The local OTLP receiver from P5-AGENT-02 stays unused until a
/// later change can point Codex at it without editing `~/.codex/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtelInjection {
    started: bool,
    plan: Option<OtelEnvPlan>,
}

impl OtelInjection {
    /// Not started, no plan yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            started: false,
            plan: None,
        }
    }

    /// Whether [`SelfReportSource::start`] has been called without a later `stop`.
    #[must_use]
    pub fn is_started(&self) -> bool {
        self.started
    }

    /// Plan recorded by the last `start`, if any.
    #[must_use]
    pub fn plan(&self) -> Option<&OtelEnvPlan> {
        self.plan.as_ref()
    }
}

impl Default for OtelInjection {
    fn default() -> Self {
        Self::new()
    }
}

impl SelfReportSource for OtelInjection {
    fn id(&self) -> &str {
        "codex/otel"
    }

    fn start(&mut self, session: &SessionHandle) -> Result<(), ChannelError> {
        // The session id is not a destination. Storing it here would not make
        // Codex export, and this placeholder has no other use for it.
        let _ = session;
        self.plan = Some(OtelEnvPlan::NotInjected);
        self.started = true;
        Ok(())
    }

    fn stop(&mut self) -> Result<(), ChannelError> {
        self.started = false;
        Ok(())
    }
}
