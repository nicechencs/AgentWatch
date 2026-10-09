//! Codex process-shape checks against the embedded profile.
//!
//! These are inferences ([`crate::Inference`]). SPIKE-07 §5.2 did not record a
//! real `ps` line: the product command is `codex`, and the real executable name
//! and argv are unverified. The exe names below are the product command plus
//! the Windows `.exe` form already declared in `profiles/codex.toml`, not a
//! captured path.
//!
//! Sandbox helpers are children, not the agent. Official pages checked
//! 2026-10-09 name `sandbox-exec` (macOS Seatbelt) and `bwrap` (Linux default).
//! The Codex `main` linux-sandbox README names the bundled helper
//! `codex-linux-sandbox`. A role hit is a label, not proof the process is a
//! sandbox.

use crate::{identify, Inference, MatchHit, ProcInfo};

/// Executable names the profile treats as the Codex CLI itself.
pub const CODEX_EXE_NAMES: &[&str] = &["codex", "codex.exe"];

/// Build a [`ProcInfo`] for a test or a caller that already has argv.
///
/// `env_keys` are names only. This function does not read the process environment.
#[must_use]
pub fn proc_info(pid: u32, exe_name: &str, argv: &[&str], env_keys: &[&str]) -> ProcInfo {
    ProcInfo {
        pid,
        exe_name: exe_name.to_owned(),
        argv: argv.iter().map(|arg| (*arg).to_owned()).collect(),
        env_keys: env_keys.iter().map(|key| (*key).to_owned()).collect(),
    }
}

/// `true` when built-in identification returns the `codex` profile.
#[must_use]
pub fn is_codex(proc: &ProcInfo, ancestors: &[ProcInfo]) -> bool {
    identify(proc, ancestors).is_some_and(|hit| hit.profile_id == "codex")
}

/// Profile id and the evidence letter `"I"` when `proc` matches Codex.
///
/// `None` for a sandbox helper, a bare `node` / `python`, or any other process.
/// The second element is [`Inference::as_str`], never a stronger level.
#[must_use]
pub fn codex_match<'a>(
    proc: &'a ProcInfo,
    ancestors: &'a [ProcInfo],
) -> Option<(&'static str, &'static str, Vec<MatchHit>)> {
    let hit = identify(proc, ancestors)?;
    if hit.profile_id != "codex" {
        return None;
    }
    debug_assert_eq!(hit.evidence, Inference::I);
    Some(("codex", hit.evidence.as_str(), hit.hits))
}
