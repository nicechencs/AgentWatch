//! Pure process-shape matching. No filesystem, no process memory, no env values.

use crate::profile::ProfileSet;

/// One observed process, already reduced to what matching is allowed to see.
///
/// `env_keys` are names only. Values are never stored here and are not read.
/// `exe_name` is the file name, not a full path (`node.exe`, not `C:\...\node.exe`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcInfo {
    /// Operating-system pid. Not used for matching.
    pub pid: u32,
    /// File name of the executable.
    pub exe_name: String,
    /// Argument vector as observed. Not joined, not executed.
    pub argv: Vec<String>,
    /// Environment variable names present on the process. Not values.
    pub env_keys: Vec<String>,
}

/// Evidence level of an identification.
///
/// This is always inference. In the evidence model that is level I: the UI
/// shows it as “识别为”, and it must not be upgraded. The type is local on
/// purpose — it is not `aw_core::Evidence`, so this crate does not depend on
/// `aw-core`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Inference {
    /// A profile rule matched. Evidence level I.
    I,
}

impl Inference {
    /// The evidence-model letter for this level.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::I => "I",
        }
    }
}

/// Which configured condition fired. The list is the confidence basis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchHit {
    /// `exe_name` matched `match.exe_names` (ASCII case-insensitive, `.exe` ignored).
    ExeName(String),
    /// An argv element matched this `match.argv_regex` pattern.
    ArgvRegex(String),
    /// The immediate parent matched `match.parent_exe`.
    ParentExe(String),
    /// This `match.env_keys` entry was present. The value was not read.
    EnvKey(String),
}

/// A profile hit. `evidence` is always [`Inference::I`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentMatch {
    /// Profile `id`, for example `claude-code`.
    pub profile_id: String,
    /// Conditions that fired, in profile order.
    pub hits: Vec<MatchHit>,
    /// Always [`Inference::I`].
    pub evidence: Inference,
}

/// Match `proc` against the built-in profiles only.
///
/// `ancestors` is nearest-first: index 0 is the immediate parent. Returns
/// `None` when nothing matches, including when every built-in profile failed
/// to compile (that failure is reported by [`crate::load_profiles`], not by
/// panicking here).
///
/// Matching reads only `exe_name`, `argv`, the immediate parent's `exe_name`,
/// and whether an env key exists. It does not open files or read memory.
pub fn identify(proc: &ProcInfo, ancestors: &[ProcInfo]) -> Option<AgentMatch> {
    crate::profile::builtins().and_then(|set| identify_with(set, proc, ancestors))
}

/// Match `proc` against an explicit [`ProfileSet`] (built-ins plus user overrides).
pub fn identify_with(
    profiles: &ProfileSet,
    proc: &ProcInfo,
    ancestors: &[ProcInfo],
) -> Option<AgentMatch> {
    profiles.identify(proc, ancestors)
}

pub(crate) fn exe_eq(actual: &str, expected: &str) -> bool {
    strip_exe(actual).eq_ignore_ascii_case(strip_exe(expected))
}

fn strip_exe(name: &str) -> &str {
    match name.rsplit_once('.') {
        Some((base, ext)) if ext.eq_ignore_ascii_case("exe") => base,
        _ => name,
    }
}

/// Gates, all of which must pass when they are configured.
///
/// `exe_names` and `argv_regex` are alternatives: either one identifies the
/// process. A profile that sets neither never matches, so it cannot be a
/// catch-all for `node` or `python`. `parent_exe` and `env_keys`, when set,
/// are required. Env keys are existence checks only.
pub(crate) fn try_match(
    rules_exe: &[String],
    argv_regex: &[regex::Regex],
    parent_exe: Option<&str>,
    env_keys: &[String],
    proc: &ProcInfo,
    ancestors: &[ProcInfo],
) -> Option<Vec<MatchHit>> {
    let mut hits = Vec::new();

    if let Some(expected) = parent_exe {
        let parent = ancestors.first()?;
        if !exe_eq(&parent.exe_name, expected) {
            return None;
        }
        hits.push(MatchHit::ParentExe(parent.exe_name.clone()));
    }

    for key in env_keys {
        // Exact match. On Unix names are case-sensitive; folding would treat a
        // different variable as present.
        if !proc.env_keys.iter().any(|have| have == key) {
            return None;
        }
        hits.push(MatchHit::EnvKey(key.clone()));
    }

    let mut identified = false;
    if rules_exe.iter().any(|name| exe_eq(&proc.exe_name, name)) {
        identified = true;
        hits.push(MatchHit::ExeName(proc.exe_name.clone()));
    }
    for pattern in argv_regex {
        if proc.argv.iter().any(|arg| pattern.is_match(arg)) {
            identified = true;
            hits.push(MatchHit::ArgvRegex(pattern.as_str().to_owned()));
        }
    }
    if !identified {
        return None;
    }
    Some(hits)
}
