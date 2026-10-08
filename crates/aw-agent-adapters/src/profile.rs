//! `AgentProfile` TOML. Built-ins are embedded; `agents.d` overrides by id.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use regex::RegexBuilder;
use serde::Deserialize;

use crate::identify::{try_match, AgentMatch, Inference, ProcInfo};

const BUILTINS: &[(&str, &str)] = &[
    (
        "claude-code.toml",
        include_str!("../profiles/claude-code.toml"),
    ),
    ("codex.toml", include_str!("../profiles/codex.toml")),
    ("cursor.toml", include_str!("../profiles/cursor.toml")),
    ("aider.toml", include_str!("../profiles/aider.toml")),
];

/// Why a profile file was refused. The file name is always included.
#[derive(Debug)]
pub enum ProfileError {
    /// A directory or file could not be read.
    Read {
        /// Path that failed.
        path: PathBuf,
        /// Underlying I/O error.
        source: io::Error,
    },
    /// TOML syntax is invalid, or the document is not a profile.
    Parse {
        /// File name, not a full path.
        file: String,
        /// Parser message.
        detail: String,
    },
    /// The document parsed but a field is empty or a regex does not compile.
    Invalid {
        /// File name, not a full path.
        file: String,
        /// What was wrong. Regex text is the profile's own pattern, not argv.
        detail: String,
    },
    /// The same id appeared twice in one layer (two built-ins, or two user files).
    Duplicate {
        /// File name of the second definition.
        file: String,
        /// Profile id.
        id: String,
    },
}

impl std::fmt::Display for ProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read { path, source } => {
                write!(f, "failed to read `{}`: {source}", path.display())
            }
            Self::Parse { file, detail } => {
                write!(f, "failed to parse profile `{file}`: {detail}")
            }
            Self::Invalid { file, detail } => {
                write!(f, "invalid profile `{file}`: {detail}")
            }
            Self::Duplicate { file, id } => {
                write!(f, "duplicate profile id `{id}` in `{file}`")
            }
        }
    }
}

impl std::error::Error for ProfileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// `match` table. Absent groups are empty and do not constrain.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct MatchRules {
    /// Executable file names. `node` and `python` do not belong here.
    pub exe_names: Vec<String>,
    /// Regexes tested against each argv element separately, not a joined string.
    pub argv_regex: Vec<String>,
    /// Immediate parent executable name. Nearest ancestor only.
    pub parent_exe: Option<String>,
    /// Env var names that must exist. Values are never read.
    pub env_keys: Vec<String>,
}

/// One child-process role label. Not used by [`ProfileSet::identify`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildRole {
    /// Short role name, for example `mcp` or `sandbox`.
    pub role: String,
    /// Regex tested against each argv element of the child.
    pub regex: String,
}

/// `children` table.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct ChildrenRules {
    /// First matching entry wins inside [`ProfileSet::child_role`].
    pub role_regex: Vec<ChildRole>,
}

/// One agent, as declared in TOML.
///
/// A file is either one profile at the root, or `[[agent]]` tables (the shape
/// in process-tracking §7). Unknown keys are errors.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentProfile {
    /// Stable id. User profiles with the same id replace the built-in.
    pub id: String,
    /// Human-readable name. Defaults to `id` when omitted or blank.
    #[serde(default)]
    pub display: String,
    /// Process-shape gates. TOML key is `match`.
    #[serde(rename = "match", default)]
    pub match_rules: MatchRules,
    /// Child role labels. They do not decide whether this process is the agent.
    #[serde(default)]
    pub children: ChildrenRules,
    /// E3 channel names this agent can supply. Empty means none.
    #[serde(default)]
    pub self_report: Vec<String>,
}

#[derive(Debug)]
struct Compiled {
    argv_regex: Vec<regex::Regex>,
    role_regex: Vec<regex::Regex>,
}

/// Built-ins, with user profiles of the same id substituted.
#[derive(Debug)]
pub struct ProfileSet {
    profiles: Vec<AgentProfile>,
    compiled: Vec<Compiled>,
    /// Ids where a user file replaced a built-in. Sorted.
    overridden: Vec<String>,
}

impl ProfileSet {
    /// Profile by id, after user override.
    pub fn get(&self, id: &str) -> Option<&AgentProfile> {
        self.profiles.iter().find(|profile| profile.id == id)
    }

    /// Declaration order: built-ins first, then user-only ids in file-name order.
    pub fn profiles(&self) -> &[AgentProfile] {
        &self.profiles
    }

    /// Built-in ids replaced by a user file. Sorted by id.
    pub fn overridden_ids(&self) -> &[String] {
        &self.overridden
    }

    /// Best match, or `None`. See [`crate::identify`] for the gates.
    ///
    /// When several profiles match, the one with more hits wins. A tie keeps
    /// the earlier profile in [`ProfileSet::profiles`] order.
    pub fn identify(&self, proc: &ProcInfo, ancestors: &[ProcInfo]) -> Option<AgentMatch> {
        let mut best: Option<AgentMatch> = None;
        for (profile, compiled) in self.profiles.iter().zip(self.compiled.iter()) {
            let Some(hits) = try_match(
                &profile.match_rules.exe_names,
                &compiled.argv_regex,
                profile.match_rules.parent_exe.as_deref(),
                &profile.match_rules.env_keys,
                proc,
                ancestors,
            ) else {
                continue;
            };
            let better = match &best {
                None => true,
                Some(current) => hits.len() > current.hits.len(),
            };
            if better {
                best = Some(AgentMatch {
                    profile_id: profile.id.clone(),
                    hits,
                    evidence: Inference::I,
                });
            }
        }
        best
    }

    /// Role label for a child process under `profile_id`, if a role regex hits.
    ///
    /// This does not identify the agent. It only labels a child the caller
    /// already attributes to that profile.
    pub fn child_role<'a>(&'a self, profile_id: &str, proc: &ProcInfo) -> Option<&'a str> {
        let index = self
            .profiles
            .iter()
            .position(|profile| profile.id == profile_id)?;
        let profile = self.profiles.get(index)?;
        let compiled = self.compiled.get(index)?;
        for (role, pattern) in profile
            .children
            .role_regex
            .iter()
            .zip(compiled.role_regex.iter())
        {
            if proc.argv.iter().any(|arg| pattern.is_match(arg)) {
                return Some(role.role.as_str());
            }
        }
        None
    }
}

/// Load embedded profiles, then `*.toml` files directly inside `user_dir`.
///
/// `user_dir` is the `agents.d` directory itself, not its parent. `None` loads
/// built-ins only. The same id in a user file replaces the built-in and is
/// recorded on [`ProfileSet::overridden_ids`]. A second user file with that
/// id is an error. The same id in two built-in files is also an error. A file
/// that fails to parse is an error named with that file; nothing is skipped.
pub fn load_profiles(user_dir: Option<&Path>) -> Result<ProfileSet, ProfileError> {
    let mut loaded = Vec::new();
    for (file, text) in BUILTINS {
        loaded.extend(parse_file(file, text)?);
    }
    for (file, profile) in &loaded {
        let copies = loaded
            .iter()
            .filter(|(_, other)| other.id == profile.id)
            .count();
        if copies > 1 {
            return Err(ProfileError::Duplicate {
                file: file.clone(),
                id: profile.id.clone(),
            });
        }
    }
    let mut overridden = Vec::new();
    let mut user_ids: Vec<String> = Vec::new();
    if let Some(dir) = user_dir {
        for path in toml_files(dir)? {
            let file = file_label(&path)?;
            let text = fs::read_to_string(&path).map_err(|source| ProfileError::Read {
                path: path.clone(),
                source,
            })?;
            for (label, profile) in parse_file(&file, &text)? {
                apply_user(&mut loaded, &mut overridden, &mut user_ids, label, profile)?;
            }
        }
    }
    overridden.sort();
    compile_set(loaded, overridden)
}

pub(crate) fn builtins() -> Option<&'static ProfileSet> {
    static SLOT: OnceLock<Result<ProfileSet, ()>> = OnceLock::new();
    SLOT.get_or_init(|| load_profiles(None).map_err(|_| ()))
        .as_ref()
        .ok()
}

fn apply_user(
    loaded: &mut Vec<(String, AgentProfile)>,
    overridden: &mut Vec<String>,
    user_ids: &mut Vec<String>,
    file: String,
    profile: AgentProfile,
) -> Result<(), ProfileError> {
    if user_ids.iter().any(|id| id == &profile.id) {
        return Err(ProfileError::Duplicate {
            file,
            id: profile.id,
        });
    }
    if let Some(slot) = loaded
        .iter_mut()
        .find(|(_, existing)| existing.id == profile.id)
    {
        overridden.push(profile.id.clone());
        *slot = (file, profile.clone());
    } else {
        loaded.push((file, profile.clone()));
    }
    user_ids.push(profile.id);
    Ok(())
}

fn compile_set(
    loaded: Vec<(String, AgentProfile)>,
    overridden: Vec<String>,
) -> Result<ProfileSet, ProfileError> {
    let mut profiles = Vec::with_capacity(loaded.len());
    let mut compiled = Vec::with_capacity(loaded.len());
    for (file, profile) in loaded {
        compiled.push(compile_profile(&file, &profile)?);
        profiles.push(profile);
    }
    Ok(ProfileSet {
        profiles,
        compiled,
        overridden,
    })
}

fn compile_profile(file: &str, profile: &AgentProfile) -> Result<Compiled, ProfileError> {
    let mut argv_regex = Vec::with_capacity(profile.match_rules.argv_regex.len());
    for pattern in &profile.match_rules.argv_regex {
        argv_regex.push(compile_regex(file, pattern)?);
    }
    let mut role_regex = Vec::with_capacity(profile.children.role_regex.len());
    for role in &profile.children.role_regex {
        role_regex.push(compile_regex(file, &role.regex)?);
    }
    Ok(Compiled {
        argv_regex,
        role_regex,
    })
}

fn compile_regex(file: &str, pattern: &str) -> Result<regex::Regex, ProfileError> {
    if pattern.is_empty() {
        return Err(invalid(file, "regex is empty"));
    }
    RegexBuilder::new(pattern)
        .size_limit(1 << 20)
        .dfa_size_limit(1 << 20)
        .build()
        .map_err(|err| invalid(file, format!("regex `{pattern}`: {err}")))
}

fn parse_file(file: &str, text: &str) -> Result<Vec<(String, AgentProfile)>, ProfileError> {
    let value: toml::Value = toml::from_str(text).map_err(|err| ProfileError::Parse {
        file: file.to_owned(),
        detail: err.to_string(),
    })?;
    let table = value
        .as_table()
        .ok_or_else(|| invalid(file, "profile must be a table"))?;
    let raws = if table.contains_key("agent") && !table.contains_key("id") {
        let list: AgentList =
            value
                .try_into()
                .map_err(|err: toml::de::Error| ProfileError::Parse {
                    file: file.to_owned(),
                    detail: err.to_string(),
                })?;
        if list.agent.is_empty() {
            return Err(invalid(file, "agent list is empty"));
        }
        list.agent
    } else {
        let one: AgentProfile =
            value
                .try_into()
                .map_err(|err: toml::de::Error| ProfileError::Parse {
                    file: file.to_owned(),
                    detail: err.to_string(),
                })?;
        vec![one]
    };

    let mut out = Vec::with_capacity(raws.len());
    let mut seen: Vec<String> = Vec::new();
    for mut profile in raws {
        normalize(file, &mut profile)?;
        if seen.iter().any(|id| id == &profile.id) {
            return Err(ProfileError::Duplicate {
                file: file.to_owned(),
                id: profile.id,
            });
        }
        seen.push(profile.id.clone());
        out.push((file.to_owned(), profile));
    }
    Ok(out)
}

fn normalize(file: &str, profile: &mut AgentProfile) -> Result<(), ProfileError> {
    if profile.id.is_empty() || profile.id.chars().any(char::is_whitespace) {
        return Err(invalid(file, "id must be a non-empty token"));
    }
    if profile.display.trim().is_empty() {
        profile.display = profile.id.clone();
    }
    if profile
        .match_rules
        .exe_names
        .iter()
        .any(|name| name.is_empty())
    {
        return Err(invalid(file, "exe_names contains an empty name"));
    }
    if profile
        .match_rules
        .env_keys
        .iter()
        .any(|key| key.is_empty())
    {
        return Err(invalid(file, "env_keys contains an empty name"));
    }
    if matches!(profile.match_rules.parent_exe.as_deref(), Some("")) {
        return Err(invalid(file, "parent_exe is empty"));
    }
    for role in &profile.children.role_regex {
        if role.role.is_empty() || role.role.chars().any(char::is_whitespace) {
            return Err(invalid(file, "child role must be a non-empty token"));
        }
    }
    if profile.self_report.iter().any(|channel| channel.is_empty()) {
        return Err(invalid(file, "self_report contains an empty channel"));
    }
    let identity =
        !profile.match_rules.exe_names.is_empty() || !profile.match_rules.argv_regex.is_empty();
    if !identity {
        return Err(invalid(
            file,
            "profile needs exe_names or argv_regex; otherwise it cannot match a process",
        ));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentList {
    agent: Vec<AgentProfile>,
}

fn toml_files(dir: &Path) -> Result<Vec<PathBuf>, ProfileError> {
    let entries = fs::read_dir(dir).map_err(|source| ProfileError::Read {
        path: dir.to_path_buf(),
        source,
    })?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|source| ProfileError::Read {
            path: dir.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let is_toml = path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("toml"));
        if is_toml {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}

fn file_label(path: &Path) -> Result<String, ProfileError> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .ok_or_else(|| invalid(&path.display().to_string(), "file name is not UTF-8"))
}

fn invalid(file: &str, detail: impl Into<String>) -> ProfileError {
    ProfileError::Invalid {
        file: file.to_owned(),
        detail: detail.into(),
    }
}
