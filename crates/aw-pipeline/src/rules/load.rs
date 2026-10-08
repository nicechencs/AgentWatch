//! Where rules come from.
//!
//! Built-in rules are compiled in from `crates/aw-pipeline/rules/*.toml`. A user
//! directory, when one is given, is read at startup and any file whose rule id
//! matches a built-in rule replaces it. The replacement is recorded in
//! [`RuleSet::overrides`] so `aw doctor` can list it. A file that fails to parse
//! rejects the whole load; a bad user rule is never silently skipped.

use std::path::{Path, PathBuf};

use super::ast::Rule;
use super::error::RuleError;
use super::parse::parse_rule;

/// One built-in rule file, in the order they are listed.
struct Builtin {
    name: &'static str,
    source: &'static str,
}

/// The eight P3 rules. Order is the order they run in.
const BUILTIN: &[Builtin] = &[
    Builtin {
        name: "sensitive_access.toml",
        source: include_str!("../../rules/sensitive_access.toml"),
    },
    Builtin {
        name: "sensitive_read_then_send.toml",
        source: include_str!("../../rules/sensitive_read_then_send.toml"),
    },
    Builtin {
        name: "content_match.toml",
        source: include_str!("../../rules/content_match.toml"),
    },
    Builtin {
        name: "direct_bypass_proxy.toml",
        source: include_str!("../../rules/direct_bypass_proxy.toml"),
    },
    Builtin {
        name: "attribution_break.toml",
        source: include_str!("../../rules/attribution_break.toml"),
    },
    Builtin {
        name: "self_report_mismatch.toml",
        source: include_str!("../../rules/self_report_mismatch.toml"),
    },
    Builtin {
        name: "mass_delete.toml",
        source: include_str!("../../rules/mass_delete.toml"),
    },
    Builtin {
        name: "new_executable_written_then_run.toml",
        source: include_str!("../../rules/new_executable_written_then_run.toml"),
    },
];

/// A built-in rule a user file replaced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Override {
    /// The rule id both files used.
    pub rule_id: String,
    /// The user file that won.
    pub file: PathBuf,
    /// Version of the built-in rule that was replaced.
    pub builtin_version: u32,
    /// Version of the user rule that replaced it.
    pub user_version: u32,
}

/// The rules the engine runs, after user overrides have been applied.
#[derive(Debug, Clone, PartialEq)]
pub struct RuleSet {
    rules: Vec<Rule>,
    overrides: Vec<Override>,
}

impl RuleSet {
    /// The compiled rules, in run order.
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Built-in rules a user file replaced, in the order they were replaced.
    pub fn overrides(&self) -> &[Override] {
        &self.overrides
    }

    /// One rule by id.
    pub fn get(&self, id: &str) -> Option<&Rule> {
        self.rules.iter().find(|rule| rule.id == id)
    }
}

/// The compiled-in rules, with nothing over them.
pub fn load_builtin() -> Result<RuleSet, RuleError> {
    let mut rules = Vec::with_capacity(BUILTIN.len());
    for builtin in BUILTIN {
        rules
            .push(parse_rule(builtin.source, None).map_err(|err| name_builtin(err, builtin.name))?);
    }
    Ok(RuleSet {
        rules,
        overrides: Vec::new(),
    })
}

/// Built-in rules, then every `*.toml` in `dir`.
///
/// A file whose id matches a built-in rule replaces it and is recorded in
/// [`RuleSet::overrides`]. A file with a new id is appended. `None` loads the
/// built-in rules only. A directory that does not exist is an error, not an
/// empty overlay: a mistyped path should not look like "no user rules".
pub fn load_with_user(dir: Option<&Path>) -> Result<RuleSet, RuleError> {
    let mut set = load_builtin()?;
    let Some(dir) = dir else {
        return Ok(set);
    };
    let entries = std::fs::read_dir(dir).map_err(|err| RuleError::Io {
        path: dir.to_path_buf(),
        detail: err.to_string(),
    })?;
    let mut files: Vec<PathBuf> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|err| RuleError::Io {
            path: dir.to_path_buf(),
            detail: err.to_string(),
        })?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("toml") {
            files.push(path);
        }
    }
    files.sort();
    for path in files {
        apply_user_file(&mut set, &path)?;
    }
    Ok(set)
}

fn apply_user_file(set: &mut RuleSet, path: &Path) -> Result<(), RuleError> {
    let source = std::fs::read_to_string(path).map_err(|err| RuleError::Io {
        path: path.to_path_buf(),
        detail: err.to_string(),
    })?;
    let mut rule = parse_rule(&source, Some(path))?;
    if let Some(existing) = set.rules.iter_mut().find(|have| have.id == rule.id) {
        let record = Override {
            rule_id: rule.id.clone(),
            file: path.to_path_buf(),
            builtin_version: existing.version,
            user_version: rule.version,
        };
        rule.user_override = true;
        *existing = rule;
        set.overrides.push(record);
    } else {
        set.rules.push(rule);
    }
    Ok(())
}

fn name_builtin(err: RuleError, name: &str) -> RuleError {
    let file = Some(PathBuf::from(name));
    match err {
        RuleError::Syntax { line, detail, .. } => RuleError::Syntax { file, line, detail },
        RuleError::Invalid {
            line,
            rule_id,
            detail,
            ..
        } => RuleError::Invalid {
            file,
            line,
            rule_id,
            detail,
        },
        RuleError::Where {
            line,
            rule_id,
            step,
            detail,
            ..
        } => RuleError::Where {
            file,
            line,
            rule_id,
            step,
            detail,
        },
        other => other,
    }
}
