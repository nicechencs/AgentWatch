//! Sensitive-path rules (P2-PIPE-02).
//!
//! Built-in rules are compiled in from `rules/sensitive_paths.toml`. They label
//! a `file_access` row; they do not open the file and they do not emit a
//! finding. `sensitive_access` findings belong to the P3 correlation engine.
//!
//! `~` expands to the session user's home ([`Rules::home`]), never to the
//! account the daemon happens to run as. A rule whose glob still starts with
//! `~` after that (no home was configured) matches nothing.
//!
//! `agent-config` is the documented exception: when the accessor's agent id
//! owns the directory (`claude` reading `~/.claude`), the tag is
//! `sensitive.agent-config.info` instead of `sensitive.agent-config`.

use aw_core::RawEvent;

use crate::config::{SensitiveConfig, SensitiveRuleConfig};
use crate::output::FileAccessRec;

use super::glob::PathGlob;

/// Built-in rule table. Compiled into the binary; not read from disk at runtime.
const BUILTIN_TOML: &str = include_str!("../../rules/sensitive_paths.toml");

/// Tag prefix written on a hit. pipeline.md §3.3 names `sensitive:<rule_id>`;
/// the filter grammar (api-and-cli §4.3) spells the same idea `sensitive.<rule>`.
/// Both are recorded: the dotted form is what `tag:` queries, and the colon
/// form is what the pipeline text names.
const TAG_DOT: &str = "sensitive.";

/// Compiled rules for one session.
pub struct Rules {
    home: Option<String>,
    compiled: Vec<Compiled>,
}

struct Compiled {
    id: String,
    glob: PathGlob,
    exclude: Vec<PathGlob>,
}

/// What a hit means for the row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    /// Rule id, for `file_access.sensitive_rule`.
    pub rule_id: String,
    /// `true` for the agent-config self-read exception. The tag is then `info`.
    pub info_only: bool,
}

impl Rules {
    /// Built-in rules plus `cfg.extra`. A user rule whose id collides with a
    /// built-in id is dropped: built-in rules are read-only.
    pub fn load(cfg: &SensitiveConfig) -> Self {
        let mut rules = Vec::new();
        rules.extend(parse_builtin());
        let builtin_ids: Vec<String> = rules.iter().map(|rule| rule.id.clone()).collect();
        for extra in &cfg.extra {
            if builtin_ids.iter().any(|id| id == &extra.id) {
                continue;
            }
            rules.push(extra.clone());
        }
        let home = cfg.home.clone();
        let case_insensitive = cfg.case_insensitive;
        let compiled = rules
            .iter()
            .filter_map(|rule| compile_rule(rule, home.as_deref(), case_insensitive))
            .collect();
        Self { home, compiled }
    }

    /// Built-in rules only, with no home and case-sensitive compare.
    pub fn builtin() -> Self {
        Self::load(&SensitiveConfig::default())
    }

    /// First matching rule, in table order. `None` when nothing matches.
    ///
    /// `agent` is the accessor's profile id (`"claude"`, `"codex"`, …). It only
    /// changes the `agent-config` hit into an info tag; it never suppresses a
    /// different rule.
    pub fn hit(&self, path: &str, agent: Option<&str>) -> Option<Hit> {
        let expanded = expand_home(path, self.home.as_deref());
        for rule in &self.compiled {
            if !rule.glob.is_match(&expanded) {
                continue;
            }
            if rule.exclude.iter().any(|ex| ex.is_match(&expanded)) {
                continue;
            }
            let info_only = rule.id == "agent-config" && agent_owns_dir(agent, &expanded);
            return Some(Hit {
                rule_id: rule.id.clone(),
                info_only,
            });
        }
        None
    }

    /// Write `sensitive_rule` and the tag onto `row`, when the path matches.
    ///
    /// A row that already has a rule is left alone: the first label wins, and
    /// this function does not upgrade an info tag into a finding.
    pub fn label(&self, row: &mut FileAccessRec, agent: Option<&str>) {
        if row.sensitive_rule.is_some() {
            return;
        }
        let Some(hit) = self.hit(&row.path, agent) else {
            return;
        };
        let tag = if hit.info_only {
            format!("{TAG_DOT}{}.info", hit.rule_id)
        } else {
            format!("{TAG_DOT}{}", hit.rule_id)
        };
        row.sensitive_rule = Some(hit.rule_id);
        if !row.tags.iter().any(|have| have == &tag) {
            row.tags.push(tag);
        }
    }

    /// Agent id carried on a `ProcessStart`, when the event is one.
    ///
    /// Other events do not carry the profile. Callers that already know it
    /// pass it to [`Self::label`] directly.
    pub fn agent_of(event: &RawEvent) -> Option<&str> {
        match &event.kind {
            aw_core::EventKind::AgentToolCall(call) => Some(call.agent.as_str()),
            _ => None,
        }
    }
}

fn compile_rule(
    rule: &SensitiveRuleConfig,
    home: Option<&str>,
    case_insensitive: bool,
) -> Option<Compiled> {
    let insensitive = case_insensitive || rule.platform.eq_ignore_ascii_case("windows");
    let glob_src = expand_home(&rule.glob, home);
    if glob_src.contains('~') && home.is_none() {
        // No session home. A `~` glob must not match the daemon's home, and
        // it must not match a literal tilde either: that would label unrelated
        // paths. Skip the rule until a home is set.
        return None;
    }
    let glob = PathGlob::compile(&glob_src, insensitive);
    let exclude = rule
        .exclude
        .iter()
        .map(|pattern| PathGlob::compile(&expand_home(pattern, home), insensitive))
        .collect();
    Some(Compiled {
        id: rule.id.clone(),
        glob,
        exclude,
    })
}

/// Replace a leading `~` with `home`. A `~` that is not the first character,
/// or a missing home, is left as written.
pub fn expand_home(path: &str, home: Option<&str>) -> String {
    let Some(home) = home else {
        return path.to_owned();
    };
    let home = home.trim_end_matches(['/', '\\']);
    if path == "~" {
        return home.to_owned();
    }
    if let Some(rest) = path.strip_prefix("~/").or_else(|| path.strip_prefix("~\\")) {
        let sep = if path.as_bytes().get(1) == Some(&b'\\') {
            '\\'
        } else {
            '/'
        };
        let mut out = String::with_capacity(home.len() + 1 + rest.len());
        out.push_str(home);
        out.push(sep);
        out.push_str(rest);
        return out;
    }
    path.to_owned()
}

/// `claude` owns `~/.claude`, `codex` owns `~/.codex`, `cursor` owns `~/.cursor`,
/// `copilot` owns `github-copilot`. Compared on the last directory of the
/// matched prefix, case-insensitively, so `Claude` on Windows still matches.
fn agent_owns_dir(agent: Option<&str>, path: &str) -> bool {
    let Some(agent) = agent else {
        return false;
    };
    let agent = agent.to_ascii_lowercase();
    let lower = path.replace('\\', "/").to_ascii_lowercase();
    let needle = match agent.as_str() {
        "claude" => "/.claude/",
        "codex" => "/.codex/",
        "cursor" => "/.cursor/",
        "copilot" | "github-copilot" => "/github-copilot/",
        _ => return false,
    };
    lower.contains(needle) || lower.ends_with(needle.trim_end_matches('/'))
}

fn parse_builtin() -> Vec<SensitiveRuleConfig> {
    let value: toml::Value = match toml::from_str(BUILTIN_TOML) {
        Ok(value) => value,
        Err(_) => return Vec::new(),
    };
    let Some(rules) = value.get("rule").and_then(toml::Value::as_array) else {
        return Vec::new();
    };
    rules
        .iter()
        .filter_map(|rule| {
            let id = rule.get("id")?.as_str()?.to_owned();
            let platform = rule
                .get("platform")
                .and_then(toml::Value::as_str)
                .unwrap_or("any")
                .to_owned();
            let glob = rule.get("glob")?.as_str()?.to_owned();
            let exclude = rule
                .get("exclude")
                .and_then(toml::Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(toml::Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            Some(SensitiveRuleConfig {
                id,
                platform,
                glob,
                exclude,
            })
        })
        .collect()
}
