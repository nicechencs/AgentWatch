//! TOML policy loader. Pure: a string in, a [`PolicyState`] out.
//!
//! A missing file is the caller's job (`Off`). This module treats an empty
//! document, `enabled` absent, and `enabled = false` as off as well, so a
//! file that exists only to be explicit does not start intercepting.

use super::match_field::{MatchError, Matcher};
use super::{Action, FieldMatch, FieldRewrite, Layer, OnError, Policy, Rule};

/// What a file means. [`PolicyState::Off`] is not an error.
#[derive(Debug, Clone)]
pub enum PolicyState {
    /// No intercept. Callers keep the previous byte-for-byte behaviour.
    Off,
    /// Rules are in force.
    On(Policy),
}

/// Why a file that claimed to be a policy could not be loaded.
///
/// Display does not include file bytes. A broken rule can quote a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    /// `toml` rejected the document.
    NotToml,
    /// `version` is missing or not `1`.
    Version,
    /// `enabled` was not a bool.
    Enabled,
    /// `on_error` was not `deny` or `allow`.
    OnError,
    /// `[[rule]]` was not an array of tables.
    Rules,
    /// One rule failed. `index` is its position in the file, from 0.
    Rule { index: usize, detail: RuleError },
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotToml => f.write_str("policy is not TOML"),
            Self::Version => f.write_str("policy version must be 1"),
            Self::Enabled => f.write_str("policy enabled must be a bool"),
            Self::OnError => f.write_str("policy on_error must be deny or allow"),
            Self::Rules => f.write_str("policy rule must be an array of tables"),
            Self::Rule { index, detail } => write!(f, "policy rule {index}: {detail}"),
        }
    }
}

/// Why one `[[rule]]` was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleError {
    /// Not a table.
    NotTable,
    /// `id` missing or empty.
    Id,
    /// `layer` was not a list of `hook` / `mcp` / `proxy`.
    Layer,
    /// `agent` or `tool` was not a list of strings.
    List,
    /// `action` missing or not one of the four.
    Action,
    /// `reason` was not a string.
    Reason,
    /// `match` was not a table, or one field failed.
    Match(String),
    /// `rewrite` was not a table, or one field failed.
    Rewrite(String),
    /// `action = "rewrite"` with no `rewrite` fields.
    RewriteRequired,
}

impl std::fmt::Display for RuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotTable => f.write_str("not a table"),
            Self::Id => f.write_str("id is required"),
            Self::Layer => f.write_str("layer must be hook, mcp, or proxy"),
            Self::List => f.write_str("agent and tool must be lists of strings"),
            Self::Action => f.write_str("action must be allow, deny, rewrite, or ask"),
            Self::Reason => f.write_str("reason must be a string"),
            Self::Match(detail) | Self::Rewrite(detail) => f.write_str(detail),
            Self::RewriteRequired => f.write_str("rewrite action needs at least one rewrite field"),
        }
    }
}

/// Parse `text`.
///
/// # Errors
///
/// [`PolicyError`] when the document is TOML but not a policy, or when a rule
/// cannot be compiled. An absent `enabled` (or `enabled = false`) is
/// [`PolicyState::Off`], not an error, even if later keys are junk: those
/// keys are not consulted.
pub fn load_str(text: &str) -> Result<PolicyState, PolicyError> {
    let value: toml::Value = toml::from_str(text).map_err(|_| PolicyError::NotToml)?;
    let Some(root) = value.as_table() else {
        return Err(PolicyError::NotToml);
    };
    if let Some(version) = root.get("version") {
        if version.as_integer() != Some(1) {
            return Err(PolicyError::Version);
        }
    }
    let enabled = match root.get("enabled") {
        None => false,
        Some(toml::Value::Boolean(flag)) => *flag,
        Some(_) => return Err(PolicyError::Enabled),
    };
    if !enabled {
        return Ok(PolicyState::Off);
    }
    let on_error = match root.get("on_error") {
        None => OnError::Deny,
        Some(value) => {
            let text = value.as_str().ok_or(PolicyError::OnError)?;
            OnError::parse(text).ok_or(PolicyError::OnError)?
        }
    };
    let rules = match root.get("rule") {
        None => Vec::new(),
        Some(toml::Value::Array(items)) => items
            .iter()
            .enumerate()
            .map(|(index, item)| {
                parse_rule(item).map_err(|detail| PolicyError::Rule { index, detail })
            })
            .collect::<Result<Vec<_>, _>>()?,
        Some(_) => return Err(PolicyError::Rules),
    };
    Ok(PolicyState::On(Policy { on_error, rules }))
}

fn parse_rule(value: &toml::Value) -> Result<Rule, RuleError> {
    let table = value.as_table().ok_or(RuleError::NotTable)?;
    let id = table
        .get("id")
        .and_then(toml::Value::as_str)
        .filter(|text| !text.is_empty())
        .ok_or(RuleError::Id)?
        .to_owned();
    let layers = optional_layers(table.get("layer"))?;
    let agents = optional_strings(table.get("agent"))?;
    let tools = optional_strings(table.get("tool"))?;
    let action = table
        .get("action")
        .and_then(toml::Value::as_str)
        .and_then(Action::parse)
        .ok_or(RuleError::Action)?;
    let reason = match table.get("reason") {
        None => None,
        Some(value) => Some(
            value
                .as_str()
                .filter(|text| !text.is_empty())
                .ok_or(RuleError::Reason)?
                .to_owned(),
        ),
    };
    let matches = match table.get("match") {
        None => Vec::new(),
        Some(value) => parse_matches(value)?,
    };
    let rewrites = match table.get("rewrite") {
        None => Vec::new(),
        Some(value) => parse_rewrites(value)?,
    };
    if action == Action::Rewrite && rewrites.is_empty() {
        return Err(RuleError::RewriteRequired);
    }
    Ok(Rule {
        id,
        layers,
        agents,
        tools,
        matches,
        action,
        reason,
        rewrites,
    })
}

fn optional_layers(value: Option<&toml::Value>) -> Result<Vec<Layer>, RuleError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let items = value.as_array().ok_or(RuleError::Layer)?;
    items
        .iter()
        .map(|item| item.as_str().and_then(Layer::parse).ok_or(RuleError::Layer))
        .collect()
}

fn optional_strings(value: Option<&toml::Value>) -> Result<Vec<String>, RuleError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let items = value.as_array().ok_or(RuleError::List)?;
    items
        .iter()
        .map(|item| {
            item.as_str()
                .filter(|text| !text.is_empty())
                .map(str::to_owned)
                .ok_or(RuleError::List)
        })
        .collect()
}

fn parse_matches(value: &toml::Value) -> Result<Vec<FieldMatch>, RuleError> {
    let table = value
        .as_table()
        .ok_or(RuleError::Match("match is not a table".into()))?;
    let mut flat = Vec::new();
    flatten_match("", table, &mut flat).map_err(RuleError::Match)?;
    let mut out = Vec::new();
    for (key, raw) in flat {
        if !known_match_field(&key) {
            return Err(RuleError::Match(format!("unknown match field `{key}`")));
        }
        let matcher =
            Matcher::compile(&raw).map_err(|err| RuleError::Match(field_error(&key, err)))?;
        out.push(FieldMatch {
            field: key,
            matcher,
        });
    }
    Ok(out)
}

/// `match.arg.command` is a nested table in TOML (`arg = { command = ... }`),
/// not a dotted key the parser keeps. Flatten one level of that nesting.
/// A matcher table (it has `exact` / `prefix` / `glob` / `regex`) stops the walk.
fn flatten_match(
    prefix: &str,
    table: &toml::Table,
    out: &mut Vec<(String, toml::Value)>,
) -> Result<(), String> {
    if is_matcher_table(table) {
        if prefix.is_empty() {
            return Err("match entry has no field name".to_owned());
        }
        out.push((prefix.to_owned(), toml::Value::Table(table.clone())));
        return Ok(());
    }
    for (key, raw) in table {
        let name = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{prefix}.{key}")
        };
        if let Some(nested) = raw.as_table() {
            if !is_matcher_table(nested) {
                flatten_match(&name, nested, out)?;
                continue;
            }
        }
        out.push((name, raw.clone()));
    }
    Ok(())
}

fn is_matcher_table(table: &toml::Table) -> bool {
    table.keys().any(|key| {
        matches!(
            key.as_str(),
            "exact" | "prefix" | "glob" | "regex" | "replace"
        )
    })
}

fn known_match_field(name: &str) -> bool {
    matches!(
        name,
        "command"
            | "path"
            | "host"
            | "url"
            | "method"
            | "mcp_method"
            | "mcp_tool"
            | "tool"
            | "direction"
    ) || name.starts_with("arg.") && name.len() > "arg.".len() && !name[4..].contains('.')
}

fn field_error(field: &str, err: MatchError) -> String {
    format!("match.{field}: {err}")
}

fn parse_rewrites(value: &toml::Value) -> Result<Vec<FieldRewrite>, RuleError> {
    let table = value
        .as_table()
        .ok_or(RuleError::Rewrite("rewrite is not a table".into()))?;
    let mut flat = Vec::new();
    flatten_match("", table, &mut flat).map_err(RuleError::Rewrite)?;
    let mut out = Vec::new();
    for (key, raw) in flat {
        if !known_match_field(&key) {
            return Err(RuleError::Rewrite(format!("unknown rewrite field `{key}`")));
        }
        // `direction` selects which way a frame is moving. It is not a field
        // of the frame, so a rewrite of it can never be written back.
        if key == "direction" {
            return Err(RuleError::Rewrite(
                "rewrite.direction is not a frame field".to_owned(),
            ));
        }
        let pair = raw
            .as_table()
            .and_then(|table| table.get("replace"))
            .and_then(toml::Value::as_array)
            .ok_or(RuleError::Rewrite(format!(
                "rewrite.{key} needs replace = [from, to]"
            )))?;
        if pair.len() != 2 {
            return Err(RuleError::Rewrite(format!(
                "rewrite.{key} replace needs exactly two strings"
            )));
        }
        let from = pair[0].as_str().ok_or(RuleError::Rewrite(format!(
            "rewrite.{key} replace[0] is not a string"
        )))?;
        let to = pair[1].as_str().ok_or(RuleError::Rewrite(format!(
            "rewrite.{key} replace[1] is not a string"
        )))?;
        if from.is_empty() {
            return Err(RuleError::Rewrite(format!(
                "rewrite.{key} replace-from is empty"
            )));
        }
        out.push(FieldRewrite {
            field: key.clone(),
            from: from.to_owned(),
            to: to.to_owned(),
        });
    }
    Ok(out)
}

/// A policy document, as loaded. Kept so callers can name the type.
pub type PolicyFile = PolicyState;
