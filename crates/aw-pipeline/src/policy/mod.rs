//! Optional intercept policy (P5-SEC-01, ADR-0014).
//!
//! A missing file and `enabled = false` are both "off". Callers that see
//! [`PolicyState::Off`] must keep today's behaviour: no decision JSON, no
//! rewritten bytes. A present, enabled file is a pure function from a
//! [`Subject`] to a [`Decision`]. Nothing here reads the clock, the network,
//! or a platform API.
//!
//! Audit text is a redacted, truncated summary plus a salted SHA-256. The
//! original subject is not stored and is not put in an error string.

mod audit;
mod decide;
mod load;
mod match_field;

#[cfg(test)]
mod tests;

pub use audit::{audit_record, hash_original, AuditRecord, Delivered, AUDIT_SUMMARY_CHARS};
pub use decide::{decide, downgrade_codex_ask, DecideError, Decision};
pub use load::{load_str, PolicyError, PolicyFile, PolicyState};
pub use match_field::Matcher;

use std::fmt;

/// One compiled policy. Rules stay in file order.
#[derive(Debug, Clone)]
pub struct Policy {
    on_error: OnError,
    rules: Vec<Rule>,
}

impl Policy {
    /// What to do when a later step cannot decide (a bad regex at match time
    /// is already a load error; this covers a caller-supplied failure).
    #[must_use]
    pub fn on_error(&self) -> OnError {
        self.on_error
    }

    /// Compiled rules, file order.
    #[must_use]
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }
}

/// `on_error` in the policy file. Missing means [`OnError::Deny`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnError {
    /// A decision failure refuses the call.
    Deny,
    /// A decision failure leaves the call alone.
    Allow,
}

impl OnError {
    fn parse(text: &str) -> Option<Self> {
        match text {
            "deny" => Some(Self::Deny),
            "allow" => Some(Self::Allow),
            _ => None,
        }
    }

    /// The token written into an audit row.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deny => "deny",
            Self::Allow => "allow",
        }
    }
}

/// Where a rule applies. A rule with an empty list matches every layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    /// Agent hook (`aw hook`).
    Hook,
    /// MCP stdio tap (`aw mcp-tap`).
    Mcp,
    /// Session network proxy.
    Proxy,
}

impl Layer {
    fn parse(text: &str) -> Option<Self> {
        match text {
            "hook" => Some(Self::Hook),
            "mcp" => Some(Self::Mcp),
            "proxy" => Some(Self::Proxy),
            _ => None,
        }
    }

    /// Stable name for audit and tests.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hook => "hook",
            Self::Mcp => "mcp",
            Self::Proxy => "proxy",
        }
    }
}

/// What the rule asks for. Strictness, highest first: deny, ask, rewrite, allow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Leave the call alone. Not an approval.
    Allow,
    /// Refuse the call.
    Deny,
    /// Field-level replacement, then a second pass.
    Rewrite,
    /// Ask the user. Some layers cannot, and downgrade.
    Ask,
}

impl Action {
    fn parse(text: &str) -> Option<Self> {
        match text {
            "allow" => Some(Self::Allow),
            "deny" => Some(Self::Deny),
            "rewrite" => Some(Self::Rewrite),
            "ask" => Some(Self::Ask),
            _ => None,
        }
    }

    /// Token stored on the audit row.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Rewrite => "rewrite",
            Self::Ask => "ask",
        }
    }

    /// Higher means stricter. `deny > ask > rewrite > allow`.
    #[must_use]
    pub fn rank(self) -> u8 {
        match self {
            Self::Allow => 0,
            Self::Rewrite => 1,
            Self::Ask => 2,
            Self::Deny => 3,
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One compiled rule.
#[derive(Debug, Clone)]
pub struct Rule {
    /// `id`. Required, non-empty.
    pub id: String,
    /// Empty means every layer.
    pub layers: Vec<Layer>,
    /// Empty means every agent.
    pub agents: Vec<String>,
    /// Empty means every tool.
    pub tools: Vec<String>,
    /// Field matchers. Every one must match (AND). An empty list matches all.
    pub matches: Vec<FieldMatch>,
    /// What the rule asks for.
    pub action: Action,
    /// Shown to the agent or the user. Not a secret.
    pub reason: Option<String>,
    /// Field replacements. Only meaningful for [`Action::Rewrite`].
    pub rewrites: Vec<FieldRewrite>,
}

/// One `match.<field>` entry.
#[derive(Debug, Clone)]
pub struct FieldMatch {
    /// `command`, `path`, `host`, `url`, `method`, `mcp_method`, `mcp_tool`,
    /// or `arg.<name>`.
    pub field: String,
    /// How the text is compared.
    pub matcher: Matcher,
}

/// One `rewrite.<field>` entry. Only `replace = [from, to]` is accepted.
#[derive(Debug, Clone)]
pub struct FieldRewrite {
    /// Same names as [`FieldMatch::field`], plus the fields a hook rewrites.
    pub field: String,
    /// Substring that must occur. The first occurrence is replaced.
    pub from: String,
    /// Replacement text. Not interpreted.
    pub to: String,
}

/// What the caller is asking about. Missing fields stay `None`: they do not
/// match an `exact` of `""`.
///
/// Not `Debug`. `command`, `url`, and `args` can hold a secret. Tests print
/// the decision, not the subject.
#[derive(Clone)]
pub struct Subject {
    /// `hook`, `mcp`, or `proxy`.
    pub layer: Layer,
    /// Agent id, when the caller knows one.
    pub agent: Option<String>,
    /// Tool name (`Bash`, an MCP tool, …).
    pub tool: Option<String>,
    /// Hook event name (`PreToolUse`, `PostToolUse`, …).
    pub event: Option<String>,
    /// Command text, when the tool has one.
    pub command: Option<String>,
    /// Path text, when the tool has one.
    pub path: Option<String>,
    /// Host, for a proxy subject.
    pub host: Option<String>,
    /// URL, for a proxy subject. Already the request target, not a body.
    pub url: Option<String>,
    /// HTTP method, or the MCP method (`tools/call`).
    pub method: Option<String>,
    /// MCP method, when it differs from [`Self::method`].
    pub mcp_method: Option<String>,
    /// MCP tool name (`params.name`).
    pub mcp_tool: Option<String>,
    /// Named argument strings. Other JSON types are not matched.
    pub args: Vec<(String, String)>,
    /// Hook phase the caller is formatting. `post` selects tool-output rewrite.
    pub phase: Phase,
}

/// Which side of a tool call this decision formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Phase {
    /// Before the tool runs.
    #[default]
    Pre,
    /// After the tool ran. Only Claude Code can rewrite the model-facing output.
    Post,
}

impl Default for Subject {
    fn default() -> Self {
        Self {
            layer: Layer::Hook,
            agent: None,
            tool: None,
            event: None,
            command: None,
            path: None,
            host: None,
            url: None,
            method: None,
            mcp_method: None,
            mcp_tool: None,
            args: Vec::new(),
            phase: Phase::Pre,
        }
    }
}

impl Subject {
    /// Text of one match field. `None` when the subject does not carry it.
    #[must_use]
    pub fn field(&self, name: &str) -> Option<&str> {
        if let Some(arg) = name.strip_prefix("arg.") {
            return self
                .args
                .iter()
                .find(|(key, _)| key == arg)
                .map(|(_, value)| value.as_str());
        }
        match name {
            "command" => self.command.as_deref(),
            "path" => self.path.as_deref(),
            "host" => self.host.as_deref(),
            "url" => self.url.as_deref(),
            "method" => self.method.as_deref(),
            "mcp_method" => self.mcp_method.as_deref().or(self.method.as_deref()),
            "mcp_tool" => self.mcp_tool.as_deref().or(self.tool.as_deref()),
            "tool" => self.tool.as_deref(),
            // `c2s` on a request, `s2c` on a response. A rule uses this to
            // name one direction. The caller sets [`Self::event`] to that
            // token; a subject with no direction does not match.
            "direction" => self.event.as_deref(),
            _ => None,
        }
    }
}
