//! Decision. Every matching rule is considered; the strictest action wins.
//!
//! A rewrite is applied, then the whole rule list is checked again against
//! the rewritten subject. A deny on that second pass replaces the rewrite.
//! The second pass does not itself rewrite: one replacement, then a check.

use super::{Action, Layer, Policy, Rule, Subject};

/// Why [`decide`] could not finish. Today this is only a rewrite that names a
/// field the subject does not carry, which is a rule bug rather than a match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecideError {
    /// `rewrite.<field>` but the subject has no such field.
    MissingRewriteField { rule_id: String, field: String },
    /// The `from` text was not in the field, so the replacement would be a no-op
    /// that still claimed a rewrite. Callers treat this as `on_error`.
    RewriteMissed { rule_id: String, field: String },
}

impl std::fmt::Display for DecideError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingRewriteField { rule_id, field } => {
                write!(
                    f,
                    "rule {rule_id} rewrites {field}, which this call does not have"
                )
            }
            Self::RewriteMissed { rule_id, field } => {
                write!(f, "rule {rule_id} replace-from was not found in {field}")
            }
        }
    }
}

/// The outcome of one subject. `Allow` with no rule means nothing matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// Rule that supplied [`Self::action`]. `None` when nothing matched.
    pub rule_id: Option<String>,
    /// The rule's action, before a layer downgrade.
    pub action: Action,
    /// What the layer will actually do. Equal to [`Self::action`] unless a
    /// downgrade applied.
    pub effective: Action,
    /// `true` when [`Self::effective`] is not [`Self::action`].
    pub downgraded: bool,
    /// Why, when the rule or the downgrade has a sentence. Not a secret.
    pub reason: Option<String>,
    /// Field values after a rewrite. Empty unless [`Self::effective`] is
    /// [`Action::Rewrite`].
    pub fields: Vec<(String, String)>,
}

/// Decide `subject` against `policy`.
///
/// # Errors
///
/// [`DecideError`] when the winning rewrite cannot be applied. The caller
/// maps that onto `policy.on_error()` and writes an audit row or a gap.
pub fn decide(policy: &Policy, subject: &Subject) -> Result<Decision, DecideError> {
    let hits = matching(policy, subject);
    let Some(winner) = strictest(&hits) else {
        return Ok(allow_none());
    };
    if winner.action != Action::Rewrite {
        return Ok(finish(winner, subject.layer, None));
    }
    let rewritten = apply_rewrite(winner, subject)?;
    let after = subject_with(subject, &rewritten);
    let again = matching(policy, &after);
    if let Some(blocker) = again.iter().find(|rule| rule.action == Action::Deny) {
        return Ok(finish(blocker, subject.layer, None));
    }
    // A layer that cannot rewrite (the proxy, step 1) downgrades to deny and
    // must not hand the replacement back. The caller would otherwise apply it.
    let decision = finish(winner, subject.layer, Some(rewritten));
    if decision.effective != Action::Rewrite {
        return Ok(Decision {
            fields: Vec::new(),
            ..decision
        });
    }
    Ok(decision)
}

fn allow_none() -> Decision {
    Decision {
        rule_id: None,
        action: Action::Allow,
        effective: Action::Allow,
        downgraded: false,
        reason: None,
        fields: Vec::new(),
    }
}

fn matching<'a>(policy: &'a Policy, subject: &Subject) -> Vec<&'a Rule> {
    policy
        .rules()
        .iter()
        .filter(|rule| rule_matches(rule, subject))
        .collect()
}

fn rule_matches(rule: &Rule, subject: &Subject) -> bool {
    if !rule.layers.is_empty() && !rule.layers.contains(&subject.layer) {
        return false;
    }
    if !rule.agents.is_empty()
        && !subject
            .agent
            .as_deref()
            .is_some_and(|agent| rule.agents.iter().any(|want| want == agent))
    {
        return false;
    }
    if !rule.tools.is_empty()
        && !subject
            .tool
            .as_deref()
            .is_some_and(|tool| rule.tools.iter().any(|want| want == tool))
    {
        return false;
    }
    rule.matches.iter().all(|field| {
        subject
            .field(&field.field)
            .is_some_and(|text| field.matcher.is_match(text))
    })
}

fn strictest<'a>(hits: &[&'a Rule]) -> Option<&'a Rule> {
    hits.iter().copied().max_by_key(|rule| rule.action.rank())
}

/// Layer downgrades from the design, §5.2.
///
/// Codex has no `ask` (the caller passes `codex_ask`). MCP and the proxy
/// have no `ask` in step 1, and the proxy has no rewrite.
fn finish(rule: &Rule, layer: Layer, rewritten: Option<Vec<(String, String)>>) -> Decision {
    let (effective, downgraded, reason) = downgrade(rule, layer);
    Decision {
        rule_id: Some(rule.id.clone()),
        action: rule.action,
        effective,
        downgraded,
        reason,
        fields: rewritten.unwrap_or_default(),
    }
}

fn downgrade(rule: &Rule, layer: Layer) -> (Action, bool, Option<String>) {
    let reason = rule.reason.clone();
    match (layer, rule.action) {
        (Layer::Proxy, Action::Rewrite | Action::Ask) => (
            Action::Deny,
            true,
            Some(proxy_downgrade_reason(rule.action, reason.as_deref())),
        ),
        (Layer::Mcp, Action::Ask) => {
            (
                Action::Deny,
                true,
                Some(reason.unwrap_or_else(|| {
                    "这一步需要你确认；工具转接层不能询问，已改为拒绝".to_owned()
                })),
            )
        }
        _ => (rule.action, false, reason),
    }
}

fn proxy_downgrade_reason(action: Action, reason: Option<&str>) -> String {
    let base = match action {
        Action::Rewrite => "网络代理第一步不改写，已改为拒绝",
        Action::Ask => "网络代理第一步不能询问，已改为拒绝",
        _ => "已改为拒绝",
    };
    match reason {
        Some(text) if !text.is_empty() => format!("{base}：{text}"),
        _ => base.to_owned(),
    }
}

fn apply_rewrite(rule: &Rule, subject: &Subject) -> Result<Vec<(String, String)>, DecideError> {
    let mut fields = Vec::with_capacity(rule.rewrites.len());
    for rewrite in &rule.rewrites {
        let Some(current) = subject.field(&rewrite.field) else {
            return Err(DecideError::MissingRewriteField {
                rule_id: rule.id.clone(),
                field: rewrite.field.clone(),
            });
        };
        let Some(replaced) = replace_once(current, &rewrite.from, &rewrite.to) else {
            return Err(DecideError::RewriteMissed {
                rule_id: rule.id.clone(),
                field: rewrite.field.clone(),
            });
        };
        fields.push((rewrite.field.clone(), replaced));
    }
    Ok(fields)
}

fn replace_once(text: &str, from: &str, to: &str) -> Option<String> {
    let index = text.find(from)?;
    let mut out = String::with_capacity(text.len() - from.len() + to.len());
    out.push_str(&text[..index]);
    out.push_str(to);
    out.push_str(&text[index + from.len()..]);
    Some(out)
}

fn subject_with(subject: &Subject, fields: &[(String, String)]) -> Subject {
    let mut next = subject.clone();
    for (name, value) in fields {
        set_field(&mut next, name, value);
    }
    next
}

fn set_field(subject: &mut Subject, name: &str, value: &str) {
    if let Some(arg) = name.strip_prefix("arg.") {
        if let Some(slot) = subject.args.iter_mut().find(|(key, _)| key == arg) {
            slot.1 = value.to_owned();
        }
        return;
    }
    let slot = match name {
        "command" => &mut subject.command,
        "path" => &mut subject.path,
        "host" => &mut subject.host,
        "url" => &mut subject.url,
        "method" => &mut subject.method,
        "mcp_method" => &mut subject.mcp_method,
        "mcp_tool" => &mut subject.mcp_tool,
        "tool" => &mut subject.tool,
        _ => return,
    };
    *slot = Some(value.to_owned());
}

/// Codex `ask` becomes deny. The design is explicit: returning `ask` makes
/// Codex run the tool. The audit row records `downgraded`.
#[must_use]
pub fn downgrade_codex_ask(decision: &Decision) -> Decision {
    if decision.action != Action::Ask || decision.downgraded {
        return decision.clone();
    }
    let mut next = decision.clone();
    next.effective = Action::Deny;
    next.downgraded = true;
    let extra = "这一步需要你确认，请在 aw 里放行后重试";
    next.reason = Some(match decision.reason.as_deref() {
        Some(text) if !text.is_empty() => format!("{text}（{extra}）"),
        _ => extra.to_owned(),
    });
    next
}
