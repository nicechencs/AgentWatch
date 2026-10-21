//! One intercept audit record (design §5.4).
//!
//! `before` and `after` keep a redacted summary cut at 256 Unicode scalars,
//! plus a SHA-256 of the original bytes mixed with a caller-supplied salt.
//! The original text is not a field of [`AuditRecord`].

use sha2::{Digest, Sha256};

use crate::config::RedactionConfig;
use crate::redact::Redactor;

use super::{Action, Decision, Layer, Subject};

/// How many Unicode scalars a summary may keep. The design says 256 字.
pub const AUDIT_SUMMARY_CHARS: usize = 256;

/// Where the record landed. The caller sets this after the write attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivered {
    /// The daemon accepted `POST /api/v1/agent/intercept`.
    Daemon,
    /// The daemon did not, and the session jsonl backup was written.
    LocalBackup,
    /// Neither write worked. The caller also records a gap.
    Dropped,
}

impl Delivered {
    /// Token stored in `intercept_events.delivered` and the jsonl backup.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Daemon => "daemon",
            Self::LocalBackup => "local_backup",
            Self::Dropped => "dropped",
        }
    }
}

/// One deny / rewrite / ask / downgrade. Not `Debug`: the summaries are still
/// derived from commands and URLs, even after redaction.
#[derive(Clone, PartialEq, Eq)]
pub struct AuditRecord {
    /// Public session id, or unknown.
    pub session: Option<String>,
    /// Agent id, or unknown.
    pub agent: Option<String>,
    /// `hook` / `mcp` / `proxy`.
    pub layer: String,
    /// Hook event name, or unknown.
    pub event: Option<String>,
    /// Winning rule, or unknown when `on_error` fired with no rule.
    pub rule_id: Option<String>,
    /// The rule's action (`deny`, `rewrite`, `ask`, or `on_error`'s action).
    pub action: String,
    /// What was actually done. Differs from [`Self::action`] on a downgrade.
    pub effective_action: String,
    /// Tool name, when the subject had one.
    pub tool: Option<String>,
    /// Host, when the subject had one.
    pub host: Option<String>,
    /// MCP method, when the subject had one.
    pub mcp_method: Option<String>,
    /// Redacted original, at most [`AUDIT_SUMMARY_CHARS`] scalars.
    pub before_summary: String,
    /// Hex SHA-256 of `salt || 0xff || original bytes`.
    pub before_hash: String,
    /// Redacted replacement, only when the effective action is a rewrite.
    pub after_summary: Option<String>,
    /// Hash of the replacement original, only for a rewrite.
    pub after_hash: Option<String>,
    /// Sentence shown to the agent or the user.
    pub reason: Option<String>,
    /// `E3` for a hook (self-report path), `S` for mcp-tap and the proxy.
    pub evidence: String,
    /// `intercept.<agent>/hook`, `intercept.mcp-tap`, or `intercept.proxy`.
    pub source: String,
    /// Filled by the caller after delivery. `None` until then.
    pub delivered: Option<Delivered>,
    /// `true` when the effective action is not the rule's action.
    pub downgraded: bool,
}

/// Build the record for `decision`. `salt` is the session salt; an empty salt
/// still hashes (the prefix is the separator byte alone), so two originals
/// do not collide just because no salt was configured.
///
/// `original` is the pre-decision text (command, URL, or the JSON the caller
/// is about to change). `rewritten` is the same text after a rewrite, or
/// `None`. Neither string is stored.
#[must_use]
pub fn audit_record(
    subject: &Subject,
    decision: &Decision,
    salt: &[u8],
    original: &str,
    rewritten: Option<&str>,
) -> AuditRecord {
    let before_summary = audit_summary(original);
    let before_hash = hash_original(salt, original.as_bytes());
    let (after_summary, after_hash) = if decision.effective == Action::Rewrite {
        let text = rewritten.unwrap_or("");
        (
            Some(audit_summary(text)),
            Some(hash_original(salt, text.as_bytes())),
        )
    } else {
        (None, None)
    };
    let agent = subject.agent.clone();
    AuditRecord {
        session: None,
        agent: agent.clone(),
        layer: subject.layer.as_str().to_owned(),
        event: subject.event.clone(),
        rule_id: decision.rule_id.clone(),
        action: decision.action.as_str().to_owned(),
        effective_action: decision.effective.as_str().to_owned(),
        tool: subject.tool.clone(),
        host: subject.host.clone(),
        mcp_method: subject.mcp_method.clone().or_else(|| {
            if subject.layer == Layer::Mcp {
                subject.method.clone()
            } else {
                None
            }
        }),
        before_summary,
        before_hash,
        after_summary,
        after_hash,
        reason: decision.reason.clone(),
        evidence: evidence_for(subject.layer).to_owned(),
        source: source_for(subject.layer, agent.as_deref()).to_owned(),
        delivered: None,
        downgraded: decision.downgraded,
    }
}

/// SHA-256 of `salt || 0xff || bytes`, hex-encoded. The `0xff` keeps a salt
/// that happens to look like a prefix of the text from colliding with another
/// pair. Not reversible from the hash alone.
#[must_use]
pub fn hash_original(salt: &[u8], bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update([0xff]);
    hasher.update(bytes);
    hex_encode(&hasher.finalize())
}

fn evidence_for(layer: Layer) -> &'static str {
    match layer {
        // The hook sees what the agent reported. That is E3, not an upgrade.
        Layer::Hook => "E3",
        // aw itself made the decision on bytes it forwarded.
        Layer::Mcp | Layer::Proxy => "S",
    }
}

fn source_for(layer: Layer, agent: Option<&str>) -> String {
    match layer {
        Layer::Hook => format!("intercept.{}/hook", agent.unwrap_or("unknown")),
        Layer::Mcp => "intercept.mcp-tap".to_owned(),
        Layer::Proxy => "intercept.proxy".to_owned(),
    }
}

/// What an audit summary stores: redacted, then cut at [`AUDIT_SUMMARY_CHARS`].
///
/// A caller that hashes one string and displays another (a response field's
/// value versus its name) runs the displayed text through this, so it gets the
/// same redaction and the same length cap as [`audit_record`].
#[must_use]
pub fn audit_summary(text: &str) -> String {
    let redactor = Redactor::new(&RedactionConfig::default());
    truncate_summary(&redactor.scrub_text(text))
}

fn truncate_summary(text: &str) -> String {
    let mut out = String::new();
    for (index, ch) in text.chars().enumerate() {
        if index >= AUDIT_SUMMARY_CHARS {
            break;
        }
        out.push(ch);
    }
    out
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn summary_drops_a_bearer_and_stops_at_256_scalars() {
        let subject = Subject {
            layer: Layer::Hook,
            agent: Some("claude-code".to_owned()),
            tool: Some("Bash".to_owned()),
            command: Some("curl".to_owned()),
            ..Subject::default()
        };
        let decision = Decision {
            rule_id: Some("n".to_owned()),
            action: Action::Deny,
            effective: Action::Deny,
            downgraded: false,
            reason: Some("no".to_owned()),
            fields: Vec::new(),
        };
        let original = format!(
            "Authorization: Bearer sk-abcdefghijklmnopqrstuvwxyz {}",
            "字".repeat(300)
        );
        let record = audit_record(&subject, &decision, b"salt", &original, None);
        assert!(!record.before_summary.contains("Bearer sk-"));
        assert!(!record.before_summary.contains("sk-abc"));
        assert!(record.before_summary.contains("redacted"));
        assert_eq!(record.before_summary.chars().count(), AUDIT_SUMMARY_CHARS);
        assert_eq!(record.before_hash.len(), 64);
        assert!(record.after_summary.is_none());
        assert_eq!(record.evidence, "E3");
        assert_eq!(record.source, "intercept.claude-code/hook");
        // The hash is of the original, not of the redacted summary.
        assert_ne!(
            record.before_hash,
            hash_original(b"salt", record.before_summary.as_bytes())
        );
    }
}
