//! Banned-phrase lint (evidence-model §7).
//!
//! Each pattern is a phrase copied from that table, compiled once with the
//! `regex` crate (linear time). English tokens use ASCII word boundaries so
//! `stole` does not fire inside `stolen` wait — the table lists the bare words,
//! and `\b` keeps `uploaded` from matching a longer unrelated token while still
//! matching `Uploaded` only when the table's lowercase form is present.
//!
//! [`lint`] does not guess which template a string came from. "内容与……匹配"
//! (and the English "chunks identical to" / "content matches") is reported as
//! [`RuleId::ContentMatchPhrase`]. A caller that rendered `evidence.content_match`
//! passes that id to [`lint_allowing`].

use std::sync::OnceLock;

use regex::Regex;

/// One row of evidence-model §7, plus the content-match phrase that section
/// allows only inside `evidence.content_match`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleId {
    /// "X 上传了文件 Y" / "uploaded file".
    UploadedFile,
    /// "泄露" "窃取" "外泄" / "exfiltrated" "leaked" "stole".
    Intent,
    /// "访问了 evil.com" asserted from an IP lookup alone.
    BareEvilDomain,
    /// "Agent 读取了 X" when a child process did the read.
    AgentRead,
    /// "没有上传任何文件" "安全" / "no data leaked".
    UnprovableNegative,
    /// "读取了 0 字节" standing in for an unavailable count.
    ZeroBytes,
    /// "所有流量" / "all traffic".
    AllTraffic,
    /// "A 让 B 窃取了 …" / "A instructed B to steal …".
    InstructedSteal,
    /// "A 通过 B 上传了 …" / "A uploaded … via B".
    UploadedVia,
    /// "内容与……匹配". Legal only in text from `evidence.content_match`.
    ContentMatchPhrase,
}

/// One hit. `offset` is a byte index into the scanned text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// Which row matched.
    pub rule: RuleId,
    /// Byte offset of the match.
    pub offset: usize,
    /// Rewrite named by evidence-model §7: a template id, not a fresh sentence.
    pub suggestion: &'static str,
}

/// Scan `text` with no rule allow-listed.
pub fn lint(text: &str) -> Vec<Violation> {
    lint_allowing(text, &[])
}

/// Scan `text`, skipping rules named in `allow`.
///
/// The caller declares the whitelist. This function never infers it from the
/// text. Pass [`RuleId::ContentMatchPhrase`] only for a rendering of
/// `evidence.content_match`.
pub fn lint_allowing(text: &str, allow: &[RuleId]) -> Vec<Violation> {
    let mut hits = Vec::new();
    for pattern in patterns() {
        if allow.contains(&pattern.rule) {
            continue;
        }
        for found in pattern.regex.find_iter(text) {
            hits.push(Violation {
                rule: pattern.rule,
                offset: found.start(),
                suggestion: pattern.suggestion,
            });
        }
    }
    hits.sort_by(|left, right| {
        left.offset
            .cmp(&right.offset)
            .then(rule_order(left.rule).cmp(&rule_order(right.rule)))
    });
    hits
}

fn rule_order(rule: RuleId) -> u8 {
    match rule {
        RuleId::UploadedFile => 0,
        RuleId::Intent => 1,
        RuleId::BareEvilDomain => 2,
        RuleId::AgentRead => 3,
        RuleId::UnprovableNegative => 4,
        RuleId::ZeroBytes => 5,
        RuleId::AllTraffic => 6,
        RuleId::InstructedSteal => 7,
        RuleId::UploadedVia => 8,
        RuleId::ContentMatchPhrase => 9,
    }
}

struct Pattern {
    rule: RuleId,
    regex: Regex,
    suggestion: &'static str,
}

fn patterns() -> &'static [Pattern] {
    static PATTERNS: OnceLock<Vec<Pattern>> = OnceLock::new();
    PATTERNS.get_or_init(compile_patterns)
}

fn compile_patterns() -> Vec<Pattern> {
    // Phrases are the banned column of evidence-model §7, one pattern per row.
    // A pattern that fails to compile is a bug in this list: startup panics
    // with the rule id only, never with scanned text.
    const SPECS: &[(RuleId, &str, &str)] = &[
        (
            RuleId::UploadedFile,
            r"上传了文件|\buploaded file\b",
            "infer.temporal",
        ),
        (
            RuleId::Intent,
            r"泄露|窃取|外泄|\bexfiltrated\b|\bleaked\b|\bstole\b",
            "fact.net_send",
        ),
        (
            RuleId::BareEvilDomain,
            r"访问了\s*evil\.com",
            "fact.net_send",
        ),
        (
            RuleId::AgentRead,
            r"Agent 读取了|\bAgent read\b",
            "fact.file_read",
        ),
        (
            RuleId::UnprovableNegative,
            r"没有上传任何文件|\bno data leaked\b|(?<!不)安全",
            "gap.generic",
        ),
        (
            RuleId::ZeroBytes,
            r"读取了\s*0\s*字节|\bread 0 bytes\b",
            "fact.file_opened_read",
        ),
        (
            RuleId::AllTraffic,
            r"所有流量|\ball traffic\b",
            "fact.net_send",
        ),
        (
            RuleId::InstructedSteal,
            r"让.{1,40}?窃取了|\binstructed \S+ to steal\b",
            "delegation.chain",
        ),
        (
            RuleId::UploadedVia,
            r"通过.{1,40}?上传了|\buploaded \S+ via\b",
            "ipc.channel",
        ),
        (
            RuleId::ContentMatchPhrase,
            r"内容与.{0,80}?匹配|\bchunks identical to\b|\bcontent matches\b",
            "evidence.content_match",
        ),
    ];
    SPECS
        .iter()
        .map(|(rule, source, suggestion)| Pattern {
            rule: *rule,
            regex: compile_or_panic(*rule, source),
            suggestion,
        })
        .collect()
}

fn compile_or_panic(rule: RuleId, source: &str) -> Regex {
    match Regex::new(source) {
        Ok(regex) => regex,
        Err(err) => panic!("wording lint rule {rule:?} failed to compile: {err}"),
    }
}
