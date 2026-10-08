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
            if pattern
                .except
                .is_some_and(|except| except(text, found.start()))
            {
                continue;
            }
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
    /// Drop a match the regex cannot express on its own.
    ///
    /// The `regex` crate has no look-around, so "安全" but not "不安全" is
    /// decided here: `at` is the byte offset of the match.
    except: Option<fn(&str, usize) -> bool>,
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
            // "安全" but not "不安全": `(?<!不)` is look-behind, which the regex
            // crate rejects, so the prefix check lives in `not_after_bu`.
            r"没有上传任何文件|\bno data leaked\b|安全",
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
            // Kept off the spec tuple: a fn pointer there trips clippy's
            // type_complexity lint, and only one rule needs an exception.
            except: (*rule == RuleId::UnprovableNegative)
                .then_some(not_after_bu as fn(&str, usize) -> bool),
        })
        .collect()
}

/// True when the match at `at` is the "安全" alternative preceded by "不".
///
/// Other alternatives of the same rule ("没有上传任何文件", "no data leaked")
/// are never excluded: only a match whose preceding char is 不 qualifies.
fn not_after_bu(text: &str, at: usize) -> bool {
    let Some(before) = text.get(..at) else {
        return false;
    };
    before.ends_with('不')
}

fn compile_or_panic(rule: RuleId, source: &str) -> Regex {
    match Regex::new(source) {
        Ok(regex) => regex,
        Err(err) => panic!("wording lint rule {rule:?} failed to compile: {err}"),
    }
}

#[cfg(test)]
mod tests {
    use super::{lint, lint_allowing, RuleId};

    fn rules(text: &str) -> Vec<RuleId> {
        lint(text).into_iter().map(|hit| hit.rule).collect()
    }

    #[test]
    fn every_rule_compiles_and_matches_its_banned_phrase() {
        // Compiling is the point: the previous "安全" pattern used look-behind,
        // which the regex crate rejects, so the first call panicked.
        assert_eq!(
            rules("该进程上传了文件 report.pdf"),
            vec![RuleId::UploadedFile]
        );
        assert_eq!(
            rules("it uploaded file report.pdf"),
            vec![RuleId::UploadedFile]
        );
        assert_eq!(rules("疑似泄露"), vec![RuleId::Intent]);
        assert_eq!(rules("数据被窃取"), vec![RuleId::Intent]);
        assert_eq!(rules("发生外泄"), vec![RuleId::Intent]);
        assert_eq!(rules("data was exfiltrated"), vec![RuleId::Intent]);
        assert_eq!(rules("the key leaked"), vec![RuleId::Intent]);
        assert_eq!(rules("someone stole it"), vec![RuleId::Intent]);
        assert_eq!(rules("访问了 evil.com"), vec![RuleId::BareEvilDomain]);
        assert_eq!(rules("Agent 读取了配置"), vec![RuleId::AgentRead]);
        assert_eq!(rules("Agent read the config"), vec![RuleId::AgentRead]);
        assert_eq!(rules("没有上传任何文件"), vec![RuleId::UnprovableNegative]);
        // "leaked" is also an Intent phrase, so this sentence hits both rules.
        // Hits are ordered by byte offset, so "leaked" comes before the full phrase.
        assert_eq!(
            rules("no data leaked"),
            vec![RuleId::UnprovableNegative, RuleId::Intent]
        );
        assert_eq!(rules("连接是安全的"), vec![RuleId::UnprovableNegative]);
        assert_eq!(rules("读取了 0 字节"), vec![RuleId::ZeroBytes]);
        assert_eq!(rules("read 0 bytes"), vec![RuleId::ZeroBytes]);
        assert_eq!(rules("捕获了所有流量"), vec![RuleId::AllTraffic]);
        assert_eq!(rules("saw all traffic"), vec![RuleId::AllTraffic]);
        assert_eq!(
            rules("A 让 B 窃取了密钥"),
            vec![RuleId::InstructedSteal, RuleId::Intent]
        );
        assert_eq!(
            rules("A instructed B to steal it"),
            vec![RuleId::InstructedSteal]
        );
        assert_eq!(rules("A 通过 B 上传了数据"), vec![RuleId::UploadedVia]);
        assert_eq!(rules("A uploaded data via B"), vec![RuleId::UploadedVia]);
        assert_eq!(rules("内容与文件匹配"), vec![RuleId::ContentMatchPhrase]);
        assert_eq!(
            rules("chunks identical to the file"),
            vec![RuleId::ContentMatchPhrase]
        );
        assert_eq!(
            rules("content matches the file"),
            vec![RuleId::ContentMatchPhrase]
        );
    }

    #[test]
    fn anquan_after_bu_is_not_a_safety_claim() {
        assert!(lint("此操作不安全").is_empty());
        assert!(lint("不安全").is_empty());
    }

    #[test]
    fn content_match_phrase_is_allowed_only_when_named() {
        let text = "内容与 report.pdf 匹配";
        assert_eq!(rules(text), vec![RuleId::ContentMatchPhrase]);
        assert!(lint_allowing(text, &[RuleId::ContentMatchPhrase]).is_empty());
    }

    #[test]
    fn a_negative_phrase_is_still_caught_beside_anquan() {
        // "不" only suppresses the "安全" alternative, not the rest of the rule.
        assert_eq!(
            rules("虽然不安全，但没有上传任何文件"),
            vec![RuleId::UnprovableNegative]
        );
    }
}
