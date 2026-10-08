//! Streaming matcher.
//!
//! Each rule is a small state machine over a sliding window. A record is offered
//! to every rule; a rule keeps the records that matched a step but not yet the
//! whole rule, and completes them when a later record arrives inside the window.
//!
//! State is bounded. Each rule keeps at most [`EngineConfig::state_cap`] partial
//! matches (default [`DEFAULT_STATE_CAP`]). Past that, the oldest partial match
//! is dropped and the engine emits a [`RuleGap`] of kind `rule_state_evicted`.
//! The drop is never silent.
//!
//! Time comes from a [`RuleClock`]. The engine does not read the host clock, so
//! a replay is a function of its input and nothing else.
//!
//! Evidence is fixed when the rule is loaded. This module copies that level onto
//! the finding and never raises it: `sensitive_read_then_send` emits `"I"` on
//! every path, including the one where a content hash was compared and missed.

use std::collections::{BTreeMap, VecDeque};

use aw_core::filter::{EvalCtx, Expr, RecordView};

use super::ast::{EvidenceLevel, KeyField, Rule, Same, UpgradeIf, DEFAULT_STATE_CAP};
use super::load::RuleSet;
use super::clock::RuleClock;
use super::record::{RuleRecord, StepFacts};

/// Bounds the matcher checks while it runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineConfig {
    /// Partial matches one rule may hold. The oldest is dropped past this.
    pub state_cap: usize,
    /// `path` and `dir` compare case-insensitively when the session is Windows.
    pub case_insensitive_paths: bool,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            state_cap: DEFAULT_STATE_CAP,
            case_insensitive_paths: false,
        }
    }
}

/// One reference a finding cites. A table name plus the row id inside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordRef {
    /// Record type, which is also the table name (`file_access`, `net_flow`).
    pub table: String,
    /// Row id inside `table`.
    pub id: u64,
}

/// A finding the engine produced. Not a stored row: nothing here writes SQL.
///
/// `params` holds the template parameters the rule declared. Rendering them is
/// the caller's job, so this crate does not build a sentence it cannot lint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingDraft {
    /// Rule that fired.
    pub rule_id: String,
    /// Rule version.
    pub rule_version: u32,
    /// `fact`, `fact_conjunction`, `inference`, or `content_match`.
    pub kind: String,
    /// Evidence level, as loaded. Never raised by a match.
    pub evidence: String,
    /// `info`, `notice`, or `warn`.
    pub severity: String,
    /// Wording template id. An inference rule may substitute the no-proxy or
    /// hash-miss template; the evidence string stays `"I"`.
    pub wording_id: String,
    /// Template parameters, in the order the rule declared them.
    pub params: Vec<(String, String)>,
    /// Dedup key. The same key repeats as a higher `count`, not a new finding.
    pub dedup_key: String,
    /// The records the match used.
    pub refs: Vec<RecordRef>,
    /// How many times this key has fired, including this one.
    pub count: u64,
    /// Monotonic timestamp of the completing record.
    pub ts_ns: u64,
}

/// A gap the engine itself produced.
///
/// `kind` is a plain string because this crate must not add a variant to
/// `aw_core::GapKind`. `rule_state_evicted` means partial matches were dropped
/// to stay inside the state cap, so a correlation that depended on them did not
/// happen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleGap {
    /// Why. `rule_state_evicted` is the only kind this engine emits.
    pub kind: String,
    /// The rule whose state overflowed.
    pub rule_id: String,
    /// When the overflow was noticed.
    pub ts_ns: u64,
    /// How many partial matches were dropped at once.
    pub dropped: u64,
}

/// What one call produced.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StepOutput {
    /// Findings completed by the record, or flushed at the end.
    pub findings: Vec<FindingDraft>,
    /// Gaps produced while making room for state.
    pub gaps: Vec<RuleGap>,
}

/// A process the matcher may need when a rule says `same = "process_tree"`.
#[derive(Debug, Clone, Copy)]
pub struct ProcNode {
    /// The process.
    pub proc_uid: u64,
    /// Its parent, when it has one inside the session.
    pub parent: Option<u64>,
}

/// The matcher.
pub struct Engine {
    rules: Vec<Rule>,
    config: EngineConfig,
    /// Partial matches per rule, oldest at the front.
    state: Vec<VecDeque<Partial>>,
    /// Findings already emitted, keyed by `(rule index, dedup key)`, so a repeat
    /// raises `count` instead of producing a second draft.
    emitted: BTreeMap<(usize, String), u64>,
    /// Parent links for `process_tree`.
    parents: BTreeMap<u64, Option<u64>>,
}

/// One in-progress match: the records that satisfied a prefix of the steps.
struct Partial {
    /// Facts per step taken so far. Index 0 is step 0.
    facts: Vec<StepFacts>,
    /// The anchor timestamp the next step's `within` is measured from.
    anchor_ns: u64,
    /// Session of the anchor, when it had one.
    session: Option<u64>,
    /// Process of the anchor, when it had one.
    proc_uid: Option<u64>,
}

impl Engine {
    /// Build an engine over `set`. Rules run in the set's order.
    pub fn new(set: RuleSet, config: EngineConfig) -> Self {
        let n = set.rules().len();
        Self {
            rules: set.rules().to_vec(),
            config,
            state: (0..n).map(|_| VecDeque::new()).collect(),
            emitted: BTreeMap::new(),
            parents: BTreeMap::new(),
        }
    }

    /// The rules being run.
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Record a process so `same = "process_tree"` can walk parents.
    ///
    /// A process with no parent is stored as such. The engine does not invent a
    /// parent it was not given.
    pub fn observe_process(&mut self, node: ProcNode) {
        self.parents.insert(node.proc_uid, node.parent);
    }

    /// Offer one record to every rule.
    ///
    /// `clock` decides which partial matches are still inside their window. The
    /// record's own timestamp is what the match is anchored to.
    pub fn push<C: RuleClock + ?Sized>(&mut self, clock: &C, record: &RuleRecord) -> StepOutput {
        let mut out = StepOutput::default();
        let now = clock.now_ns();
        for index in 0..self.rules.len() {
            self.expire(index, now);
            self.offer(index, record, now, &mut out);
        }
        out
    }

    /// Drop state and return nothing new.
    ///
    /// Findings are emitted as soon as they complete, so there is nothing left
    /// to flush. The call exists so a caller can release the window at a
    /// session boundary.
    pub fn finish<C: RuleClock + ?Sized>(&mut self, clock: &C) -> StepOutput {
        let now = clock.now_ns();
        for index in 0..self.rules.len() {
            self.expire(index, now);
        }
        StepOutput::default()
    }

    fn expire(&mut self, index: usize, now: u64) {
        let window = self.rules[index]
            .steps
            .iter()
            .filter_map(|step| step.within_ns)
            .max()
            .unwrap_or(0);
        if window == 0 {
            return;
        }
        let state = &mut self.state[index];
        while state.front().is_some_and(|partial| partial.anchor_ns.saturating_add(window) < now) {
            state.pop_front();
        }
    }

    fn offer(&mut self, index: usize, record: &RuleRecord, now: u64, out: &mut StepOutput) {
        let first_type = self.rules[index].steps[0].record.clone();
        let second_type = self.rules[index].steps.get(1).map(|step| step.record.clone());
        if record.record_type() == first_type && self.matches_step(index, 0, record, None) {
            self.note_first_step(index, record, now, out);
        }
        if second_type.as_deref() == Some(record.record_type()) {
            self.note_second_step(index, record, out);
        }
    }

    fn note_first_step(&mut self, index: usize, record: &RuleRecord, now: u64, out: &mut StepOutput) {
        let rule = &self.rules[index];
        let mut facts = record.facts();
        facts.alias = rule.steps[0].alias.clone();
        if rule.steps.len() == 1 {
            if let Some(threshold) = rule.steps[0].threshold {
                self.note_threshold(index, record, &facts, threshold, out);
                return;
            }
            self.emit(index, &[facts], record.ts_ns(), None, out);
            return;
        }
        self.push_partial(
            index,
            Partial {
                facts: vec![facts],
                anchor_ns: record.ts_ns(),
                session: record.session(),
                proc_uid: record.proc_uid(),
            },
            now,
            out,
        );
    }

    /// A threshold rule fires once the window holds strictly more than
    /// `threshold` matching records. The count and the window both come from
    /// the rule, not from a constant in this file.
    fn note_threshold(
        &mut self,
        index: usize,
        record: &RuleRecord,
        facts: &StepFacts,
        threshold: u64,
        out: &mut StepOutput,
    ) {
        let window = self.rules[index].steps[0].within_ns.unwrap_or(0);
        let proc = record.proc_uid();
        let session = record.session();
        let ts = record.ts_ns();
        let state = &mut self.state[index];
        let mut count = 1_u64;
        for partial in state.iter() {
            if partial.proc_uid != proc || partial.session != session {
                continue;
            }
            if ts.saturating_sub(partial.anchor_ns) <= window {
                count = count.saturating_add(1);
            }
        }
        self.push_partial(
            index,
            Partial { facts: vec![facts.clone()], anchor_ns: ts, session, proc_uid: proc },
            ts,
            out,
        );
        if count > threshold {
            self.emit(index, std::slice::from_ref(facts), ts, Some(count), out);
        }
    }

    fn note_second_step(&mut self, index: usize, record: &RuleRecord, out: &mut StepOutput) {
        let rule_steps_same = self.rules[index].steps[1].same;
        let window = self.rules[index].steps[1].within_ns.unwrap_or(0);
        let ts = record.ts_ns();
        let completed: Vec<Vec<StepFacts>> = self.state[index]
            .iter()
            .filter(|partial| self.pairs(partial, record, rule_steps_same, window, ts))
            .filter(|partial| self.matches_step(index, 1, record, partial.facts.first()))
            .map(|partial| {
                let mut facts = partial.facts.clone();
                let mut second = record.facts();
                second.alias = self.rules[index].steps[1].alias.clone();
                facts.push(second);
                facts
            })
            .collect();
        for facts in completed {
            self.emit(index, &facts, ts, None, out);
        }
    }

    fn pairs(&self, partial: &Partial, record: &RuleRecord, same: Option<Same>, window: u64, ts: u64) -> bool {
        if ts < partial.anchor_ns || ts.saturating_sub(partial.anchor_ns) > window {
            return false;
        }
        match same.unwrap_or(Same::Session) {
            Same::Session => partial.session.is_some() && partial.session == record.session(),
            Same::Process => partial.proc_uid.is_some() && partial.proc_uid == record.proc_uid(),
            Same::ProcessTree => self.in_tree(partial.proc_uid, record.proc_uid()),
        }
    }

    /// `candidate` is `anchor` itself or a descendant of it.
    fn in_tree(&self, anchor: Option<u64>, candidate: Option<u64>) -> bool {
        let (Some(anchor), Some(mut current)) = (anchor, candidate) else {
            return false;
        };
        let mut guard = 0_u32;
        loop {
            if current == anchor {
                return true;
            }
            match self.parents.get(&current).copied().flatten() {
                Some(parent) => current = parent,
                None => return false,
            }
            guard = guard.saturating_add(1);
            if guard > 64 {
                return false;
            }
        }
    }

    fn matches_step(
        &self,
        index: usize,
        step_index: usize,
        record: &RuleRecord,
        earlier: Option<&StepFacts>,
    ) -> bool {
        let ctx = EvalCtx {
            session_start_ns: 0,
            now_ns: i64::try_from(record.ts_ns()).unwrap_or(i64::MAX),
            case_insensitive_paths: self.config.case_insensitive_paths,
        };
        // `path = a.path` cannot be answered by the shared evaluator, which has
        // no notion of an alias. Substitute the earlier step's value first, so
        // the comparison that reaches it is between two plain strings.
        let pred = restore_fields(&bind_aliases(&self.rules[index].steps[step_index].pred, earlier));
        let view = AliasView { record, earlier };
        let hit = pred.to_predicate(ctx)(&view);
        hit
    }

    fn push_partial(&mut self, index: usize, partial: Partial, now: u64, out: &mut StepOutput) {
        let cap = self.config.state_cap;
        if cap == 0 {
            self.record_eviction(index, 1, now, out);
            return;
        }
        let overflow = self.state[index].len().saturating_sub(cap.saturating_sub(1));
        if overflow > 0 {
            self.state[index].drain(..overflow);
            self.record_eviction(index, u64::try_from(overflow).unwrap_or(u64::MAX), now, out);
        }
        self.state[index].push_back(partial);
    }

    fn record_eviction(&self, index: usize, dropped: u64, ts_ns: u64, out: &mut StepOutput) {
        out.gaps.push(RuleGap {
            kind: "rule_state_evicted".to_owned(),
            rule_id: self.rules[index].id.clone(),
            ts_ns,
            dropped,
        });
    }

    fn emit(
        &mut self,
        index: usize,
        facts: &[StepFacts],
        ts_ns: u64,
        observed: Option<u64>,
        out: &mut StepOutput,
    ) {
        let rule = &self.rules[index];
        let dedup_key = build_key(&rule.key, facts);
        let seen = self.emitted.entry((index, dedup_key.clone())).or_insert(0);
        *seen = seen.saturating_add(1);
        let count = *seen;
        let wording_id = pick_wording(rule, facts);
        // A threshold rule already counted the window. Use that count, not the
        // number of times the rule has fired, so the sentence states what was
        // observed.
        let params = build_params(rule, facts, observed.unwrap_or(count));
        let refs = facts
            .iter()
            .map(|fact| RecordRef { table: fact.record.clone(), id: fact.record_id })
            .collect();
        out.findings.push(FindingDraft {
            rule_id: rule.id.clone(),
            rule_version: rule.version,
            kind: rule.kind.clone(),
            evidence: rule.evidence.as_str().to_owned(),
            severity: rule.severity.as_str().to_owned(),
            wording_id,
            params,
            dedup_key,
            refs,
            count,
            ts_ns,
        });
    }
}

/// Put aliased fields back to the name the record actually stores.
///
/// [`super::parse`] rewrites `is_loopback` to `direct` so the shared parser
/// accepts it. The record keeps the real name, so the comparison has to ask for
/// `is_loopback` again.
fn restore_fields(expr: &Expr) -> Expr {
    match expr {
        Expr::True => Expr::True,
        Expr::And(left, right) => Expr::And(Box::new(restore_fields(left)), Box::new(restore_fields(right))),
        Expr::Or(left, right) => Expr::Or(Box::new(restore_fields(left)), Box::new(restore_fields(right))),
        Expr::Not(inner) => Expr::Not(Box::new(restore_fields(inner))),
        Expr::Term(term) => {
            let mut term = term.clone();
            let marked = term.values.iter().any(|value| {
                matches!(value, aw_core::filter::Value::Text(text) if text.starts_with('\u{0}'))
            });
            if marked && term.field.name() == "direct" {
                term.field = aw_core::filter::FieldRef::Named(loopback_field());
                term.values.retain(|value| {
                    !matches!(value, aw_core::filter::Value::Text(text) if text.starts_with('\u{0}'))
                });
            }
            Expr::Term(term)
        }
    }
}

fn loopback_field() -> &'static aw_core::filter::FieldInfo {
    use aw_core::filter::{FieldInfo, FieldKind, FieldType};
    static FIELD: FieldInfo = FieldInfo { name: "is_loopback", ty: FieldType::Bool, kind: FieldKind::Net };
    &FIELD
}

/// Replace `alias.field` text values with the earlier step's value.
///
/// A reference whose step has not matched yet is left as written, so it can
/// only compare equal to a field that literally contains that text.
fn bind_aliases(expr: &Expr, earlier: Option<&StepFacts>) -> Expr {
    match expr {
        Expr::True => Expr::True,
        Expr::And(left, right) => {
            Expr::And(Box::new(bind_aliases(left, earlier)), Box::new(bind_aliases(right, earlier)))
        }
        Expr::Or(left, right) => {
            Expr::Or(Box::new(bind_aliases(left, earlier)), Box::new(bind_aliases(right, earlier)))
        }
        Expr::Not(inner) => Expr::Not(Box::new(bind_aliases(inner, earlier))),
        Expr::Term(term) => {
            let mut term = term.clone();
            for value in &mut term.values {
                if let aw_core::filter::Value::Text(text) = value {
                    if let Some((alias, field)) = text.split_once('.') {
                        if earlier.is_some_and(|facts| facts.alias == alias) {
                            if let Some(bound) = earlier.and_then(|facts| facts.text(field)) {
                                *text = bound.clone();
                            }
                        }
                    }
                }
            }
            Expr::Term(term)
        }
    }
}

/// A record plus, when a later step asks, the facts of the step before it.
struct AliasView<'a> {
    record: &'a RuleRecord,
    earlier: Option<&'a StepFacts>,
}

impl RecordView for AliasView<'_> {
    fn text(&self, field: &str) -> Option<&str> {
        self.record.text(field).or_else(|| match field {
            "path" => self.earlier.and_then(|facts| facts.text("path")).map(String::as_str),
            _ => None,
        })
    }

    fn number(&self, field: &str) -> Option<i64> {
        self.record.number(field)
    }

    fn bool_value(&self, field: &str) -> Option<bool> {
        self.record.bool_value(field)
    }

    fn in_subtree(&self, proc_uid: &str) -> bool {
        self.record.in_subtree(proc_uid)
    }
}

fn build_key(fields: &[KeyField], facts: &[StepFacts]) -> String {
    fields
        .iter()
        .map(|field| {
            let value = facts
                .iter()
                .find(|fact| fact.alias == field.alias)
                .and_then(|fact| fact.text(&field.field))
                .map(String::as_str)
            .unwrap_or("");
            format!("{}={}", field.field, value)
        })
        .collect::<Vec<_>>()
        .join("|")
}

/// The template an inference rule renders with.
///
/// `upgrade_if` never changes the evidence level. It only picks between the
/// rule's own template, the no-proxy template, and the hash-miss template,
/// depending on what the flow record says.
fn pick_wording(rule: &Rule, facts: &[StepFacts]) -> String {
    let UpgradeIf::ContentMatch { flow_step, .. } = &rule.upgrade_if else {
        return rule.wording.clone();
    };
    if rule.evidence != EvidenceLevel::I {
        return rule.wording.clone();
    }
    let flow = facts.iter().find(|fact| &fact.alias == flow_step);
    let proxy_on = flow.and_then(|fact| fact.flag("proxy_enabled")).unwrap_or(false);
    let compared = flow.and_then(|fact| fact.flag("hash_compared")).unwrap_or(false);
    if !proxy_on {
        "infer.temporal_no_proxy".to_owned()
    } else if compared {
        "infer.temporal_hash_miss".to_owned()
    } else {
        rule.wording.clone()
    }
}

fn build_params(rule: &Rule, facts: &[StepFacts], count: u64) -> Vec<(String, String)> {
    rule.params
        .iter()
        .map(|name| {
            let value = param_value(name, facts)
                .or_else(|| rule_param(rule, name, count))
                .unwrap_or_else(|| "不可得".to_owned());
            (name.clone(), value)
        })
        .collect()
}

/// Values the rule itself knows, which no single record carries: the window it
/// counted over, the threshold it declared, and how many times it has fired.
///
/// A name that is neither on a record nor here stays unresolved. The caller
/// renders `不可得` for it rather than an empty string, so a sentence never
/// pretends a value was observed when it was not.
fn rule_param(rule: &Rule, name: &str, count: u64) -> Option<String> {
    let step = rule.steps.first()?;
    match name {
        "window" | "within" => step.within_ns.map(format_duration),
        "threshold" => step.threshold.map(|value| value.to_string()),
        "count" => Some(count.to_string()),
        _ => None,
    }
}

fn format_duration(ns: u64) -> String {
    let secs = ns / 1_000_000_000;
    if secs >= 60 && secs.is_multiple_of(60) {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
}

/// A parameter is either a plain name, filled from any step, or `alias.name`,
/// filled from that step only.
fn param_value(name: &str, facts: &[StepFacts]) -> Option<String> {
    if let Some((alias, field)) = name.split_once('.') {
        return facts.iter().find(|fact| fact.alias == alias).and_then(|fact| fact.param(field));
    }
    facts.iter().find_map(|fact| fact.param(name))
}

impl RecordView for RuleRecord {
    fn text(&self, field: &str) -> Option<&str> {
        RuleRecord::text(self, field)
    }

    fn number(&self, field: &str) -> Option<i64> {
        RuleRecord::number(self, field)
    }

    fn bool_value(&self, field: &str) -> Option<bool> {
        RuleRecord::bool_value(self, field)
    }

    fn in_subtree(&self, proc_uid: &str) -> bool {
        RuleRecord::in_subtree(self, proc_uid)
    }
}
