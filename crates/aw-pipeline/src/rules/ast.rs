//! The compiled form of one rule.
//!
//! A [`Rule`] is what the loader hands the engine. The TOML shape is checked
//! before this exists, so every field here already satisfies the constraints in
//! pipeline.md §3.6: evidence, severity, wording, and window size.

use aw_core::filter::Expr;

/// How far a later step may look back, and which records it may pair with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Same {
    /// The same session. A record with no session matches nothing.
    Session,
    /// The same process.
    Process,
    /// The same process or one of its descendants.
    ProcessTree,
}

/// What a rule is allowed to claim.
///
/// The string form is what a finding carries. The engine never raises it: a
/// rule loaded as [`EvidenceLevel::I`] emits `"I"` on every path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceLevel {
    /// A single observed fact, or a fact conjunction.
    E1,
    /// An inference. Time order is not causation.
    I,
    /// A content-hash match. Only the `content_match` rule may say this.
    ContentMatch,
}

impl EvidenceLevel {
    /// The string a finding stores. Not a display sentence.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::E1 => "E1",
            Self::I => "I",
            Self::ContentMatch => "content_match",
        }
    }
}

/// `info` / `notice` / `warn`. Nothing here means "malicious".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Worth recording, not worth highlighting.
    Info,
    /// Worth highlighting.
    Notice,
    /// Worth highlighting first.
    Warn,
}

impl Severity {
    /// The string a finding stores.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Notice => "notice",
            Self::Warn => "warn",
        }
    }
}

/// What `upgrade_if` is allowed to do: pick a different wording template.
///
/// It never changes the evidence level. `content_match(...)` on an inference
/// rule only swaps in the "compared, no match" or "no proxy" template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpgradeIf {
    /// No alternate wording.
    None,
    /// `content_match(<path step>.path, <flow step>.flow)`.
    ContentMatch {
        /// Alias of the step that carries the path.
        path_step: String,
        /// Alias of the step that carries the flow.
        flow_step: String,
    },
}

/// One `[[rule.match]]` step, already parsed.
#[derive(Debug, Clone, PartialEq)]
pub struct MatchStep {
    /// Alias used by later steps and by `emit.key`.
    pub alias: String,
    /// Record type this step consumes (`file_access`, `net_flow`, ...).
    pub record: String,
    /// The shared filter AST. [`Expr::True`] when `where` was empty.
    pub pred: Expr,
    /// How far back this step reaches, in nanoseconds. `None` on the first step
    /// of a sequence; a threshold rule uses it as the counting window.
    pub within_ns: Option<u64>,
    /// Which earlier records this step may pair with. `None` on a single step.
    pub same: Option<Same>,
    /// How many hits inside the window a threshold rule needs, strictly more
    /// than this number. `None` unless the step declared `threshold`.
    pub threshold: Option<u64>,
}

/// One compiled rule.
#[derive(Debug, Clone, PartialEq)]
pub struct Rule {
    /// Stable id. A user rule with the same id replaces the built-in one.
    pub id: String,
    /// Rule version, copied onto every finding.
    pub version: u32,
    /// Short title. Not a sentence shown to a user.
    pub title: String,
    /// Output evidence. Fixed at load time; the engine does not raise it.
    pub evidence: EvidenceLevel,
    /// `fact`, `fact_conjunction`, `inference`, or `content_match`.
    pub kind: String,
    /// Wording template id. Present in the wording catalog.
    pub wording: String,
    /// Severity.
    pub severity: Severity,
    /// Ordered steps. At least one.
    pub steps: Vec<MatchStep>,
    /// Dedup key pieces, each `alias.field`.
    pub key: Vec<KeyField>,
    /// Alternate wording selector.
    pub upgrade_if: UpgradeIf,
    /// Template parameter names this rule fills.
    pub params: Vec<String>,
    /// `true` when a user file replaced a built-in rule with this id.
    pub user_override: bool,
}

/// One piece of a dedup key: the named field of one step's record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyField {
    /// Step alias.
    pub alias: String,
    /// Field name on that step's record.
    pub field: String,
}

/// Hard ceiling on `within`. pipeline.md and the task card both say 10 minutes.
pub const MAX_WITHIN_NS: u64 = 600 * 1_000_000_000;

/// Default cap on partial matches kept per rule.
pub const DEFAULT_STATE_CAP: usize = 10_000;
