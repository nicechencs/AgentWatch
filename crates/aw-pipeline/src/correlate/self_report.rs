//! Align E3 self-reports with E1 observations (P5-PIPE-01).
//!
//! The function is pure. Time comes from the timestamps the caller already
//! recorded. Nothing here reads a clock, opens a file, or writes a log.
//!
//! Evidence split, from evidence-model §2.2 and ADR-0004:
//!
//! - A [`SelfReport`] is E3. It explains intent. It never supports a finding
//!   on its own.
//! - An [`Alignment`] (which call lines up with which event) is inference, so
//!   its evidence is `"I"`. That string is fixed. This module does not have a
//!   path that writes `"E1"` or `"E2"` onto an alignment.
//! - A [`Finding`] of kind `self_report_mismatch` carries `"E1"` only as the
//!   rule's declared level for the fact "the observation exists and the
//!   self-report does not". The alignment that selected the window stays on a
//!   separate struct at `"I"`.
//!
//! Display strings never contain argv, environment values, full URLs, file
//! contents, `Authorization`, or `Cookie`. A path parameter is redacted when
//! it contains `.ssh` or `id_rsa`. Unknown values are `None`, never `0` or `""`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::wording::{render, Lang};

/// Default window when a pre call has no matching post: 30 seconds.
pub const DEFAULT_WINDOW_NS: u64 = 30_000_000_000;

/// Wording template for the mismatch finding. evidence-model §5.
pub const WORDING_ID: &str = "fact.self_report_mismatch";

/// Annotation when a `self_report_dropped` gap overlaps the window.
///
/// evidence-model has no template for this sentence. The task card requires
/// this exact Chinese text and nothing stronger.
pub const INCOMPLETE_SELF_REPORT: &str = "自报告不完整";

/// Annotation when a self-report has no observation, the caller said the
/// collector covers that kind, and no gap overlaps the window.
pub const UNOBSERVED: &str = "系统未观测到对应事件";

/// Fixed evidence string for an alignment. Never `"E1"` or `"E2"`.
const ALIGNMENT_EVIDENCE: &str = "I";

/// Evidence the `self_report_mismatch` rule declares for the fact that an
/// observation exists and the self-report does not. Not the alignment's level.
const FINDING_EVIDENCE: &str = "E1";

/// Evidence of every self-report this function accepts.
const SELF_REPORT_EVIDENCE: &str = "E3";

/// Substrings that must not appear in any string this module emits.
const FORBIDDEN: &[&str] = &[
    "隐瞒",
    "欺骗",
    "恶意",
    "上传了",
    "泄露",
    "窃取",
    "safe",
    "安全",
];

/// Sensitive path segments replaced in a display parameter.
const SENSITIVE_SEGMENTS: &[&str] = &[".ssh", "id_rsa"];

/// Marker written over a sensitive path segment. Same marker as `wording`.
const PATH_MARK: &str = "«redacted:path»";

/// How long an unmatched pre call stays open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowConfig {
    /// Nanoseconds added to a pre timestamp when no post shares its `call_id`.
    pub unmatched_pre_ns: u64,
}

impl Default for WindowConfig {
    fn default() -> Self {
        Self {
            unmatched_pre_ns: DEFAULT_WINDOW_NS,
        }
    }
}

impl WindowConfig {
    /// A window of `unmatched_pre_ns` for a pre call that has no post.
    pub fn new(unmatched_pre_ns: u64) -> Self {
        Self { unmatched_pre_ns }
    }
}

/// Which summary field a self-report carried. Only these four are copied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SummaryKey {
    /// A shell command. Only the first token is compared.
    Command,
    /// A file path.
    Path,
    /// A URL. Only its host is kept.
    Url,
    /// A search query. Kept so the caller can see it; not matched to a domain.
    Query,
}

/// The only summary fields this module accepts. Other keys are dropped.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct SelfReportSummary {
    /// Shell command, when the tool reported one.
    pub command: Option<String>,
    /// File path, when the tool reported one.
    pub path: Option<String>,
    /// URL host only. The path and query of the URL are not stored.
    pub url_host: Option<String>,
    /// Search query, when the tool reported one.
    pub query: Option<String>,
}

impl SelfReportSummary {
    /// Keep `command`, `path`, `url`, and `query`. Ignore every other key.
    ///
    /// A `url` value is reduced to its host before it is stored. An empty
    /// string is treated as absent (`None`), not as a known empty value.
    pub fn from_pairs<I, K, V>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let mut summary = Self::default();
        for (key, value) in pairs {
            let value = value.as_ref();
            if value.is_empty() {
                continue;
            }
            match key.as_ref() {
                "command" => summary.command = Some(value.to_owned()),
                "path" => summary.path = Some(value.to_owned()),
                "url" => summary.url_host = host_of(value),
                "query" => summary.query = Some(value.to_owned()),
                _ => {}
            }
        }
        summary
    }

    /// `true` when none of the four fields is present.
    pub fn is_empty(&self) -> bool {
        self.command.is_none()
            && self.path.is_none()
            && self.url_host.is_none()
            && self.query.is_none()
    }
}

impl fmt::Debug for SelfReportSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Lengths only. A command or query must not appear in a debug print.
        f.debug_struct("SelfReportSummary")
            .field("command", &redacted_len(self.command.as_deref()))
            .field("path", &self.path.as_ref().map(|p| redact_path(p)))
            .field("url_host", &self.url_host.as_deref().map(redact_host))
            .field("query", &redacted_len(self.query.as_deref()))
            .finish()
    }
}

/// One Agent tool call. Evidence is E3 by definition.
#[derive(Clone, PartialEq, Eq)]
pub struct SelfReport {
    /// Process that reported the call.
    pub proc_uid: u64,
    /// Tool name as reported (`Bash`, `Read`, `WebFetch`, ...).
    pub tool: String,
    /// `"pre"` or `"post"`. Anything else is stored and not used as a window edge.
    pub phase: String,
    /// Pairs a pre with its post. `None` means this call cannot be paired.
    pub call_id: Option<String>,
    /// Timestamp already recorded by the caller. Not read from a clock here.
    pub ts_ns: u64,
    /// Structured summary. Only the four allowed keys survive [`SelfReportSummary`].
    pub summary: SelfReportSummary,
}

impl fmt::Debug for SelfReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SelfReport")
            .field("proc_uid", &self.proc_uid)
            .field("tool", &self.tool)
            .field("phase", &self.phase)
            .field("call_id", &redacted_len(self.call_id.as_deref()))
            .field("ts_ns", &self.ts_ns)
            .field("summary", &self.summary)
            .field("evidence", &SELF_REPORT_EVIDENCE)
            .finish()
    }
}

/// A process start inside the session.
///
/// `argv_prefix` is kept so the first token can be compared with a shell
/// command. `Debug` prints only the argument count.
///
/// The subtree walk joins `ppid` to another start's `pid`. Both are `Option`:
/// `None` means the id was not observed, and it is never stored as `0`.
#[derive(Clone, PartialEq, Eq)]
pub struct ProcessStartObs {
    /// The new process, as a `ProcUid`.
    pub proc_uid: u64,
    /// OS pid, when the caller knows it. Needed to join a child's `ppid`.
    pub pid: Option<u32>,
    /// OS parent pid, when the caller knows it.
    pub ppid: Option<u32>,
    /// Argv, in order. Compared only by its first token.
    pub argv_prefix: Vec<String>,
    /// When the process started.
    pub ts_ns: u64,
}

impl fmt::Debug for ProcessStartObs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProcessStartObs")
            .field("proc_uid", &self.proc_uid)
            .field("pid", &self.pid)
            .field("ppid", &self.ppid)
            .field(
                "argv_prefix",
                &format!("<redacted argc={}>", self.argv_prefix.len()),
            )
            .field("ts_ns", &self.ts_ns)
            .finish()
    }
}

/// A file access observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileAccessObs {
    /// Process that accessed the file.
    pub proc_uid: u64,
    /// Path as observed. Not lowercased unless the caller set the flag.
    pub path: String,
    /// `read`, `write`, or another op string the caller already chose.
    pub op: String,
    /// Whether a sensitive-path rule already marked this access.
    pub sensitive: bool,
    /// When the access was observed.
    pub ts_ns: u64,
}

/// A network or HTTP observation. Host only: no URL path, no query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetObs {
    /// Process that opened the connection or issued the request.
    pub proc_uid: u64,
    /// Domain or host. `None` when the observation had no name.
    pub host: Option<String>,
    /// When the observation was recorded.
    pub ts_ns: u64,
}

/// One observation. The kind is what matching looks at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Observation {
    /// A process start.
    Process(ProcessStartObs),
    /// A file access.
    File(FileAccessObs),
    /// A network or HTTP observation.
    Net(NetObs),
}

impl Observation {
    fn proc_uid(&self) -> u64 {
        match self {
            Self::Process(p) => p.proc_uid,
            Self::File(f) => f.proc_uid,
            Self::Net(n) => n.proc_uid,
        }
    }

    fn ts_ns(&self) -> u64 {
        match self {
            Self::Process(p) => p.ts_ns,
            Self::File(f) => f.ts_ns,
            Self::Net(n) => n.ts_ns,
        }
    }
}

/// Coarse kind, used by `collector_covers` and the unclassified list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservationKind {
    /// Process start.
    ProcessStart,
    /// File access.
    FileAccess,
    /// Network or HTTP.
    Net,
}

/// Which tool family a self-report belongs to, for matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolKind {
    /// `Bash` or `Shell`. Matches a process start by argv prefix.
    Shell,
    /// `Read`, `Edit`, or `Write`. Matches a file access by normalized path.
    File,
    /// `WebFetch` or `WebSearch`. Matches a net observation by host.
    Web,
    /// Anything else. Not matched, and not a reason to drop an observation.
    Other,
}

impl ToolKind {
    fn classify(tool: &str) -> Self {
        match tool {
            "Bash" | "Shell" => Self::Shell,
            "Read" | "Edit" | "Write" => Self::File,
            "WebFetch" | "WebSearch" => Self::Web,
            _ => Self::Other,
        }
    }

    fn covers_kind(self) -> Option<ObservationKind> {
        match self {
            Self::Shell => Some(ObservationKind::ProcessStart),
            Self::File => Some(ObservationKind::FileAccess),
            Self::Web => Some(ObservationKind::Net),
            Self::Other => None,
        }
    }
}

/// A `self_report_dropped` interval. Inclusive on both ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GapInterval {
    /// First nanosecond of the gap.
    pub start_ns: u64,
    /// Last nanosecond of the gap.
    pub end_ns: u64,
}

impl GapInterval {
    /// `true` when this gap shares any nanosecond with `[start, end]`.
    fn overlaps(self, start: u64, end: u64) -> bool {
        self.start_ns <= end && start <= self.end_ns
    }
}

/// One inferred alignment. Evidence is always `"I"`.
#[derive(Clone, PartialEq, Eq)]
pub struct Alignment {
    /// Index into the self-report slice the caller passed.
    pub report_index: usize,
    /// Index into the observation slice the caller passed.
    pub observation_index: usize,
    /// Tool family that produced the match.
    pub tool: ToolKind,
    /// Evidence of the alignment. Always `"I"`.
    pub evidence: &'static str,
}

impl fmt::Debug for Alignment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Alignment")
            .field("report_index", &self.report_index)
            .field("observation_index", &self.observation_index)
            .field("tool", &self.tool)
            .field("evidence", &self.evidence)
            .finish()
    }
}

/// A `self_report_mismatch` finding.
///
/// `evidence` is the rule's declared level for the fact, not the alignment.
#[derive(Clone, PartialEq, Eq)]
pub struct Finding {
    /// Always `self_report_mismatch`.
    pub kind: &'static str,
    /// Rule-declared level: `"E1"`. The alignment is a separate struct.
    pub evidence: &'static str,
    /// `fact.self_report_mismatch`.
    pub wording_id: &'static str,
    /// Display parameters. Paths are redacted. No argv, no full URL.
    pub params: BTreeMap<String, String>,
    /// Index of the observation that had no matching self-report.
    pub observation_index: usize,
    /// Process the observation was attributed to.
    pub proc_uid: u64,
    /// Window the observation fell in, when one was open. `None` when the
    /// session had no self-report window and the observation still qualified.
    pub window: Option<(u64, u64)>,
}

impl fmt::Debug for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Finding")
            .field("kind", &self.kind)
            .field("evidence", &self.evidence)
            .field("wording_id", &self.wording_id)
            .field("params", &self.params)
            .field("observation_index", &self.observation_index)
            .field("proc_uid", &self.proc_uid)
            .field("window", &self.window)
            .finish()
    }
}

/// A note that is not a finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Annotation {
    /// Fixed Chinese sentence. Never a motivational claim.
    pub text: &'static str,
    /// Window the note refers to, when there was one.
    pub window: Option<(u64, u64)>,
    /// Self-report the note refers to, for the reverse case.
    pub report_index: Option<usize>,
}

/// An observation this function could not classify against a tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unclassified {
    /// Index into the observation slice.
    pub observation_index: usize,
    /// Why it was not classified.
    pub reason: UnclassifiedReason,
}

/// Why an observation was counted as unclassified rather than dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnclassifiedReason {
    /// A net observation had no host, so it cannot be compared with a URL host.
    NetWithoutHost,
    /// A process start had an empty argv, so there is no first token.
    ProcessWithoutArgv,
    /// A file path was empty after normalization.
    EmptyPath,
}

/// Everything [`align`] returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlignOutput {
    /// Inferred alignments. Each has evidence `"I"`.
    pub alignments: Vec<Alignment>,
    /// Mismatch findings. Empty when the only support would be E3.
    pub findings: Vec<Finding>,
    /// Gap notes and reverse-case notes. Not findings.
    pub annotations: Vec<Annotation>,
    /// Observations that could not be classified. Never silently dropped.
    pub unclassified: Vec<Unclassified>,
    /// How many observations were not classified. Same length as `unclassified`.
    pub unmatched_observations: u64,
    /// `true` when every would-be finding was refused because its only support
    /// was E3. Callers can check this. The function does not panic.
    pub rejected_e3_only: bool,
}

/// Why [`align`] refused to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlignError {
    /// A caller-supplied evidence string for a supporting observation was E3
    /// and nothing stronger was present. The function returns this instead of
    /// emitting a finding.
    ///
    /// The current input types carry no per-observation evidence, so this is
    /// returned only through [`align_with_evidence`] when every supporting
    /// level is E3.
    E3Only,
}

impl fmt::Display for AlignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::E3Only => write!(
                f,
                "refused a finding whose only support was E3; no finding emitted"
            ),
        }
    }
}

impl std::error::Error for AlignError {}

/// One observation plus the evidence level the caller says it has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidencedObservation {
    /// The observation.
    pub observation: Observation,
    /// `"E1"`, `"E2"`, `"E3"`, `"S"`, `"I"`, or `"NA"`.
    pub evidence: String,
}

/// Align self-reports with observations.
///
/// Observations passed here are treated as system observations (E1). Use
/// [`align_with_evidence`] when a caller must prove the support is not E3-only.
///
/// `collector_covers` names kinds the collector can see. The reverse case
/// (a self-report with no observation) emits [`UNOBSERVED`] only when the
/// matching kind is in this set and no gap overlaps the window.
///
/// `case_insensitive_paths` lowercases paths before comparison. The default
/// for this Linux-shaped function is `false`.
pub fn align(
    reports: &[SelfReport],
    observations: &[Observation],
    gaps: &[GapInterval],
    collector_covers: &[ObservationKind],
    case_insensitive_paths: bool,
    window: WindowConfig,
) -> AlignOutput {
    align_inner(
        reports,
        observations,
        &vec![FINDING_EVIDENCE.to_owned(); observations.len()],
        gaps,
        collector_covers,
        case_insensitive_paths,
        window,
    )
}

/// Like [`align`], but each observation carries its own evidence string.
///
/// If a sensitive file access or outbound net observation would otherwise
/// become a finding, and every observation that supports it is E3, the
/// finding is not emitted and [`AlignOutput::rejected_e3_only`] is set.
/// This does not panic.
pub fn align_with_evidence(
    reports: &[SelfReport],
    observations: &[EvidencedObservation],
    gaps: &[GapInterval],
    collector_covers: &[ObservationKind],
    case_insensitive_paths: bool,
    window: WindowConfig,
) -> AlignOutput {
    let obs: Vec<Observation> = observations
        .iter()
        .map(|item| item.observation.clone())
        .collect();
    let levels: Vec<String> = observations
        .iter()
        .map(|item| item.evidence.clone())
        .collect();
    align_inner(
        reports,
        &obs,
        &levels,
        gaps,
        collector_covers,
        case_insensitive_paths,
        window,
    )
}

fn align_inner(
    reports: &[SelfReport],
    observations: &[Observation],
    levels: &[String],
    gaps: &[GapInterval],
    collector_covers: &[ObservationKind],
    case_insensitive_paths: bool,
    window: WindowConfig,
) -> AlignOutput {
    let tree = ProcTree::from_observations(observations);
    let windows = windows_of(reports, window.unmatched_pre_ns);
    let mut alignments = Vec::new();
    let mut matched_obs: BTreeSet<usize> = BTreeSet::new();
    let mut matched_reports: BTreeSet<usize> = BTreeSet::new();

    for (report_index, report) in reports.iter().enumerate() {
        if report.phase != "pre" {
            continue;
        }
        let Some(win) = windows.get(&report_index).copied() else {
            continue;
        };
        let tool = ToolKind::classify(&report.tool);
        for (obs_index, obs) in observations.iter().enumerate() {
            if !in_window(obs.ts_ns(), win) {
                continue;
            }
            if !tree.in_subtree(report.proc_uid, obs.proc_uid()) {
                continue;
            }
            if matches_pair(report, obs, case_insensitive_paths) {
                alignments.push(Alignment {
                    report_index,
                    observation_index: obs_index,
                    tool,
                    evidence: ALIGNMENT_EVIDENCE,
                });
                matched_obs.insert(obs_index);
                matched_reports.insert(report_index);
            }
        }
    }

    let mut unclassified = Vec::new();
    for (index, obs) in observations.iter().enumerate() {
        if let Some(reason) = unclassified_reason(obs) {
            unclassified.push(Unclassified {
                observation_index: index,
                reason,
            });
        }
    }

    let mut findings = Vec::new();
    let mut annotations = Vec::new();
    let mut rejected_e3_only = false;
    let mut finding_keys: BTreeSet<(usize, u64)> = BTreeSet::new();

    for (index, obs) in observations.iter().enumerate() {
        if matched_obs.contains(&index) {
            continue;
        }
        if !is_mismatch_candidate(obs) {
            continue;
        }
        let covering: Vec<(u64, u64)> =
            covering_windows(obs.ts_ns(), obs.proc_uid(), reports, &windows, &tree);
        // No self-report window covers this observation: there is no E3 record
        // to contradict, so there is no mismatch to report.
        if covering.is_empty() {
            continue;
        }
        let overlapped = covering
            .iter()
            .any(|(start, end)| gap_overlaps(gaps, *start, *end));
        if overlapped {
            for (start, end) in &covering {
                if gap_overlaps(gaps, *start, *end) {
                    push_incomplete(&mut annotations, *start, *end);
                }
            }
            continue;
        }
        match support_level(index, levels) {
            Support::E1OrE2 => {}
            Support::E3Only => {
                // ADR-0004: E3 cannot support a finding on its own. Refuse
                // and flag it. Do not panic in library code.
                rejected_e3_only = true;
                continue;
            }
            Support::NotSystem => continue,
        }
        let window_span = covering.first().copied();
        let key = (index, obs.proc_uid());
        if !finding_keys.insert(key) {
            continue;
        }
        findings.push(make_finding(index, obs, window_span));
    }

    // A gap over any self-report window is annotated even when nothing else
    // in that window would have been a finding. The note is the fixed sentence
    // and nothing stronger.
    for (start, end) in windows.values().copied() {
        if gap_overlaps(gaps, start, end) {
            push_incomplete(&mut annotations, start, end);
        }
    }

    // Reverse case: a pre self-report with no observation. Said only when the
    // collector covers that kind and no gap overlaps the window.
    for (report_index, report) in reports.iter().enumerate() {
        if report.phase != "pre" || matched_reports.contains(&report_index) {
            continue;
        }
        let Some(kind) = ToolKind::classify(&report.tool).covers_kind() else {
            continue;
        };
        if !collector_covers.contains(&kind) {
            continue;
        }
        let Some(win) = windows.get(&report_index).copied() else {
            continue;
        };
        if gap_overlaps(gaps, win.0, win.1) {
            continue;
        }
        // The summary must actually name something we could have observed.
        if !report_has_matchable_summary(report) {
            continue;
        }
        annotations.push(Annotation {
            text: UNOBSERVED,
            window: Some(win),
            report_index: Some(report_index),
        });
    }

    debug_assert!(
        findings.iter().all(|finding| {
            finding
                .params
                .values()
                .all(|value| !contains_forbidden(value))
                && !contains_forbidden(finding.kind)
                && !contains_forbidden(finding.wording_id)
        }),
        "a finding string contains a forbidden substring"
    );
    debug_assert!(
        annotations
            .iter()
            .all(|note| !contains_forbidden(note.text)),
        "an annotation contains a forbidden substring"
    );
    debug_assert!(
        alignments
            .iter()
            .all(|item| item.evidence == ALIGNMENT_EVIDENCE),
        "alignment evidence must stay I"
    );

    AlignOutput {
        alignments,
        findings,
        annotations,
        unmatched_observations: u64::try_from(unclassified.len()).unwrap_or(u64::MAX),
        unclassified,
        rejected_e3_only,
    }
}

/// Parent links from process-start observations.
///
/// `ppid` is an OS pid. It is joined to another start's `pid` to recover that
/// parent's `proc_uid`. A missing pid or ppid is `None` and is not walked.
struct ProcTree {
    /// `proc_uid` → parent `proc_uid`, only when both ends were observed.
    parent_of: BTreeMap<u64, u64>,
}

impl ProcTree {
    fn from_observations(observations: &[Observation]) -> Self {
        let mut pid_to_uid: BTreeMap<u32, u64> = BTreeMap::new();
        for obs in observations {
            if let Observation::Process(proc) = obs {
                if let Some(pid) = proc.pid {
                    pid_to_uid.entry(pid).or_insert(proc.proc_uid);
                }
            }
        }
        let mut parent_of = BTreeMap::new();
        for obs in observations {
            if let Observation::Process(proc) = obs {
                if let Some(ppid) = proc.ppid {
                    if let Some(parent_uid) = pid_to_uid.get(&ppid).copied() {
                        if parent_uid != proc.proc_uid {
                            parent_of.insert(proc.proc_uid, parent_uid);
                        }
                    }
                }
            }
        }
        Self { parent_of }
    }

    /// `candidate` is `anchor` or a descendant of `anchor`.
    fn in_subtree(&self, anchor: u64, candidate: u64) -> bool {
        if candidate == anchor {
            return true;
        }
        let mut current = candidate;
        for _ in 0..64 {
            match self.parent_of.get(&current).copied() {
                Some(parent) if parent == anchor => return true,
                Some(parent) => current = parent,
                None => return false,
            }
        }
        false
    }
}

fn covering_windows(
    ts: u64,
    proc_uid: u64,
    reports: &[SelfReport],
    windows: &BTreeMap<usize, (u64, u64)>,
    tree: &ProcTree,
) -> Vec<(u64, u64)> {
    let mut spans = Vec::new();
    for (index, span) in windows {
        if !in_window(ts, *span) {
            continue;
        }
        let Some(report) = reports.get(*index) else {
            continue;
        };
        if tree.in_subtree(report.proc_uid, proc_uid) && !spans.contains(span) {
            spans.push(*span);
        }
    }
    spans
}

/// Pre calls open a window. A post with the same `call_id` closes it.
/// A pre with no post stays open for `unmatched_pre_ns`.
fn windows_of(reports: &[SelfReport], unmatched_pre_ns: u64) -> BTreeMap<usize, (u64, u64)> {
    let mut posts: BTreeMap<&str, u64> = BTreeMap::new();
    for report in reports {
        if report.phase == "post" {
            if let Some(id) = report.call_id.as_deref() {
                posts.insert(id, report.ts_ns);
            }
        }
    }
    let mut windows = BTreeMap::new();
    for (index, report) in reports.iter().enumerate() {
        if report.phase != "pre" {
            continue;
        }
        let end = match report.call_id.as_deref().and_then(|id| posts.get(id)) {
            Some(post_ts) => *post_ts,
            None => report.ts_ns.saturating_add(unmatched_pre_ns),
        };
        let end = end.max(report.ts_ns);
        windows.insert(index, (report.ts_ns, end));
    }
    windows
}

fn in_window(ts: u64, window: (u64, u64)) -> bool {
    ts >= window.0 && ts <= window.1
}

fn matches_pair(report: &SelfReport, obs: &Observation, case_insensitive_paths: bool) -> bool {
    match (ToolKind::classify(&report.tool), obs) {
        (ToolKind::Shell, Observation::Process(proc)) => {
            let Some(command) = report.summary.command.as_deref() else {
                return false;
            };
            let Some(token) = first_token(command) else {
                return false;
            };
            argv_starts_with(&proc.argv_prefix, token)
        }
        (ToolKind::File, Observation::File(file)) => {
            let Some(path) = report.summary.path.as_deref() else {
                return false;
            };
            normalize_path(path, case_insensitive_paths)
                == normalize_path(&file.path, case_insensitive_paths)
                && !normalize_path(path, case_insensitive_paths).is_empty()
        }
        (ToolKind::Web, Observation::Net(net)) => {
            let Some(host) = report.summary.url_host.as_deref() else {
                return false;
            };
            net.host
                .as_deref()
                .is_some_and(|observed| hosts_equal(host, observed))
        }
        _ => false,
    }
}

fn argv_starts_with(argv: &[String], token: &str) -> bool {
    let Some(first) = argv.first() else {
        return false;
    };
    // The command's first token may be a bare name or a path. Compare the
    // final path segment so `/usr/bin/git` lines up with `git status`.
    segment_eq(first, token)
}

fn segment_eq(argv0: &str, token: &str) -> bool {
    let argv_base = base_name(argv0);
    let token_base = base_name(token);
    argv_base == token_base || argv0 == token
}

fn base_name(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

fn first_token(command: &str) -> Option<&str> {
    command.split_whitespace().next().filter(|t| !t.is_empty())
}

fn normalize_path(path: &str, case_insensitive: bool) -> String {
    let trimmed = path.trim_end_matches(['/', '\\']);
    // A path that was only slashes stays empty, which does not match.
    let owned = if trimmed.is_empty() {
        String::new()
    } else {
        trimmed.to_owned()
    };
    if case_insensitive {
        owned.to_lowercase()
    } else {
        owned
    }
}

fn hosts_equal(left: &str, right: &str) -> bool {
    host_key(left) == host_key(right) && !host_key(left).is_empty()
}

fn host_key(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Host of a URL. Returns `None` when the value has no host.
///
/// The path and the query are discarded here and never stored.
fn host_of(url: &str) -> Option<String> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return None;
    }
    let after_scheme = trimmed
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(trimmed);
    // `scheme://` with nothing after it has no host.
    if trimmed.contains("://") && after_scheme.is_empty() {
        return None;
    }
    let host_port = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    if host_port.is_empty() {
        return None;
    }
    let host = if let Some(rest) = host_port.strip_prefix('[') {
        // IPv6 literal: [::1] or [::1]:443.
        rest.split(']').next().unwrap_or(rest)
    } else {
        host_port.split(':').next().unwrap_or(host_port)
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_owned())
    }
}

fn unclassified_reason(obs: &Observation) -> Option<UnclassifiedReason> {
    match obs {
        Observation::Net(net) if net.host.as_deref().map(str::is_empty).unwrap_or(true) => {
            Some(UnclassifiedReason::NetWithoutHost)
        }
        Observation::Process(proc) if proc.argv_prefix.is_empty() => {
            Some(UnclassifiedReason::ProcessWithoutArgv)
        }
        Observation::File(file) if normalize_path(&file.path, false).is_empty() => {
            Some(UnclassifiedReason::EmptyPath)
        }
        _ => None,
    }
}

fn is_mismatch_candidate(obs: &Observation) -> bool {
    match obs {
        Observation::File(file) => file.sensitive,
        Observation::Net(net) => net.host.is_some(),
        Observation::Process(_) => false,
    }
}

fn gap_overlaps(gaps: &[GapInterval], start: u64, end: u64) -> bool {
    gaps.iter().any(|gap| gap.overlaps(start, end))
}

fn push_incomplete(annotations: &mut Vec<Annotation>, start: u64, end: u64) {
    let already = annotations
        .iter()
        .any(|note| note.text == INCOMPLETE_SELF_REPORT && note.window == Some((start, end)));
    if !already {
        annotations.push(Annotation {
            text: INCOMPLETE_SELF_REPORT,
            window: Some((start, end)),
            report_index: None,
        });
    }
}

enum Support {
    /// The observation is a system or protocol observation.
    E1OrE2,
    /// The only support is a self-report. A finding is refused.
    E3Only,
    /// S, I, NA, or a missing level. Not a mismatch finding.
    NotSystem,
}

fn support_level(index: usize, levels: &[String]) -> Support {
    match levels.get(index).map(String::as_str) {
        Some("E1" | "E2") => Support::E1OrE2,
        Some("E3") => Support::E3Only,
        // S and I are not E3, but they are also not the system observation the
        // rule requires. A finding needs E1 or E2.
        Some(_) | None => Support::NotSystem,
    }
}

fn report_has_matchable_summary(report: &SelfReport) -> bool {
    match ToolKind::classify(&report.tool) {
        ToolKind::Shell => report
            .summary
            .command
            .as_deref()
            .is_some_and(|c| first_token(c).is_some()),
        ToolKind::File => report
            .summary
            .path
            .as_deref()
            .is_some_and(|p| !normalize_path(p, false).is_empty()),
        ToolKind::Web => report.summary.url_host.is_some(),
        ToolKind::Other => false,
    }
}

fn make_finding(index: usize, obs: &Observation, window: Option<(u64, u64)>) -> Finding {
    let mut params = BTreeMap::new();
    let proc = obs.proc_uid().to_string();
    params.insert("proc".to_owned(), proc);
    match obs {
        Observation::File(file) => {
            params.insert("path".to_owned(), redact_path(&file.path));
        }
        Observation::Net(net) => {
            // The template's `{path}` slot is the thing that was observed.
            // A host is not a URL path; the query string is never included.
            // `is_mismatch_candidate` already required `host` to be `Some`, so
            // a missing host does not become an empty parameter.
            if let Some(host) = net.host.as_deref() {
                params.insert("path".to_owned(), redact_host(host));
            }
        }
        Observation::Process(_) => {}
    }
    Finding {
        kind: "self_report_mismatch",
        evidence: FINDING_EVIDENCE,
        wording_id: WORDING_ID,
        params,
        observation_index: index,
        proc_uid: obs.proc_uid(),
        window,
    }
}

/// Replace a `.ssh` or `id_rsa` path segment with the fixed marker.
fn redact_path(path: &str) -> String {
    let mut parts: Vec<String> = Vec::new();
    let slash = if path.contains('\\') && !path.contains('/') {
        '\\'
    } else {
        '/'
    };
    for segment in path.split(['/', '\\']) {
        if SENSITIVE_SEGMENTS
            .iter()
            .any(|needle| segment == *needle || segment.contains(needle))
        {
            parts.push(PATH_MARK.to_owned());
        } else {
            parts.push(segment.to_owned());
        }
    }
    // Preserve a leading slash that `split` turned into an empty first piece.
    parts.join(&slash.to_string())
}

fn redact_host(host: &str) -> String {
    // A host is not a URL. Do not append a path or a query.
    host.to_owned()
}

fn redacted_len(value: Option<&str>) -> String {
    match value {
        Some(text) => format!("<redacted len={}>", text.len()),
        None => "<absent>".to_owned(),
    }
}

/// Render the finding with the compiled wording table.
///
/// Returns `None` when the template cannot be filled. The error is not
/// displayed: wording errors must not echo a parameter value, and this helper
/// does not need to.
pub fn render_finding(finding: &Finding, lang: Lang) -> Option<String> {
    let pairs: Vec<(&str, &str)> = finding
        .params
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();
    render(finding.wording_id, &pairs, lang).ok()
}

/// `true` when `text` contains a forbidden substring from the task card.
pub fn contains_forbidden(text: &str) -> bool {
    FORBIDDEN.iter().any(|ban| text.contains(ban))
}
