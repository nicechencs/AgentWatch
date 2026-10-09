//! Correlation that the declarative rule engine cannot express (P5-PIPE-01).
//!
//! [`self_report`] aligns Agent self-reports (E3) with system observations and
//! returns findings plus annotations. It is a pure function: no I/O, no clock
//! reads, no payload logging. The alignment itself is always inference (`I`).
//! A `self_report_mismatch` finding copies the rule's declared level (`E1`)
//! for the fact "an observation exists and the self-report does not", and never
//! upgrades the alignment to that level.
//!
//! The built-in rule `rules/self_report_mismatch.toml` stays as the engine
//! declaration (id, evidence, wording). Path, argv-prefix, and domain comparison
//! do not fit that engine's `where` grammar, so they live here.

pub mod self_report;

pub use self_report::{
    align, align_with_evidence, contains_forbidden, render_finding, AlignError, AlignOutput,
    Alignment, Annotation, EvidencedObservation, FileAccessObs, Finding, GapInterval, NetObs,
    Observation, ObservationKind, ProcessStartObs, SelfReport, SelfReportSummary, SummaryKey,
    ToolKind, Unclassified, UnclassifiedReason, WindowConfig, DEFAULT_WINDOW_NS,
    INCOMPLETE_SELF_REPORT, UNOBSERVED, WORDING_ID,
};
