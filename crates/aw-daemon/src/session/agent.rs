//! Agent label for a session (P5-AGENT-01).
//!
//! The label does not change what is collected. Scope stays with launch or
//! attach. This module does not write the database and does not spawn processes.

use aw_agent_adapters::{identify, Inference, ProcInfo};

/// Why the session got this agent id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnnotationBasis {
    /// The caller passed an id (`--agent <id>`). It wins over matching.
    Explicit,
    /// [`identify`] matched the root or a process in the next two layers.
    Inferred,
}

/// What the session should record. Not a finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentAnnotation {
    /// Profile id, or the explicit id the caller passed.
    pub id: String,
    /// Evidence letter. Inferred matches are `"I"` ([`Inference`]).
    ///
    /// An explicit id is not a process-shape inference. It is still stored as
    /// `"I"` so this card cannot present it as a stronger level. [`AgentAnnotation::basis`]
    /// is what distinguishes the two.
    pub evidence: &'static str,
    /// Explicit request, or a profile match.
    pub basis: AnnotationBasis,
}

/// Label the session from an explicit id, or from the root and two child layers.
///
/// A blank `explicit` is treated as absent. Any other value is returned as
/// given and the processes are not consulted.
///
/// Automatic order is `root`, then `children`, then `grandchildren`. The first
/// match wins, so a nested tool does not override the root. The root is matched
/// with no ancestors. Each child is matched with the root as its immediate
/// parent. Grandchildren are a flat list, so their immediate parent is unknown
/// and they are matched with an empty ancestor list.
pub fn annotate_session(
    explicit: Option<&str>,
    root: &ProcInfo,
    children: &[ProcInfo],
    grandchildren: &[ProcInfo],
) -> Option<AgentAnnotation> {
    if let Some(id) = explicit.map(str::trim).filter(|id| !id.is_empty()) {
        return Some(AgentAnnotation {
            id: id.to_owned(),
            evidence: Inference::I.as_str(),
            basis: AnnotationBasis::Explicit,
        });
    }

    let parent = [root.clone()];
    let matched = identify(root, &[])
        .or_else(|| children.iter().find_map(|child| identify(child, &parent)))
        .or_else(|| grandchildren.iter().find_map(|grand| identify(grand, &[])));

    matched.map(|hit| AgentAnnotation {
        id: hit.profile_id,
        evidence: hit.evidence.as_str(),
        basis: AnnotationBasis::Inferred,
    })
}
