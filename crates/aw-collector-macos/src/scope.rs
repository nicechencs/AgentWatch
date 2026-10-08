//! Fork-chain scope tracking for the macOS collector (P1-MAC-03, macos.md §4).
//!
//! macOS has no public container that automatically covers descendants, so the
//! daemon follows the process tree. This module is the decision, not the
//! collector: it does not subscribe to Endpoint Security, does not mute, and
//! does not call libproc. OS enumeration sits behind [`ChildList`]. Tests pass
//! a fake and run on every host, including Windows.
//!
//! # Fork
//!
//! [`on_fork`] adds the child only when the parent is already in the set
//! (CAP-SCOPE-01). A parent outside the set leaves the child out.
//!
//! # Unknown pid
//!
//! An event whose pid is not in the set is not dropped. [`on_unknown_pid`]
//! returns [`ScopeAction::Pending`] with [`PENDING_HOLD`] (200 ms). The
//! pipeline's pending buffer is a later card; this module only names the hold.
//!
//! # Attribution break
//!
//! A child whose parent is launchd (`ppid == 1` and marked launchd) is not a
//! fork of the session. If `responsible_pid` names a process that is in scope,
//! the child is added at [`aw_core::Evidence::I`] (macos.md §4.3: launchd
//! spawned it, the responsible process is still the target). Otherwise the
//! decision is [`ScopeAction::AttributionBreak`] with [`LINK_BROKEN_NOTE`]
//! (CAP-SCOPE-03). That child is not added and is not recorded as E1.
//! `open -a` is that second case: launchd is the parent and the responsible
//! pid is outside the set.
//!
//! # Attach
//!
//! [`attach_snapshot`] walks [`ChildList`] depth-first from the roots, in the
//! order the trait returns children. A pid already seen is not visited again.

use std::collections::BTreeSet;
use std::time::Duration;

use aw_core::Evidence;

/// How long an event for an unknown pid is held before the pipeline decides.
///
/// macos.md §4: eslogger is asynchronous, so a child's first events can arrive
/// before the fork. The pipeline pending buffer (not this module) holds them
/// for this long and may also match on `ppid`.
pub const PENDING_HOLD: Duration = Duration::from_millis(200);

/// Fixed note for CAP-SCOPE-03 when the fork chain stops at launchd and the
/// responsible pid is not in scope. Not an E1 attribution.
pub const LINK_BROKEN_NOTE: &str = "链路中断";

/// launchd's pid. A parent at this pid counts as launchd only when the caller
/// also sets [`ForkParent::launchd`].
pub const LAUNCHD_PID: u32 = 1;

/// What the scope set did with one observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeAction {
    /// Parent was in scope. `child_pid` was inserted.
    Added { child_pid: u32 },
    /// Parent was not in scope. The child was not inserted.
    NotInScope { child_pid: u32 },
    /// Pid is not in the set. Hold the event; do not drop it.
    ///
    /// `hold` is always [`PENDING_HOLD`]. The buffer itself is not here.
    Pending { pid: u32, hold: Duration },
    /// launchd parent, and `responsible_pid` is in scope. The child was
    /// inserted. `evidence` is [`Evidence::I`], never [`Evidence::E1`].
    Responsible {
        child_pid: u32,
        responsible_pid: u32,
        evidence: Evidence,
    },
    /// launchd parent, and the responsible pid is missing or outside the set.
    /// The child was not inserted. `note` is [`LINK_BROKEN_NOTE`].
    AttributionBreak { child_pid: u32, note: &'static str },
}

/// Parent of a fork, as the collector already decoded it.
///
/// `launchd` is a separate fact from the pid. `ppid == 1` alone is not enough:
/// pid 1 might be something else, and that is not recorded as launchd.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForkParent {
    pub pid: u32,
    /// True only when this parent was identified as launchd.
    pub launchd: bool,
}

impl ForkParent {
    /// A parent that is not launchd.
    #[must_use]
    pub const fn new(pid: u32) -> Self {
        Self {
            pid,
            launchd: false,
        }
    }

    /// launchd. The pid is [`LAUNCHD_PID`].
    #[must_use]
    pub const fn launchd() -> Self {
        Self {
            pid: LAUNCHD_PID,
            launchd: true,
        }
    }

    /// True when both the marker and the pid say launchd.
    #[must_use]
    pub const fn is_launchd(self) -> bool {
        self.launchd && self.pid == LAUNCHD_PID
    }
}

/// Pids the daemon is following. Membership is the decision input.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScopeSet {
    members: BTreeSet<u32>,
}

impl ScopeSet {
    #[must_use]
    pub fn new() -> Self {
        Self {
            members: BTreeSet::new(),
        }
    }

    /// Insert `pid`. Returns whether it was not already a member.
    pub fn insert(&mut self, pid: u32) -> bool {
        self.members.insert(pid)
    }

    #[must_use]
    pub fn contains(&self, pid: u32) -> bool {
        self.members.contains(&pid)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.members.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// Members in ascending pid order.
    pub fn iter(&self) -> impl Iterator<Item = u32> + '_ {
        self.members.iter().copied()
    }
}

/// If `parent_in_scope`, insert `child_pid` and return [`ScopeAction::Added`].
/// Otherwise return [`ScopeAction::NotInScope`] and leave the set unchanged.
#[must_use]
pub fn on_fork(scope: &mut ScopeSet, parent_in_scope: bool, child_pid: u32) -> ScopeAction {
    if parent_in_scope {
        scope.insert(child_pid);
        ScopeAction::Added { child_pid }
    } else {
        ScopeAction::NotInScope { child_pid }
    }
}

/// An event arrived for `pid` and that pid is not in the set.
///
/// Does not insert. The caller hands the event to the pipeline pending buffer
/// for [`PENDING_HOLD`]. This function does not buffer.
#[must_use]
pub fn on_unknown_pid(pid: u32) -> ScopeAction {
    ScopeAction::Pending {
        pid,
        hold: PENDING_HOLD,
    }
}

/// Decide a process whose parent is outside the ordinary fork chain.
///
/// * Parent is launchd and `responsible_pid` is `Some` and in scope: insert the
///   child and return [`ScopeAction::Responsible`] at [`Evidence::I`].
/// * Parent is launchd and the responsible pid is absent or not in scope:
///   do not insert. Return [`ScopeAction::AttributionBreak`]. This is not E1.
/// * Parent is not launchd: same as [`on_fork`] with `parent_in_scope` taken
///   from the set. `responsible_pid` is ignored on that path.
#[must_use]
pub fn on_attribution(
    scope: &mut ScopeSet,
    parent: ForkParent,
    child_pid: u32,
    responsible_pid: Option<u32>,
) -> ScopeAction {
    if parent.is_launchd() {
        if let Some(responsible) = responsible_pid {
            if scope.contains(responsible) {
                scope.insert(child_pid);
                return ScopeAction::Responsible {
                    child_pid,
                    responsible_pid: responsible,
                    evidence: Evidence::I,
                };
            }
        }
        return ScopeAction::AttributionBreak {
            child_pid,
            note: LINK_BROKEN_NOTE,
        };
    }
    on_fork(scope, scope.contains(parent.pid), child_pid)
}

/// Enumerate children of one pid.
///
/// The production side is `proc_listchildpids` or a `sysinfo` snapshot. Both
/// are macOS calls, so they stay behind this trait. [`attach_snapshot`] only
/// sees what the impl returns. A failure is [`SnapshotError`], never an empty
/// child list standing in for "could not look".
pub trait ChildList {
    /// Direct children of `pid`, in the order the source reported them.
    ///
    /// # Errors
    ///
    /// [`SnapshotError::Unavailable`] when the source could not be read.
    fn children_of(&mut self, pid: u32) -> Result<Vec<u32>, SnapshotError>;
}

/// Why an attach snapshot stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotError {
    /// The child list for `pid` could not be read. Not the same as "no children".
    Unavailable { pid: u32, detail: String },
}

impl std::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable { pid, detail } => {
                write!(f, "child list for pid {pid} is unavailable: {detail}")
            }
        }
    }
}

impl std::error::Error for SnapshotError {}

/// Descendants of `roots`, depth-first and without duplicates.
///
/// A root is not included. A pid already emitted is not walked again, so a
/// cycle in the source does not loop. Children of one pid keep the order
/// [`ChildList::children_of`] returned: the first child is visited, and its
/// whole subtree emitted, before the next sibling. Roots are visited in the
/// order given.
///
/// # Errors
///
/// The first [`SnapshotError`] from the trait. Pids collected before that
/// error are discarded with it; a partial tree is not returned as success.
pub fn attach_snapshot<C: ChildList>(
    children: &mut C,
    roots: &[u32],
) -> Result<Vec<u32>, SnapshotError> {
    let mut ordered = Vec::new();
    let mut seen = BTreeSet::new();
    // Roots are the walk's starting points, never part of the result, and they
    // are queried exactly once even when a descendant names one back.
    for root in roots {
        seen.insert(*root);
    }
    // Pushed back to front: a stack pops the last push first, so the first
    // child reported by `children_of` is the next one visited.
    let mut stack: Vec<u32> = roots.iter().rev().copied().collect();
    while let Some(pid) = stack.pop() {
        let kids = children.children_of(pid)?;
        for child in kids.into_iter().rev() {
            if seen.insert(child) {
                stack.push(child);
            }
        }
        // Record on visit, after the children are stacked, so a node is emitted
        // before its descendants and a shared descendant is queried only once.
        if !roots.contains(&pid) {
            ordered.push(pid);
        }
    }
    Ok(ordered)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Scripted child lists. Missing pid is an empty list, which is "no
    /// children", not an error. `fail_at` is the unavailable case.
    struct FakeChildren {
        edges: Vec<(u32, Vec<u32>)>,
        fail_at: Option<u32>,
        queried: Vec<u32>,
    }

    impl ChildList for FakeChildren {
        fn children_of(&mut self, pid: u32) -> Result<Vec<u32>, SnapshotError> {
            self.queried.push(pid);
            if self.fail_at == Some(pid) {
                return Err(SnapshotError::Unavailable {
                    pid,
                    detail: "scripted".to_owned(),
                });
            }
            Ok(self
                .edges
                .iter()
                .find(|(parent, _)| *parent == pid)
                .map(|(_, kids)| kids.clone())
                .unwrap_or_default())
        }
    }

    #[test]
    fn fork_of_in_scope_parent_is_added() {
        let mut scope = ScopeSet::new();
        scope.insert(10);
        let action = on_fork(&mut scope, true, 11);
        assert_eq!(action, ScopeAction::Added { child_pid: 11 });
        assert!(scope.contains(11));
    }

    #[test]
    fn fork_of_out_of_scope_parent_is_not_added() {
        let mut scope = ScopeSet::new();
        scope.insert(10);
        let action = on_fork(&mut scope, false, 99);
        assert_eq!(action, ScopeAction::NotInScope { child_pid: 99 });
        assert!(!scope.contains(99));
        assert_eq!(scope.len(), 1);
    }

    #[test]
    fn unknown_pid_is_pending_for_200ms() {
        let action = on_unknown_pid(77);
        assert_eq!(
            action,
            ScopeAction::Pending {
                pid: 77,
                hold: Duration::from_millis(200),
            }
        );
        assert_eq!(PENDING_HOLD, Duration::from_millis(200));
    }

    #[test]
    fn responsible_pid_in_scope_is_inference_not_e1() {
        let mut scope = ScopeSet::new();
        scope.insert(10);
        let action = on_attribution(&mut scope, ForkParent::launchd(), 50, Some(10));
        match action {
            ScopeAction::Responsible {
                child_pid,
                responsible_pid,
                evidence,
            } => {
                assert_eq!(child_pid, 50);
                assert_eq!(responsible_pid, 10);
                assert_eq!(evidence, Evidence::I);
                assert_ne!(evidence, Evidence::E1);
            }
            other => panic!("expected responsible inference, got {other:?}"),
        }
        assert!(scope.contains(50));
    }

    #[test]
    fn open_dash_a_is_link_broken_and_not_e1() {
        // `open -a TextEdit`: parent is launchd, responsible pid is not in scope.
        let mut scope = ScopeSet::new();
        scope.insert(10);
        let action = on_attribution(&mut scope, ForkParent::launchd(), 80, Some(3));
        assert_eq!(
            action,
            ScopeAction::AttributionBreak {
                child_pid: 80,
                note: LINK_BROKEN_NOTE,
            }
        );
        assert_eq!(LINK_BROKEN_NOTE, "链路中断");
        assert!(!scope.contains(80));
        // The break variant carries no Evidence::E1. A missing responsible pid
        // is the same break, not a guessed parent.
        let missing = on_attribution(&mut scope, ForkParent::launchd(), 81, None);
        assert_eq!(
            missing,
            ScopeAction::AttributionBreak {
                child_pid: 81,
                note: "链路中断",
            }
        );
        assert!(!scope.contains(81));
    }

    #[test]
    fn ppid_one_without_launchd_marker_is_an_ordinary_fork() {
        let mut scope = ScopeSet::new();
        let parent = ForkParent::new(LAUNCHD_PID);
        assert!(!parent.is_launchd());
        let action = on_attribution(&mut scope, parent, 5, Some(1));
        assert_eq!(action, ScopeAction::NotInScope { child_pid: 5 });
        assert!(!scope.contains(5));
    }

    #[test]
    fn attach_snapshot_is_ordered_and_deduped() {
        // 1 -> 2, 3. 2 -> 4, 3. 3 is listed twice; 4 -> 2 would cycle.
        let mut fake = FakeChildren {
            edges: vec![
                (1, vec![2, 3]),
                (2, vec![4, 3]),
                (4, vec![2]),
                (9, vec![8, 2]),
            ],
            fail_at: None,
            queried: Vec::new(),
        };
        let got = attach_snapshot(&mut fake, &[1, 9]).expect("snapshot");
        assert_eq!(got, vec![2, 4, 3, 8]);
        // 8 is a leaf descendant of 9, so it is enumerated exactly once. It is
        // not skipped: every in-scope pid gets one child-list read.
        assert_eq!(fake.queried, vec![1, 2, 4, 3, 9, 8]);
    }

    #[test]
    fn attach_snapshot_does_not_treat_failure_as_empty() {
        let mut fake = FakeChildren {
            edges: vec![(1, vec![2])],
            fail_at: Some(2),
            queried: Vec::new(),
        };
        let err = attach_snapshot(&mut fake, &[1]).expect_err("unavailable");
        assert_eq!(
            err,
            SnapshotError::Unavailable {
                pid: 2,
                detail: "scripted".to_owned(),
            }
        );
    }
}
