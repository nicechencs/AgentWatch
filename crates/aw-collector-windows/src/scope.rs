//! Launch-mode scope notes and the attach snapshot (P1-WIN-04).
//!
//! This module does not call Win32. It does not create a process, open a Job
//! Object, or duplicate a handle. The CLI launch state machine lives in
//! `aw-cli` (`launch/windows.rs`) and talks to the OS only through a trait the
//! default tests replace with a fake.
//!
//! # What was measured
//!
//! SPIKE-05 (this machine, 2026-10-07, ordinary user) created an unnamed Job,
//! started `cmd.exe` with `CREATE_SUSPENDED`, assigned it, and resumed it.
//! The child and its grandchildren (`PING.EXE`, `conhost.exe`) stayed in that
//! Job. `JOB_OBJECT_LIMIT_BREAKAWAY_OK` was not set. That path needs no
//! administrator.
//!
//! Still 【待验证】, and therefore not implemented as a live call here:
//!
//! - `DuplicateHandle` of the Job into the daemon, and named Jobs.
//! - `JobObjectAssociateCompletionPortInformation` and
//!   `JOB_OBJECT_MSG_NEW_PROCESS` / `JOB_OBJECT_MSG_EXIT_PROCESS`.
//! - Nested Jobs (Chrome, VS Code, Node) and whether forbidding breakaway
//!   makes those programs fail.
//! - `CreateToolhelp32Snapshot` on a live process table.
//!
//! # Attach
//!
//! [`build_attach_tree`] is the pure half of windows.md §4.2. The caller hands
//! it rows a snapshot would have returned (`pid`, `ppid`, `create_time`). A
//! child is included only when its parent's `CreateTime` is strictly earlier.
//! A reused pid whose current owner started later (or at the same tick) is
//! left out and recorded as [`ExcludedReason::ParentCreateTimeNotEarlier`],
//! the same strict-earlier rule the ETW parent cache uses.
//!
//! The tree is a list of members. Nothing here assigns an already-running
//! process to a Job. windows.md §4.2 forbids that: a Job would change the
//! target's behaviour. [`AttachPlan::job_assigned`] is always `false`.
//!
//! Evidence of a snapshot row is [`Evidence::S`] (P1-DAEMON-04). A row whose
//! `create_time` is missing stays in the tree when the parent link is
//! otherwise known, but its start time is [`Evidence::NA`] with
//! [`NaReason::Preexisting`]: `0` is not used as "unknown".

use aw_core::{Evidence, NaReason, ProcUid};

/// Fixed session annotation when the operator opts into breakaway.
///
/// windows.md §4.1 does not set `JOB_OBJECT_LIMIT_BREAKAWAY_OK`. SPIKE-05 did
/// not measure whether forbidding breakaway breaks Chrome or VS Code, so the
/// option exists, and turning it on is recorded with this sentence rather than
/// a claim that the scope is still complete.
pub const BREAKAWAY_INCOMPLETE_NOTE: &str = "范围可能不完整";

/// Default: the Job does not allow `CREATE_BREAKAWAY_FROM_JOB`.
///
/// SPIKE-05 ran with this off (`breakaway_ok=false`, `silent_breakaway_ok=false`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakawayPolicy {
    /// `JOB_OBJECT_LIMIT_BREAKAWAY_OK` is not set.
    Forbidden,
    /// Operator passed `--allow-breakaway`. Descendants may leave the Job.
    Allowed {
        /// Always [`BREAKAWAY_INCOMPLETE_NOTE`].
        session_note: &'static str,
    },
}

impl BreakawayPolicy {
    /// Policy for one launch. `allow` is the `--allow-breakaway` flag.
    #[must_use]
    pub const fn from_flag(allow: bool) -> Self {
        if allow {
            Self::Allowed {
                session_note: BREAKAWAY_INCOMPLETE_NOTE,
            }
        } else {
            Self::Forbidden
        }
    }

    /// `true` when descendants are permitted to leave the Job.
    #[must_use]
    pub const fn allows_breakaway(self) -> bool {
        matches!(self, Self::Allowed { .. })
    }

    /// Session annotation. `None` when breakaway stays forbidden.
    #[must_use]
    pub const fn session_note(self) -> Option<&'static str> {
        match self {
            Self::Forbidden => None,
            Self::Allowed { session_note } => Some(session_note),
        }
    }
}

/// One process a Toolhelp-style snapshot reported.
///
/// `create_time` is the platform's `CreateTime` in the same unit for every row
/// (FILETIME 100-ns ticks, the unit the ETW decoder stores). `None` means the
/// snapshot did not carry a time. It is not `0`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotProcess {
    /// OS pid.
    pub pid: u32,
    /// Parent pid, when the snapshot had one.
    pub ppid: Option<u32>,
    /// `CreateTime`. `None` is "not observed".
    pub create_time: Option<i64>,
    /// Identity the caller already computed, when it had both pid and time.
    ///
    /// `None` when the caller could not hash an identity (missing time, or a
    /// boot id the hasher rejected). This module does not invent one.
    pub uid: Option<ProcUid>,
}

/// Why a row was not added to the attach tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExcludedReason {
    /// A row exists for the parent pid, but its `CreateTime` is not strictly
    /// earlier than the child's. ADR-0007: that pid was reused.
    ParentCreateTimeNotEarlier,
    /// The child has no `CreateTime`, so the reuse check cannot be made.
    ///
    /// The row is not included. Guessing "it is a child" would hide a reused pid.
    ParentCreateTimeMissing,
}

/// One process the attach plan keeps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachMember {
    /// OS pid.
    pub pid: u32,
    /// Parent pid. `None` on the root.
    pub ppid: Option<u32>,
    /// `ProcUid` when the caller supplied one.
    pub uid: Option<ProcUid>,
    /// Start time the snapshot reported. `None` is unknown, not the epoch.
    pub create_time: Option<i64>,
    /// Evidence of the membership. Always [`Evidence::S`]: a snapshot, not an
    /// ETW event at the moment of creation (P1-DAEMON-04).
    pub membership: Evidence,
    /// Evidence of `create_time`. [`Evidence::S`] when the snapshot had a time,
    /// [`Evidence::NA`] with [`NaReason::Preexisting`] when it did not.
    pub start_time: Evidence,
}

/// A row the walk saw and refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExcludedProcess {
    /// OS pid.
    pub pid: u32,
    /// Parent pid the snapshot named, when it named one.
    pub ppid: Option<u32>,
    /// Why the row is not a member.
    pub reason: ExcludedReason,
}

/// Result of walking one snapshot.
///
/// `job_assigned` is `false`. Attaching does not put a running process into a
/// Job (windows.md §4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachPlan {
    /// The root the caller named.
    pub root_pid: u32,
    /// Root first, then descendants in first-seen order.
    pub members: Vec<AttachMember>,
    /// Rows that named a parent inside the walked set but failed the
    /// `CreateTime` check. Rows that are simply outside the tree are not listed:
    /// they were never candidates.
    pub excluded: Vec<ExcludedProcess>,
    /// Always `false`. See the struct note.
    pub job_assigned: bool,
}

/// Why [`build_attach_tree`] returned no plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttachError {
    /// `root_pid` is not in `rows`.
    RootNotFound { pid: u32 },
}

impl std::fmt::Display for AttachError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RootNotFound { pid } => {
                write!(f, "pid {pid} is not in the snapshot")
            }
        }
    }
}

impl std::error::Error for AttachError {}

/// Build the attach tree from a snapshot.
///
/// `rows` is the process list. Order is the order a caller wants ties broken;
/// the walk itself is parent-before-child via a queue, starting at `root_pid`.
///
/// A child is included only when every hop from the root has a parent
/// `CreateTime` strictly earlier than the child. A failed hop is recorded in
/// [`AttachPlan::excluded`] and its descendants are not walked: a reused pid
/// must not pull a stranger's children into the session.
///
/// Does not assign a Job. [`AttachPlan::job_assigned`] is `false`.
///
/// # Errors
///
/// [`AttachError::RootNotFound`] when `root_pid` is absent from `rows`.
pub fn build_attach_tree(
    rows: &[SnapshotProcess],
    root_pid: u32,
) -> Result<AttachPlan, AttachError> {
    let root = rows.iter().find(|row| row.pid == root_pid);
    let Some(root) = root else {
        return Err(AttachError::RootNotFound { pid: root_pid });
    };

    let mut members = Vec::new();
    let mut excluded = Vec::new();
    members.push(member_of(root, None));

    // Indices of rows already decided (member or excluded), so a cycle cannot
    // walk forever. The root is decided.
    let mut decided = vec![root_pid];
    let mut frontier = vec![root_pid];

    while let Some(parent_pid) = frontier.pop() {
        let parent_time = rows
            .iter()
            .find(|row| row.pid == parent_pid)
            .and_then(|row| row.create_time);

        for row in rows {
            if row.pid == parent_pid || decided.contains(&row.pid) {
                continue;
            }
            if row.ppid != Some(parent_pid) {
                continue;
            }
            decided.push(row.pid);
            match parent_link_ok(parent_time, row.create_time) {
                ParentCheck::Earlier => {
                    members.push(member_of(row, Some(parent_pid)));
                    frontier.push(row.pid);
                }
                ParentCheck::NotEarlier => {
                    excluded.push(ExcludedProcess {
                        pid: row.pid,
                        ppid: Some(parent_pid),
                        reason: ExcludedReason::ParentCreateTimeNotEarlier,
                    });
                }
                ParentCheck::Missing => {
                    excluded.push(ExcludedProcess {
                        pid: row.pid,
                        ppid: Some(parent_pid),
                        reason: ExcludedReason::ParentCreateTimeMissing,
                    });
                }
            }
        }
    }

    Ok(AttachPlan {
        root_pid,
        members,
        excluded,
        job_assigned: false,
    })
}

fn member_of(row: &SnapshotProcess, ppid: Option<u32>) -> AttachMember {
    let start_time = if row.create_time.is_some() {
        Evidence::S
    } else {
        Evidence::NA(NaReason::Preexisting)
    };
    AttachMember {
        pid: row.pid,
        ppid,
        uid: row.uid,
        create_time: row.create_time,
        membership: Evidence::S,
        start_time,
    }
}

#[derive(Clone, Copy)]
enum ParentCheck {
    Earlier,
    NotEarlier,
    Missing,
}

/// Strictly earlier. Equal ticks are not earlier: ADR-0007 treats a same-tick
/// parent as a reused pid, matching the ETW parent-cache check.
fn parent_link_ok(parent: Option<i64>, child: Option<i64>) -> ParentCheck {
    match (parent, child) {
        (Some(parent), Some(child)) if parent < child => ParentCheck::Earlier,
        (Some(_), Some(_)) => ParentCheck::NotEarlier,
        _ => ParentCheck::Missing,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn row(pid: u32, ppid: Option<u32>, create_time: Option<i64>) -> SnapshotProcess {
        SnapshotProcess {
            pid,
            ppid,
            create_time,
            uid: None,
        }
    }

    #[test]
    fn parent_create_time_must_be_strictly_earlier() {
        let rows = vec![
            row(10, None, Some(100)),
            row(11, Some(10), Some(200)),
            row(12, Some(11), Some(150)),
            row(13, Some(11), Some(200)),
            row(14, Some(12), Some(400)),
        ];
        let plan = build_attach_tree(&rows, 10).expect("root present");
        let pids: Vec<u32> = plan.members.iter().map(|member| member.pid).collect();
        assert_eq!(pids, vec![10, 11]);
        assert!(plan
            .members
            .iter()
            .all(|member| member.membership == Evidence::S));
        assert_eq!(
            plan.excluded,
            vec![
                ExcludedProcess {
                    pid: 12,
                    ppid: Some(11),
                    reason: ExcludedReason::ParentCreateTimeNotEarlier,
                },
                ExcludedProcess {
                    pid: 13,
                    ppid: Some(11),
                    reason: ExcludedReason::ParentCreateTimeNotEarlier,
                },
            ]
        );
        // 14's parent was itself excluded, so 14 is not pulled in on a reused pid.
        assert!(!plan.members.iter().any(|member| member.pid == 14));
        assert!(!plan.excluded.iter().any(|item| item.pid == 14));
        assert!(!plan.job_assigned);
    }

    #[test]
    fn missing_create_time_is_na_preexisting_and_blocks_the_link() {
        let rows = vec![
            row(1, None, Some(10)),
            row(2, Some(1), None),
            row(3, Some(1), Some(20)),
        ];
        let plan = build_attach_tree(&rows, 1).expect("root present");
        assert_eq!(plan.members.len(), 2);
        assert_eq!(plan.members[1].pid, 3);
        assert_eq!(plan.members[1].start_time, Evidence::S);
        assert_eq!(
            plan.excluded,
            vec![ExcludedProcess {
                pid: 2,
                ppid: Some(1),
                reason: ExcludedReason::ParentCreateTimeMissing,
            }]
        );
    }

    #[test]
    fn root_without_create_time_stays_and_marks_start_na() {
        let rows = vec![row(7, None, None)];
        let plan = build_attach_tree(&rows, 7).expect("root present");
        assert_eq!(plan.members.len(), 1);
        assert_eq!(plan.members[0].create_time, None);
        assert_eq!(
            plan.members[0].start_time,
            Evidence::NA(NaReason::Preexisting)
        );
        assert_eq!(plan.members[0].membership, Evidence::S);
        assert!(!plan.job_assigned);
    }

    #[test]
    fn missing_root_is_an_error() {
        let err = build_attach_tree(&[row(1, None, Some(1))], 9).expect_err("no root");
        assert_eq!(err, AttachError::RootNotFound { pid: 9 });
    }

    #[test]
    fn breakaway_flag_annotates_the_session() {
        assert_eq!(BreakawayPolicy::from_flag(false).session_note(), None);
        assert!(!BreakawayPolicy::from_flag(false).allows_breakaway());
        assert_eq!(
            BreakawayPolicy::from_flag(true).session_note(),
            Some(BREAKAWAY_INCOMPLETE_NOTE)
        );
        assert!(BreakawayPolicy::from_flag(true).allows_breakaway());
    }
}
