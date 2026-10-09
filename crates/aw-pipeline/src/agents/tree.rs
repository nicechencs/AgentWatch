//! Instance tree. The parent of an instance is the nearest ancestor **instance**,
//! not the nearest process. A `node` between Claude Code and an MCP server does
//! not become an instance and does not break the ancestor walk: the walk uses
//! `ProcUid` parent links recorded for every considered process.

use std::collections::HashMap;
use std::fmt;

use aw_core::ProcUid;

use super::role::{AgentRole, EVIDENCE_STR, SOURCE_STR};

/// Evidence string on every draft. Always `"I"`.
pub const EVIDENCE: &str = EVIDENCE_STR;

/// Source string on every draft. Always `"pipeline.agents/identify"`.
pub const SOURCE: &str = SOURCE_STR;

/// One recognized instance, shaped like `aw_store::AgentInstanceInsert` plus
/// the human label the store table does not have yet.
///
/// `evidence` is always [`EVIDENCE`]. `label` is the human override text and
/// does not replace `role`. Both are kept.
///
/// This struct does not derive `Debug` in a way that could grow an argv field
/// later without review: the fields here are ids, role names, and the label
/// the user typed. The label is a name, not argv; it is still not printed,
/// because a user can paste a command line into it.
pub struct AgentInstanceDraft {
    /// Session the caller is replaying. Not assigned by this module.
    pub session_id: i64,
    /// `ProcUid` bit-cast the same way the store expects (`as i64`).
    pub proc_uid: i64,
    /// OS pid, so a later card can join events. Not a store column.
    pub pid: u32,
    /// Profile id when this process matched an agent profile.
    ///
    /// For an MCP server or tool child this is the **parent** profile that
    /// supplied the role rule, not a separate `mcp-server` profile. `None`
    /// when no profile id was available (should not happen for a real match).
    pub profile_id: Option<String>,
    /// Inferred role. Not overwritten by [`apply_label`].
    pub role: AgentRole,
    /// Nearest ancestor instance, once the caller has stored this draft and
    /// knows the row id. `None` for a primary, or when the parent draft has
    /// not been inserted yet — see [`AgentInstanceDraft::parent_proc_uid`].
    pub parent_instance_id: Option<i64>,
    /// `ProcUid` of the parent instance, when there is one.
    ///
    /// The store wants a row id. This module does not insert rows, so the
    /// parent is named by process identity. A later card maps it to
    /// `parent_instance_id` after insert.
    pub parent_proc_uid: Option<ProcUid>,
    /// Always [`EVIDENCE`] (`"I"`).
    pub evidence: &'static str,
    /// Always [`SOURCE`].
    pub source: &'static str,
    /// Human annotation. `None` until [`apply_label`]. Does not change `role`
    /// or `evidence`.
    pub label: Option<String>,
}

impl PartialEq for AgentInstanceDraft {
    fn eq(&self, other: &Self) -> bool {
        self.session_id == other.session_id
            && self.proc_uid == other.proc_uid
            && self.pid == other.pid
            && self.profile_id == other.profile_id
            && self.role == other.role
            && self.parent_instance_id == other.parent_instance_id
            && self.parent_proc_uid == other.parent_proc_uid
            && self.evidence == other.evidence
            && self.source == other.source
            && self.label == other.label
    }
}

impl Eq for AgentInstanceDraft {}

impl fmt::Debug for AgentInstanceDraft {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentInstanceDraft")
            .field("session_id", &self.session_id)
            .field("proc_uid", &self.proc_uid)
            .field("pid", &self.pid)
            .field("profile_id", &self.profile_id)
            .field("role", &self.role)
            .field("parent_instance_id", &self.parent_instance_id)
            .field("parent_proc_uid", &self.parent_proc_uid)
            .field("evidence", &self.evidence)
            .field("source", &self.source)
            .field(
                "label",
                &self
                    .label
                    .as_ref()
                    .map(|text| format!("<redacted len={}>", text.len())),
            )
            .finish()
    }
}

impl AgentInstanceDraft {
    pub(crate) fn new(
        session_id: i64,
        proc_uid: ProcUid,
        pid: u32,
        profile_id: Option<String>,
        role: AgentRole,
        parent_proc_uid: Option<ProcUid>,
    ) -> Self {
        Self {
            session_id,
            proc_uid: proc_uid_as_i64(proc_uid),
            pid,
            profile_id,
            role,
            parent_instance_id: None,
            parent_proc_uid,
            evidence: EVIDENCE,
            source: SOURCE,
            label: None,
        }
    }
}

/// Record a human label without changing the inferred role or the evidence.
///
/// The card says a manual correction is stored in `label`. The inferred `role`
/// stays so a reader can see both. Empty or whitespace-only text is refused:
/// an unknown label is `None`, not `""`.
///
/// Returns `false` when `label` is empty. The draft is unchanged in that case.
pub fn apply_label(instance: &mut AgentInstanceDraft, label: &str) -> bool {
    let trimmed = label.trim();
    if trimmed.is_empty() {
        return false;
    }
    instance.label = Some(trimmed.to_owned());
    // Role and evidence are intentionally not assigned here.
    debug_assert_eq!(instance.evidence, EVIDENCE);
    instance.evidence = EVIDENCE;
    instance.source = SOURCE;
    true
}

/// Processes seen in one session, and the instances recognized among them.
///
/// Insert order is call order. A later `ProcessStart` can name an earlier
/// process as parent. A process that is not an instance is still remembered,
/// so the walk can step through it to the nearest ancestor instance.
pub struct AgentTree {
    session_id: i64,
    /// Every considered process: uid → parent uid (if the event had one).
    parents: HashMap<ProcUid, Option<ProcUid>>,
    /// uid → index in `instances`, for processes that became instances.
    by_uid: HashMap<ProcUid, usize>,
    instances: Vec<AgentInstanceDraft>,
}

impl AgentTree {
    /// Empty tree for `session_id`.
    pub fn new(session_id: i64) -> Self {
        Self {
            session_id,
            parents: HashMap::new(),
            by_uid: HashMap::new(),
            instances: Vec::new(),
        }
    }

    /// Session this tree was built for.
    pub fn session_id(&self) -> i64 {
        self.session_id
    }

    /// Recognized instances, in the order they were added.
    pub fn instances(&self) -> &[AgentInstanceDraft] {
        &self.instances
    }

    /// Draft for `uid`, if that process was recognized.
    pub fn get(&self, uid: ProcUid) -> Option<&AgentInstanceDraft> {
        self.by_uid.get(&uid).map(|index| &self.instances[*index])
    }

    /// Mutable draft. Used by [`apply_label`] callers.
    pub fn get_mut(&mut self, uid: ProcUid) -> Option<&mut AgentInstanceDraft> {
        let index = *self.by_uid.get(&uid)?;
        self.instances.get_mut(index)
    }

    /// Remember `uid`'s parent even when `uid` is not an instance.
    ///
    /// A second observation for the same uid does not overwrite a known parent
    /// with `None`.
    pub(crate) fn note_process(&mut self, uid: ProcUid, parent: Option<ProcUid>) {
        self.parents.entry(uid).or_insert(parent);
    }

    /// Nearest ancestor that is already an instance.
    ///
    /// Walks parent links. Stops on a cycle or when the parent was never noted.
    /// A parent that was noted but is not an instance is skipped (the plain
    /// `node` case).
    pub fn nearest_ancestor_instance(&self, uid: ProcUid) -> Option<ProcUid> {
        let mut cursor = self.parents.get(&uid).copied().flatten();
        let mut guard = 0u32;
        while let Some(parent) = cursor {
            if self.by_uid.contains_key(&parent) {
                return Some(parent);
            }
            guard = guard.saturating_add(1);
            if guard > 65_536 {
                return None;
            }
            let next = self.parents.get(&parent).copied().flatten();
            if next == Some(parent) || next == Some(uid) {
                return None;
            }
            cursor = next;
        }
        None
    }

    /// Push a draft. Returns `false` when `uid` is already an instance.
    ///
    /// The existing draft is left as-is. A second `ProcessStart` for the same
    /// uid is not a silent drop of the event: the caller still has the first
    /// draft, and [`super::consider_start`] reports
    /// [`super::Considered::Skipped`] ([`super::NotInstanceReason::Duplicate`]).
    pub(crate) fn insert(&mut self, draft: AgentInstanceDraft) -> bool {
        let uid = proc_uid_from_i64(draft.proc_uid);
        if self.by_uid.contains_key(&uid) {
            return false;
        }
        let index = self.instances.len();
        self.by_uid.insert(uid, index);
        self.instances.push(draft);
        true
    }
}

pub(crate) fn proc_uid_as_i64(uid: ProcUid) -> i64 {
    uid.0 as i64
}

pub(crate) fn proc_uid_from_i64(bits: i64) -> ProcUid {
    ProcUid(bits as u64)
}
