//! One `ProcessStart` reduced to the fields recognition is allowed to use.
//!
//! Argv is borrowed. [`ProcessObservation`] does not derive `Debug`: a derived
//! impl would print argv. [`ProcessObservation::summary`] prints lengths only.

use std::fmt;

use aw_core::ProcUid;

/// Fields copied off a `ProcessStart` (and its event envelope) by the caller.
///
/// This crate does not read `/proc` or the event stream. `stdio_is_pipe` is
/// not on `ProcessStart`; the caller supplies it when a collector observed
/// the standard streams. `None` means unknown, not "not a pipe".
pub struct ProcessObservation<'a> {
    /// `ProcUid` of the new process.
    pub proc_uid: ProcUid,
    /// OS pid. Not used to invent a parent.
    pub pid: u32,
    /// OS parent pid from `ProcessStart.ppid`.
    ///
    /// `0` is a real ppid (the kernel's idle/init parent on some systems), not
    /// a stand-in for unknown. Unknown parent identity is [`Self::parent_uid`]
    /// `= None`.
    pub ppid: u32,
    /// Parent `ProcUid` when the event carried one.
    pub parent_uid: Option<ProcUid>,
    /// Executable path, when present. Only the file name is inspected.
    pub exe: Option<&'a str>,
    /// Argv elements, when the event carried them. Not joined.
    pub argv: Option<&'a [aw_core::Arg]>,
    /// `Some(true)` / `Some(false)` only when stdio was observed.
    ///
    /// `None` means the collector did not report it. Role assignment must not
    /// treat that as "not a pipe".
    pub stdio_is_pipe: Option<bool>,
}

impl ProcessObservation<'_> {
    /// Log form. Argv and exe text are lengths, never the strings.
    pub fn summary(&self) -> ObservationSummary {
        ObservationSummary {
            proc_uid: self.proc_uid,
            pid: self.pid,
            ppid: self.ppid,
            parent_known: self.parent_uid.is_some(),
            exe_len: self.exe.map(str::len),
            argc: self.argv.map(<[_]>::len),
            stdio_is_pipe: self.stdio_is_pipe,
        }
    }
}

/// Length-only view. Safe to log with `{:?}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservationSummary {
    /// Process identity.
    pub proc_uid: ProcUid,
    /// OS pid.
    pub pid: u32,
    /// OS parent pid.
    pub ppid: u32,
    /// Whether `parent_uid` was `Some`.
    pub parent_known: bool,
    /// Exe path length, or unknown.
    pub exe_len: Option<usize>,
    /// Argv length, or unknown.
    pub argc: Option<usize>,
    /// Observed stdio, or unknown.
    pub stdio_is_pipe: Option<bool>,
}

impl fmt::Debug for ProcessObservation<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.summary().fmt(f)
    }
}
