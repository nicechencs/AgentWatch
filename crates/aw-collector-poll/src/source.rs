//! Snapshot sources. The diff never talks to the operating system directly.
//!
//! A [`ProcessSource`] or [`ConnectionSource`] returns one sample. Tests use
//! [`StaticProcessSource`] / [`StaticConnectionSource`], which hand back the
//! vectors the test built. The host adapters live in [`crate::host`] and are not
//! used by tests.

use std::net::SocketAddr;
use std::time::Duration;

use aw_core::{FlowDirection, L4Proto, NaReason};

/// Why one sample could not be read.
///
/// Distinct from an empty sample. An empty `Ok` means "nothing was there".
/// `Err` means the collector could not look, and the caller records a [`aw_core::Gap`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceError {
    /// Gap class for this failure. The message is not stored: it might echo a
    /// path or a command line, and those do not belong in a diagnostic.
    pub kind: SourceFailure,
}

/// Class of a failed sample. Mapped onto [`aw_core::GapKind`] by the collector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceFailure {
    /// The probe could not be reached (command missing, sysinfo refresh failed).
    Disconnected,
    /// The output was not a table this crate understands.
    Parse,
    /// The platform refused the read. This crate does not retry with elevation.
    Permission,
}

impl SourceError {
    pub(crate) const fn disconnected() -> Self {
        Self {
            kind: SourceFailure::Disconnected,
        }
    }

    pub(crate) const fn parse() -> Self {
        Self {
            kind: SourceFailure::Parse,
        }
    }

    #[cfg(windows)]
    pub(crate) const fn permission() -> Self {
        Self {
            kind: SourceFailure::Permission,
        }
    }
}

/// Start time of one process, in the unit the source actually read.
///
/// `Unavailable` is not `0`. A start time of zero seconds since the unix epoch is
/// a real instant and must be passed as [`ProcessStartTime::UnixSeconds`] if a
/// source truly observed it. `sysinfo` reports `0` when it could not read the
/// start time; that adapter maps `0` to `Unavailable` and does not hash it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProcessStartTime {
    /// Whole seconds since the unix epoch. Coarser than the 10 ms identity bucket.
    UnixSeconds(u64),
    /// The source listed the process and could not read when it started.
    Unavailable,
}

/// One process row. Strings are owned because the source may not outlive the diff.
///
/// Tests build these from fixed literals. A live adapter must not log them: `exe`
/// and `argv` are command lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessRow {
    /// Process id as the platform reported it.
    pub pid: u32,
    /// Parent process id. `None` when the source has no parent, not `0`.
    pub ppid: Option<u32>,
    /// When the process started, or [`ProcessStartTime::Unavailable`].
    pub start: ProcessStartTime,
    /// Executable path. `None` when the source could not read it (not `""`).
    pub exe: Option<String>,
    /// Argv. `None` when the source could not read it. An empty `Vec` would mean
    /// "the process was observed to have no arguments", which a poll source cannot
    /// claim, so the live adapter uses `None` for a missing command line.
    pub argv: Option<Vec<String>>,
    /// Working directory. `None` when unreadable.
    pub cwd: Option<String>,
    /// User id as text (uid or SID). The display name is not collected.
    pub user_id: Option<String>,
}

impl ProcessRow {
    /// Row with only pid, parent, and start time. Every other field is unavailable.
    pub fn bare(pid: u32, ppid: Option<u32>, start: ProcessStartTime) -> Self {
        Self {
            pid,
            ppid,
            start,
            exe: None,
            argv: None,
            cwd: None,
            user_id: None,
        }
    }
}

/// One process sample. `boot_id` is the opaque boot identity shared by the sample.
///
/// `None` means this host could not name the boot. Callers then do not invent one
/// and do not hash an empty slice: an empty boot id is a real hash input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessSnapshot {
    /// Opaque boot id bytes. `None` when the platform helper has no boot id.
    pub boot_id: Option<Vec<u8>>,
    /// Processes visible in this sample.
    pub rows: Vec<ProcessRow>,
}

impl ProcessSnapshot {
    /// Snapshot with a known boot id.
    pub fn new(boot_id: impl Into<Vec<u8>>, rows: Vec<ProcessRow>) -> Self {
        Self {
            boot_id: Some(boot_id.into()),
            rows,
        }
    }

    /// Snapshot whose boot id could not be read.
    pub fn without_boot_id(rows: Vec<ProcessRow>) -> Self {
        Self {
            boot_id: None,
            rows,
        }
    }
}

/// Reads one process sample.
pub trait ProcessSource {
    /// List processes once. Does not start a timer.
    ///
    /// # Errors
    ///
    /// [`SourceError`] when the sample could not be taken. An empty process list
    /// is `Ok`, not an error.
    fn snapshot(&mut self) -> Result<ProcessSnapshot, SourceError>;

    /// Tell a live source which pids the next [`snapshot`](Self::snapshot) should refresh.
    ///
    /// `None` means a full enumeration. `Some(&[])` means do not touch the process
    /// table. `Some(pids)` means return those pids and every descendant of them,
    /// including children that did not exist at the previous sample.
    ///
    /// The default is a no-op. [`StaticProcessSource`] ignores it and still returns
    /// the scripted table, so tests can inject a child the collector has not seen
    /// yet. The host adapter uses it to skip the scan entirely in launch mode and to
    /// return only the watched subtree otherwise.
    fn set_restrict(&mut self, _restrict: Option<&[u32]>) {}
}

/// Process source that returns a fixed sequence of snapshots, then repeats the last.
///
/// The first call returns the first snapshot. This is what tests use. It never
/// reads the host process table.
#[derive(Debug, Clone)]
pub struct StaticProcessSource {
    pending: Vec<ProcessSnapshot>,
    last: Option<ProcessSnapshot>,
}

impl StaticProcessSource {
    /// Snapshots in the order `snapshot` will return them.
    pub fn new(snapshots: impl IntoIterator<Item = ProcessSnapshot>) -> Self {
        Self {
            pending: snapshots.into_iter().collect(),
            last: None,
        }
    }
}

impl ProcessSource for StaticProcessSource {
    fn snapshot(&mut self) -> Result<ProcessSnapshot, SourceError> {
        if !self.pending.is_empty() {
            let next = self.pending.remove(0);
            self.last = Some(next.clone());
            return Ok(next);
        }
        match &self.last {
            Some(last) => Ok(last.clone()),
            None => Err(SourceError::disconnected()),
        }
    }
}

/// One connection row from a table that has no byte counters.
///
/// `bytes` is absent from this type. A source that does not read counters cannot
/// accidentally report `0`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionRow {
    /// Owning process, when the table has a pid column. `None` if that column is missing.
    pub pid: Option<u32>,
    /// Transport. UDP and TCP are the only protocols `netstat -ano` names here.
    pub proto: L4Proto,
    /// Local endpoint.
    pub local: SocketAddr,
    /// Remote endpoint. `None` for a listening socket, which is not a flow.
    pub remote: Option<SocketAddr>,
    /// Direction if the table states it. A poll of an established row does not
    /// know who connected, so the usual value is [`FlowDirection::Unknown`].
    pub direction: FlowDirection,
    /// Platform socket id (inode). `None` on Windows `netstat -ano`, which has none.
    pub sock_id: Option<u64>,
    /// `true` when the row is a listener. Listeners are not emitted as connections.
    pub listening: bool,
}

/// One connection sample.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ConnectionSnapshot {
    /// Rows from this sample, including listeners. The diff drops listeners.
    pub rows: Vec<ConnectionRow>,
}

impl ConnectionSnapshot {
    /// Sample containing `rows`.
    pub fn new(rows: Vec<ConnectionRow>) -> Self {
        Self { rows }
    }
}

/// Reads one connection sample.
pub trait ConnectionSource {
    /// List connections once.
    ///
    /// # Errors
    ///
    /// [`SourceError`] when the sample could not be taken.
    fn snapshot(&mut self) -> Result<ConnectionSnapshot, SourceError>;

    /// Evidence note for the net capability. `None` when this source can list
    /// connections. `Some` when listing is not implemented on this platform, so
    /// the collector declares net as `NA` instead of emitting an empty table forever.
    fn unavailable_reason(&self) -> Option<NaReason> {
        None
    }
}

/// Connection source that returns a fixed sequence, then repeats the last sample.
#[derive(Debug, Clone)]
pub struct StaticConnectionSource {
    pending: Vec<ConnectionSnapshot>,
    last: Option<ConnectionSnapshot>,
    unavailable: Option<NaReason>,
}

impl StaticConnectionSource {
    /// Snapshots in the order `snapshot` will return them. Listing is available.
    pub fn new(snapshots: impl IntoIterator<Item = ConnectionSnapshot>) -> Self {
        Self {
            pending: snapshots.into_iter().collect(),
            last: None,
            unavailable: None,
        }
    }

    /// A source that never lists connections. `snapshot` returns an empty table
    /// and [`ConnectionSource::unavailable_reason`] explains why. Used for the
    /// Linux and macOS stub, and for tests of the NA capability.
    pub fn unavailable(reason: NaReason) -> Self {
        Self {
            pending: Vec::new(),
            last: Some(ConnectionSnapshot::default()),
            unavailable: Some(reason),
        }
    }
}

impl ConnectionSource for StaticConnectionSource {
    fn snapshot(&mut self) -> Result<ConnectionSnapshot, SourceError> {
        if !self.pending.is_empty() {
            let next = self.pending.remove(0);
            self.last = Some(next.clone());
            return Ok(next);
        }
        match &self.last {
            Some(last) => Ok(last.clone()),
            None => Err(SourceError::disconnected()),
        }
    }

    fn unavailable_reason(&self) -> Option<NaReason> {
        self.unavailable.clone()
    }
}

/// How long the collector waits between samples. Zero is rejected by [`crate::PollConfig`].
///
/// [`crate::PollCollector::poll_once`] samples exactly once and does not sleep.
#[allow(dead_code)]
pub type SampleInterval = Duration;

/// A source that fails every read. Tests use it to check that a failure becomes a
/// gap instead of an empty "nothing happened" sample.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct FailingProcessSource {
    /// Failure returned from every `snapshot`.
    pub failure: SourceFailure,
}

impl ProcessSource for FailingProcessSource {
    fn snapshot(&mut self) -> Result<ProcessSnapshot, SourceError> {
        Err(SourceError { kind: self.failure })
    }
}

/// Connection source that fails every read.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct FailingConnectionSource {
    /// Failure returned from every `snapshot`.
    pub failure: SourceFailure,
}

impl ConnectionSource for FailingConnectionSource {
    fn snapshot(&mut self) -> Result<ConnectionSnapshot, SourceError> {
        Err(SourceError { kind: self.failure })
    }
}
