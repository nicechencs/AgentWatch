//! Small enums that appear inside [`super::EventKind`] payloads.
//!
//! Every enum that event-schema §6 calls a compatible extension point ends in
//! `Unknown`, filled by `#[serde(other)]` when a newer writer uses a new variant.

use serde::{Deserialize, Serialize};

/// How a process came into existence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StartHow {
    Fork,
    Exec,
    /// Windows `CreateProcess`.
    Spawn,
    /// Synthesized while attaching to an already-running tree.
    Snapshot,
    #[serde(other)]
    Unknown,
}

/// Access requested by an open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileAccessMode {
    Read,
    Write,
    ReadWrite,
    Exec,
    Unknown,
}

/// Who initiated a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowDirection {
    Outbound,
    Inbound,
    Unknown,
}

/// Transport protocol of a [`super::FlowKey`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum L4Proto {
    Tcp,
    Udp,
    #[serde(other)]
    Unknown,
}

/// Path a byte count was observed through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IoVia {
    Syscall,
    Mmap,
    Sendfile,
    Splice,
    CopyFileRange,
    #[serde(other)]
    Unknown,
}

/// Hook phase of an agent self-report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolPhase {
    Pre,
    Post,
    #[serde(other)]
    Unknown,
}

/// Local IPC channel shape. Unknown variants stay so old readers do not drop the event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpcKind {
    Pipe,
    UnixStream,
    UnixDgram,
    NamedPipe,
    LoopbackTcp,
    LoopbackUdp,
    #[serde(other)]
    Unknown,
}

/// Which side of an IPC channel sent the bytes. `a` is the opener.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpcDirection {
    AToB,
    BToA,
    #[serde(other)]
    Unknown,
}

/// Why a stretch of observation is missing. The gap itself is a fact (evidence E1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GapKind {
    /// In-process queue was full.
    Dropped,
    /// The OS reported loss (ETW EventsLost, ring-buffer overrun).
    LostByOs,
    Restart,
    RateLimited,
    Permission,
    /// Events before the collector finished attaching.
    AttachWindow,
    Unsupported,
    /// The process was not yet inside the watched scope.
    ScopeRace,
    CollectorDisconnected,
    /// An E3 self-report was discarded.
    SelfReportDropped,
    /// The event could not be attributed (for example fanotify pid = 0).
    AttributionUnknown,
    CacheEvicted,
    /// External tool output could not be parsed (for example eslogger).
    ParseError,
    /// The correlation engine dropped state because its window overflowed.
    RuleStateEvicted,
    #[serde(other)]
    Unknown,
}
