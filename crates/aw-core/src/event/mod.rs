//! Event model. Re-exported from the crate root.
//!
//! Layout follows event-schema: common fields on [`RawEvent`], per-type fields
//! on [`EventKind`]. Collectors translate a system event into one `RawEvent`
//! and do not aggregate, correlate, or redact here.

mod enums;
mod evidence;
mod ids;
mod kinds;
#[cfg(test)]
mod proptest;
mod raw;

pub use enums::{
    FileAccessMode, FlowDirection, GapKind, IoVia, IpcDirection, IpcKind, L4Proto, StartHow,
    ToolPhase,
};
pub use evidence::{Evidence, NaReason};
pub use ids::{
    BodyDigestRef, ProcRef, ProcUid, SessionId, SocketAddr, Source, UserRef, SCHEMA_VERSION,
};
pub use kinds::{
    AgentRpc, AgentToolCall, Arg, DnsAnswer, DnsQuery, DnsRecord, EnvMap, FileClose, FileCreate,
    FileDelete, FileOpen, FileRead, FileRename, FileWrite, FlowKey, Gap, HeaderList, HttpRequest,
    HttpResponse, IpcClose, IpcOpen, IpcTransfer, NetClose, NetConnect, NetRecv, NetSend,
    ProcessExit, ProcessStart, Redacted, TlsSni,
};
pub use raw::{EventKind, RawEvent, RawEventParts};
