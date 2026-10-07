//! Shared event model for AgentWatch.
//!
//! Collectors emit [`RawEvent`] and nothing else. Downstream crates consume the
//! same type. This crate has no runtime, platform, or database dependencies.
//!
//! Sensitive payloads (argv, environment values, URLs, headers) are redacted
//! before they are logged. Their `Debug` impls print lengths and placeholders,
//! never the values themselves.

#![forbid(unsafe_code)]

pub mod error;
pub mod event;
pub mod proc;
pub mod time;

mod xxh3;

pub use error::{EventError, SchemaError};
pub use event::{
    AgentRpc, AgentToolCall, BodyDigestRef, DnsAnswer, DnsQuery, DnsRecord, EnvMap, EventKind,
    Evidence, FileAccessMode, FileClose, FileCreate, FileDelete, FileOpen, FileRead, FileRename,
    FileWrite, FlowDirection, FlowKey, Gap, GapKind, HeaderList, HttpRequest, HttpResponse, IoVia,
    IpcClose, IpcDirection, IpcKind, IpcOpen, IpcTransfer, L4Proto, NaReason, NetClose, NetConnect,
    NetRecv, NetSend, ProcRef, ProcUid, ProcessExit, ProcessStart, RawEvent, RawEventParts,
    Redacted, SessionId, SocketAddr, Source, StartHow, TlsSni, ToolPhase, UserRef, SCHEMA_VERSION,
};
