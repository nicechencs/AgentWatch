//! [`RawEvent`]: the only type collectors may emit.

use std::collections::BTreeMap;

use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

use super::evidence::{Evidence, NaReason};
use super::ids::{ProcRef, SessionId, Source, SCHEMA_VERSION};
use super::kinds::{
    AgentRpc, AgentToolCall, DnsAnswer, DnsQuery, FileClose, FileCreate, FileDelete, FileOpen,
    FileRead, FileRename, FileWrite, Gap, HttpRequest, HttpResponse, IpcClose, IpcOpen,
    IpcTransfer, NetClose, NetConnect, NetRecv, NetSend, ProcessExit, ProcessStart, TlsSni,
};
use crate::error::EventError;

/// One observed fact, or an explicit gap where facts were lost.
///
/// JSON is internally tagged on `kind` (snake_case). `None` is written as `null`
/// and is not skipped, so a missing observation stays distinct from an omitted
/// field. `field_evidence` is omitted when empty.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RawEvent {
    /// Schema major version. See [`SCHEMA_VERSION`].
    pub v: u16,
    /// Monotonic sequence inside one daemon process. Used to restore order and dedupe.
    pub seq: u64,
    /// Monotonic nanoseconds in the daemon clock domain.
    pub ts_mono_ns: u64,
    /// Wall clock, Unix epoch nanoseconds, UTC.
    pub ts_wall_ns: i64,
    /// Owning session. `None` before scope filtering.
    pub session_id: Option<SessionId>,
    /// Subject process. `None` for non-process events such as a collector-wide [`EventKind::Gap`].
    pub proc: Option<ProcRef>,
    /// `"<collector>/<probe>"`.
    pub source: Source,
    /// Record-level evidence. Constructors require this; there is no default.
    pub evidence: Evidence,
    /// Field-level evidence, only where it differs from the record.
    /// Keys are field paths such as `"bytes"` or `"peer"`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub field_evidence: BTreeMap<String, Evidence>,
    /// Kind-specific payload. Flattened so `kind` is a sibling of the common fields.
    #[serde(flatten)]
    pub kind: EventKind,
}

/// Type-specific fields. JSON uses an internal `kind` tag (snake_case).
///
/// Serde has no `#[serde(other)]` for an internally tagged enum that also carries
/// payload, so [`EventKind`] is (de)serialized by hand. An unrecognized `kind`
/// string becomes [`EventKind::Unknown`] and the rest of the object is kept in
/// `raw`, which lets a caller write `Gap { parse_error }` instead of dropping the
/// line (event-schema §6). Adding a real variant is an incompatible schema change;
/// P6's four IPC variants were registered before the draft froze and do not bump `v`.
#[derive(Debug, Clone, PartialEq)]
pub enum EventKind {
    ProcessStart(ProcessStart),
    ProcessExit(ProcessExit),
    FileOpen(FileOpen),
    FileRead(FileRead),
    FileWrite(FileWrite),
    FileClose(FileClose),
    FileCreate(FileCreate),
    FileDelete(FileDelete),
    FileRename(FileRename),
    NetConnect(NetConnect),
    NetSend(NetSend),
    NetRecv(NetRecv),
    NetClose(NetClose),
    DnsQuery(DnsQuery),
    DnsAnswer(DnsAnswer),
    TlsSni(TlsSni),
    HttpRequest(HttpRequest),
    HttpResponse(HttpResponse),
    AgentToolCall(AgentToolCall),
    IpcOpen(IpcOpen),
    IpcTransfer(IpcTransfer),
    IpcClose(IpcClose),
    AgentRpc(AgentRpc),
    Gap(Gap),
    /// `kind` string this build does not recognize. `raw` is the original object
    /// minus the common envelope fields, so nothing the writer sent is discarded.
    Unknown {
        raw: Value,
    },
}

impl EventKind {
    /// Snake_case JSON tag.
    pub fn kind_name(&self) -> &'static str {
        match self {
            Self::ProcessStart(_) => "process_start",
            Self::ProcessExit(_) => "process_exit",
            Self::FileOpen(_) => "file_open",
            Self::FileRead(_) => "file_read",
            Self::FileWrite(_) => "file_write",
            Self::FileClose(_) => "file_close",
            Self::FileCreate(_) => "file_create",
            Self::FileDelete(_) => "file_delete",
            Self::FileRename(_) => "file_rename",
            Self::NetConnect(_) => "net_connect",
            Self::NetSend(_) => "net_send",
            Self::NetRecv(_) => "net_recv",
            Self::NetClose(_) => "net_close",
            Self::DnsQuery(_) => "dns_query",
            Self::DnsAnswer(_) => "dns_answer",
            Self::TlsSni(_) => "tls_sni",
            Self::HttpRequest(_) => "http_request",
            Self::HttpResponse(_) => "http_response",
            Self::AgentToolCall(_) => "agent_tool_call",
            Self::IpcOpen(_) => "ipc_open",
            Self::IpcTransfer(_) => "ipc_transfer",
            Self::IpcClose(_) => "ipc_close",
            Self::AgentRpc(_) => "agent_rpc",
            Self::Gap(_) => "gap",
            Self::Unknown { .. } => "unknown",
        }
    }

    /// Executable base name of a `process_start`, for rules that depend on which
    /// program is running (`argv.mysql_p`, `argv.basic_auth`).
    ///
    /// `None` for every other kind, and when the event carried no `exe`. The path
    /// itself is not returned: only the last segment after `/` or `\`.
    pub fn exe_base(&self) -> Option<String> {
        let Self::ProcessStart(start) = self else {
            return None;
        };
        let exe = start.exe.as_deref()?;
        let base = exe.rsplit(['/', '\\']).next().unwrap_or(exe);
        if base.is_empty() {
            None
        } else {
            Some(base.to_owned())
        }
    }

    /// Option fields that event-schema §3 treats as semantically required.
    ///
    /// A `None` here must have an `NA(...)` entry in `field_evidence`. Other
    /// `Option` fields are nullable by schema (the platform may simply not have
    /// the value, and the record stays valid). Non-option fields cannot be
    /// absent, so they are not listed.
    ///
    /// `AgentRpc::target` is included because event-schema §3 says the tool name
    /// is `NA(protocol_not_observed)` when the tap is off — a `None` without that
    /// entry would hide "not observed" as "no tool".
    pub fn required_absent(&self) -> Vec<&'static str> {
        match self {
            Self::FileRead(v) if v.bytes.is_none() => vec!["bytes"],
            Self::FileWrite(v) if v.bytes.is_none() => vec!["bytes"],
            Self::IpcOpen(v) if v.peer.is_none() => vec!["peer"],
            Self::AgentRpc(v) if v.target.is_none() => vec!["target"],
            _ => Vec::new(),
        }
    }
}

/// Fields a caller must supply. `v` defaults to [`SCHEMA_VERSION`] inside [`RawEvent::try_new`].
#[derive(Debug, Clone)]
pub struct RawEventParts {
    pub seq: u64,
    pub ts_mono_ns: u64,
    pub ts_wall_ns: i64,
    pub session_id: Option<SessionId>,
    pub proc: Option<ProcRef>,
    pub source: Source,
    pub evidence: Evidence,
    pub kind: EventKind,
}

impl RawEvent {
    /// Build an event at the current schema version and check required `None`s.
    ///
    /// `evidence` and `source` are parameters, not defaults (ADR-0004).
    pub fn try_new(parts: RawEventParts) -> Result<Self, EventError> {
        let event = Self {
            v: SCHEMA_VERSION,
            seq: parts.seq,
            ts_mono_ns: parts.ts_mono_ns,
            ts_wall_ns: parts.ts_wall_ns,
            session_id: parts.session_id,
            proc: parts.proc,
            source: parts.source,
            evidence: parts.evidence,
            field_evidence: BTreeMap::new(),
            kind: parts.kind,
        };
        event.check()?;
        Ok(event)
    }

    /// Record that `field` is unavailable, and require the reason to be `NA`.
    ///
    /// `field` is a path inside the kind payload (`"bytes"`, `"peer"`, `"target"`).
    pub fn mark_na(&mut self, field: impl Into<String>, reason: NaReason) {
        self.field_evidence
            .insert(field.into(), Evidence::NA(reason));
    }

    /// Re-check version and required-field evidence. Called by constructors and decoders.
    pub fn check(&self) -> Result<(), EventError> {
        if self.v != SCHEMA_VERSION {
            return Err(EventError::UnsupportedSchema { found: self.v });
        }
        if matches!(self.kind, EventKind::Unknown { .. }) {
            return Ok(());
        }
        for field in self.kind.required_absent() {
            let marked = self.field_evidence.get(field).is_some_and(Evidence::is_na);
            if !marked {
                return Err(EventError::MissingRequired {
                    kind: self.kind.kind_name(),
                    field,
                });
            }
        }
        Ok(())
    }

    /// Stable JSON. Object key order follows serde's derived field order.
    pub fn to_json(&self) -> Result<String, EventError> {
        serde_json::to_string(self).map_err(|err| EventError::Decode(err.to_string()))
    }

    /// Decode one event.
    ///
    /// Unknown object fields are ignored. An unknown `kind` becomes
    /// [`EventKind::Unknown`] instead of an error, so a newer minor writer does
    /// not make this reader drop the line. A `v` other than [`SCHEMA_VERSION`]
    /// is [`EventError::UnsupportedSchema`].
    pub fn from_json(text: &str) -> Result<Self, EventError> {
        let value: Value =
            serde_json::from_str(text).map_err(|err| EventError::Decode(err.to_string()))?;
        Self::from_value(value)
    }

    pub fn from_value(value: Value) -> Result<Self, EventError> {
        let v = match value.get("v") {
            Some(Value::Number(n)) => n
                .as_u64()
                .and_then(|n| u16::try_from(n).ok())
                .ok_or_else(|| EventError::Decode(format!("schema version `{n}` is not a u16")))?,
            Some(other) => {
                return Err(EventError::Decode(format!(
                    "schema version has unexpected JSON type {other}"
                )));
            }
            None => {
                return Err(EventError::Decode(
                    "event JSON is missing required field `v`".to_owned(),
                ));
            }
        };
        if v != SCHEMA_VERSION {
            return Err(EventError::UnsupportedSchema { found: v });
        }

        let event: RawEvent =
            serde_json::from_value(value).map_err(|err| EventError::Decode(err.to_string()))?;
        event.check()?;
        Ok(event)
    }
}

impl Serialize for EventKind {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut payload = self.to_payload_value().map_err(serde::ser::Error::custom)?;
        let Some(obj) = payload.as_object_mut() else {
            return Err(serde::ser::Error::custom(
                "event kind payload did not serialize as an object",
            ));
        };
        // The event tag is the only `kind` key. `IpcOpen`'s channel type is
        // serialized as `ipc_kind` (see that field), so it never collides.
        let kind_tag = if matches!(self, Self::Unknown { .. }) {
            None
        } else {
            Some(self.kind_name())
        };
        let extra = usize::from(kind_tag.is_some());
        let mut out = serializer.serialize_map(Some(obj.len() + extra))?;
        let keys: Vec<String> = obj.keys().cloned().collect();
        for key in keys {
            if let Some(value) = obj.remove(&key) {
                out.serialize_entry(&key, &value)?;
            }
        }
        if let Some(tag) = kind_tag {
            out.serialize_entry("kind", tag)?;
        }
        out.end()
    }
}

impl<'de> Deserialize<'de> for EventKind {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut value = Value::deserialize(deserializer)?;
        let Some(obj) = value.as_object_mut() else {
            return Err(serde::de::Error::custom(
                "event kind payload must be an object",
            ));
        };
        let kind = obj
            .remove("kind")
            .and_then(|v| match v {
                Value::String(s) => Some(s),
                other => {
                    obj.insert("kind".to_owned(), other);
                    None
                }
            })
            .ok_or_else(|| serde::de::Error::custom("event is missing string field `kind`"))?;
        // Anything that is not a known kind — including the literal "unknown" — is kept
        // verbatim, tag included. Known kinds still ignore fields they do not declare.
        if !is_known_kind(&kind) {
            obj.insert("kind".to_owned(), Value::String(kind));
            return Ok(Self::Unknown { raw: value });
        }
        decode_known(&kind, value).map_err(serde::de::Error::custom)
    }
}

impl EventKind {
    fn to_payload_value(&self) -> Result<Value, String> {
        let value = match self {
            Self::ProcessStart(v) => serde_json::to_value(v),
            Self::ProcessExit(v) => serde_json::to_value(v),
            Self::FileOpen(v) => serde_json::to_value(v),
            Self::FileRead(v) => serde_json::to_value(v),
            Self::FileWrite(v) => serde_json::to_value(v),
            Self::FileClose(v) => serde_json::to_value(v),
            Self::FileCreate(v) => serde_json::to_value(v),
            Self::FileDelete(v) => serde_json::to_value(v),
            Self::FileRename(v) => serde_json::to_value(v),
            Self::NetConnect(v) => serde_json::to_value(v),
            Self::NetSend(v) => serde_json::to_value(v),
            Self::NetRecv(v) => serde_json::to_value(v),
            Self::NetClose(v) => serde_json::to_value(v),
            Self::DnsQuery(v) => serde_json::to_value(v),
            Self::DnsAnswer(v) => serde_json::to_value(v),
            Self::TlsSni(v) => serde_json::to_value(v),
            Self::HttpRequest(v) => serde_json::to_value(v),
            Self::HttpResponse(v) => serde_json::to_value(v),
            Self::AgentToolCall(v) => serde_json::to_value(v),
            Self::IpcOpen(v) => serde_json::to_value(v),
            Self::IpcTransfer(v) => serde_json::to_value(v),
            Self::IpcClose(v) => serde_json::to_value(v),
            Self::AgentRpc(v) => serde_json::to_value(v),
            Self::Gap(v) => serde_json::to_value(v),
            Self::Unknown { raw } => return Ok(raw.clone()),
        };
        value.map_err(|err| err.to_string())
    }
}

fn is_known_kind(kind: &str) -> bool {
    matches!(
        kind,
        "process_start"
            | "process_exit"
            | "file_open"
            | "file_read"
            | "file_write"
            | "file_close"
            | "file_create"
            | "file_delete"
            | "file_rename"
            | "net_connect"
            | "net_send"
            | "net_recv"
            | "net_close"
            | "dns_query"
            | "dns_answer"
            | "tls_sni"
            | "http_request"
            | "http_response"
            | "agent_tool_call"
            | "ipc_open"
            | "ipc_transfer"
            | "ipc_close"
            | "agent_rpc"
            | "gap"
    )
}

fn decode_known(kind: &str, value: Value) -> Result<EventKind, String> {
    let err = |e: serde_json::Error| e.to_string();
    Ok(match kind {
        "process_start" => EventKind::ProcessStart(serde_json::from_value(value).map_err(err)?),
        "process_exit" => EventKind::ProcessExit(serde_json::from_value(value).map_err(err)?),
        "file_open" => EventKind::FileOpen(serde_json::from_value(value).map_err(err)?),
        "file_read" => EventKind::FileRead(serde_json::from_value(value).map_err(err)?),
        "file_write" => EventKind::FileWrite(serde_json::from_value(value).map_err(err)?),
        "file_close" => EventKind::FileClose(serde_json::from_value(value).map_err(err)?),
        "file_create" => EventKind::FileCreate(serde_json::from_value(value).map_err(err)?),
        "file_delete" => EventKind::FileDelete(serde_json::from_value(value).map_err(err)?),
        "file_rename" => EventKind::FileRename(serde_json::from_value(value).map_err(err)?),
        "net_connect" => EventKind::NetConnect(serde_json::from_value(value).map_err(err)?),
        "net_send" => EventKind::NetSend(serde_json::from_value(value).map_err(err)?),
        "net_recv" => EventKind::NetRecv(serde_json::from_value(value).map_err(err)?),
        "net_close" => EventKind::NetClose(serde_json::from_value(value).map_err(err)?),
        "dns_query" => EventKind::DnsQuery(serde_json::from_value(value).map_err(err)?),
        "dns_answer" => EventKind::DnsAnswer(serde_json::from_value(value).map_err(err)?),
        "tls_sni" => EventKind::TlsSni(serde_json::from_value(value).map_err(err)?),
        "http_request" => EventKind::HttpRequest(serde_json::from_value(value).map_err(err)?),
        "http_response" => EventKind::HttpResponse(serde_json::from_value(value).map_err(err)?),
        "agent_tool_call" => EventKind::AgentToolCall(serde_json::from_value(value).map_err(err)?),
        "ipc_open" => EventKind::IpcOpen(serde_json::from_value(value).map_err(err)?),
        "ipc_transfer" => EventKind::IpcTransfer(serde_json::from_value(value).map_err(err)?),
        "ipc_close" => EventKind::IpcClose(serde_json::from_value(value).map_err(err)?),
        "agent_rpc" => EventKind::AgentRpc(serde_json::from_value(value).map_err(err)?),
        "gap" => EventKind::Gap(serde_json::from_value(value).map_err(err)?),
        other => EventKind::Unknown {
            raw: {
                let mut obj = match value {
                    Value::Object(map) => map,
                    other_value => {
                        return Err(format!(
                            "payload for kind `{other}` was not an object: {other_value}"
                        ));
                    }
                };
                obj.insert("kind".to_owned(), Value::String(other.to_owned()));
                Value::Object(obj)
            },
        },
    })
}
