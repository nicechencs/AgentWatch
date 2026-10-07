//! Payloads of [`super::EventKind`]. One struct per variant so each has a constructor.
//!
//! `Debug` on anything that can hold argv, environment values, URLs, or headers
//! prints lengths and `<redacted>`, never the values. JSON serde is unchanged:
//! fixtures still round-trip the strings. Callers must not log those structs with
//! `{:?}` before the pipeline redact stage.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::enums::{
    FileAccessMode, FlowDirection, GapKind, IoVia, IpcDirection, IpcKind, L4Proto, StartHow,
    ToolPhase,
};
use super::ids::{BodyDigestRef, ProcRef, ProcUid, SocketAddr, Source, UserRef};

fn redacted_len(n: usize) -> String {
    format!("<redacted len={n}>")
}

/// A string whose `Debug` form is a length placeholder.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Redacted(pub String);

impl Redacted {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&redacted_len(self.0.len()))
    }
}

impl From<String> for Redacted {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for Redacted {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

/// One argv element. Same redaction rule as [`Redacted`].
pub type Arg = Redacted;

/// Environment map. Keys stay visible (they are a whitelist); values do not.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(transparent)]
pub struct EnvMap(pub BTreeMap<String, String>);

impl fmt::Debug for EnvMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut map = f.debug_map();
        for key in self.0.keys() {
            map.entry(key, &"<redacted>");
        }
        map.finish()
    }
}

/// Header list. Names stay; values are placeholders in `Debug`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(transparent)]
pub struct HeaderList(pub Vec<(String, String)>);

impl fmt::Debug for HeaderList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(
                self.0
                    .iter()
                    .map(|(name, value)| format!("{name}: <redacted len={}>", value.len())),
            )
            .finish()
    }
}

/// Four-tuple plus an optional platform socket id, so a reused tuple stays distinct.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowKey {
    pub proto: L4Proto,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    /// Linux inode or sock-pointer hash. `None` where the platform has no such id.
    pub sock_id: Option<u64>,
}

impl FlowKey {
    pub fn new(
        proto: L4Proto,
        local: impl Into<SocketAddr>,
        remote: impl Into<SocketAddr>,
        sock_id: Option<u64>,
    ) -> Self {
        Self {
            proto,
            local: local.into(),
            remote: remote.into(),
            sock_id,
        }
    }
}

/// One DNS answer. `data` is an IP string for A/AAAA and a name for CNAME.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsRecord {
    pub rtype: u16,
    pub data: String,
}

// --- process ---------------------------------------------------------------------

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessStart {
    pub ppid: u32,
    pub parent_uid: Option<ProcUid>,
    pub start_time_ns: i64,
    pub exe: Option<String>,
    /// Redacted in the pipeline. Collectors may still hold the raw argv in memory.
    pub argv: Option<Vec<Arg>>,
    pub cwd: Option<String>,
    pub user: Option<UserRef>,
    pub how: StartHow,
    /// Only whitelisted names are kept. Values are redacted before persistence.
    pub env: Option<EnvMap>,
    pub signer: Option<String>,
}

impl ProcessStart {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ppid: u32,
        parent_uid: Option<ProcUid>,
        start_time_ns: i64,
        exe: Option<String>,
        argv: Option<Vec<Arg>>,
        cwd: Option<String>,
        user: Option<UserRef>,
        how: StartHow,
        env: Option<EnvMap>,
        signer: Option<String>,
    ) -> Self {
        Self {
            ppid,
            parent_uid,
            start_time_ns,
            exe,
            argv,
            cwd,
            user,
            how,
            env,
            signer,
        }
    }
}

impl fmt::Debug for ProcessStart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProcessStart")
            .field("ppid", &self.ppid)
            .field("parent_uid", &self.parent_uid)
            .field("start_time_ns", &self.start_time_ns)
            .field("exe", &self.exe.as_ref().map(|s| redacted_len(s.len())))
            .field(
                "argv",
                &self
                    .argv
                    .as_ref()
                    .map(|v| format!("<redacted argc={}>", v.len())),
            )
            .field("cwd", &self.cwd.as_ref().map(|s| redacted_len(s.len())))
            .field("user", &self.user)
            .field("how", &self.how)
            .field(
                "env",
                &self
                    .env
                    .as_ref()
                    .map(|m| format!("<redacted env_keys={}>", m.0.len())),
            )
            .field(
                "signer",
                &self.signer.as_ref().map(|s| redacted_len(s.len())),
            )
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessExit {
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
}

impl ProcessExit {
    pub fn new(exit_code: Option<i32>, signal: Option<i32>) -> Self {
        Self { exit_code, signal }
    }
}

// --- files ----------------------------------------------------------------------

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileOpen {
    pub handle: Option<u64>,
    pub path: String,
    pub access: FileAccessMode,
    pub created: Option<bool>,
    pub truncated: Option<bool>,
    /// Platform error code when the open failed (`EACCES` and friends).
    pub result: Option<i32>,
    pub via: Option<IoVia>,
    pub path_resolved: bool,
}

impl FileOpen {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        handle: Option<u64>,
        path: impl Into<String>,
        access: FileAccessMode,
        created: Option<bool>,
        truncated: Option<bool>,
        result: Option<i32>,
        via: Option<IoVia>,
        path_resolved: bool,
    ) -> Self {
        Self {
            handle,
            path: path.into(),
            access,
            created,
            truncated,
            result,
            via,
            path_resolved,
        }
    }
}

impl fmt::Debug for FileOpen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileOpen")
            .field("handle", &self.handle)
            .field("path", &redacted_len(self.path.len()))
            .field("access", &self.access)
            .field("created", &self.created)
            .field("truncated", &self.truncated)
            .field("result", &self.result)
            .field("via", &self.via)
            .field("path_resolved", &self.path_resolved)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileRead {
    pub handle: Option<u64>,
    pub path: Option<String>,
    pub bytes: Option<u64>,
    pub offset: Option<u64>,
    pub via: Option<IoVia>,
}

impl FileRead {
    pub fn new(
        handle: Option<u64>,
        path: Option<String>,
        bytes: Option<u64>,
        offset: Option<u64>,
        via: Option<IoVia>,
    ) -> Self {
        Self {
            handle,
            path,
            bytes,
            offset,
            via,
        }
    }
}

impl fmt::Debug for FileRead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileRead")
            .field("handle", &self.handle)
            .field("path", &self.path.as_ref().map(|p| redacted_len(p.len())))
            .field("bytes", &self.bytes)
            .field("offset", &self.offset)
            .field("via", &self.via)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileWrite {
    pub handle: Option<u64>,
    pub path: Option<String>,
    pub bytes: Option<u64>,
    pub offset: Option<u64>,
}

impl FileWrite {
    pub fn new(
        handle: Option<u64>,
        path: Option<String>,
        bytes: Option<u64>,
        offset: Option<u64>,
    ) -> Self {
        Self {
            handle,
            path,
            bytes,
            offset,
        }
    }
}

impl fmt::Debug for FileWrite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileWrite")
            .field("handle", &self.handle)
            .field("path", &self.path.as_ref().map(|p| redacted_len(p.len())))
            .field("bytes", &self.bytes)
            .field("offset", &self.offset)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileClose {
    pub handle: Option<u64>,
    pub path: Option<String>,
    pub modified: Option<bool>,
}

impl FileClose {
    pub fn new(handle: Option<u64>, path: Option<String>, modified: Option<bool>) -> Self {
        Self {
            handle,
            path,
            modified,
        }
    }
}

impl fmt::Debug for FileClose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileClose")
            .field("handle", &self.handle)
            .field("path", &self.path.as_ref().map(|p| redacted_len(p.len())))
            .field("modified", &self.modified)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileCreate {
    pub path: String,
    pub is_dir: bool,
}

impl FileCreate {
    pub fn new(path: impl Into<String>, is_dir: bool) -> Self {
        Self {
            path: path.into(),
            is_dir,
        }
    }
}

impl fmt::Debug for FileCreate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileCreate")
            .field("path", &redacted_len(self.path.len()))
            .field("is_dir", &self.is_dir)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileDelete {
    pub path: String,
    pub is_dir: Option<bool>,
}

impl FileDelete {
    pub fn new(path: impl Into<String>, is_dir: Option<bool>) -> Self {
        Self {
            path: path.into(),
            is_dir,
        }
    }
}

impl fmt::Debug for FileDelete {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileDelete")
            .field("path", &redacted_len(self.path.len()))
            .field("is_dir", &self.is_dir)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileRename {
    pub from: String,
    pub to: String,
}

impl FileRename {
    pub fn new(from: impl Into<String>, to: impl Into<String>) -> Self {
        Self {
            from: from.into(),
            to: to.into(),
        }
    }
}

impl fmt::Debug for FileRename {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileRename")
            .field("from", &redacted_len(self.from.len()))
            .field("to", &redacted_len(self.to.len()))
            .finish()
    }
}

// --- network --------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetConnect {
    pub flow: FlowKey,
    pub direction: FlowDirection,
    pub result: Option<i32>,
}

impl NetConnect {
    pub fn new(flow: FlowKey, direction: FlowDirection, result: Option<i32>) -> Self {
        Self {
            flow,
            direction,
            result,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetSend {
    pub flow: FlowKey,
    pub bytes: u64,
    /// `sendfile` / `splice` means the bytes came from a file descriptor. Still only an I-level clue.
    pub via: Option<IoVia>,
}

impl NetSend {
    pub fn new(flow: FlowKey, bytes: u64, via: Option<IoVia>) -> Self {
        Self { flow, bytes, via }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetRecv {
    pub flow: FlowKey,
    pub bytes: u64,
}

impl NetRecv {
    pub fn new(flow: FlowKey, bytes: u64) -> Self {
        Self { flow, bytes }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetClose {
    pub flow: FlowKey,
    pub total_sent: Option<u64>,
    pub total_recv: Option<u64>,
}

impl NetClose {
    pub fn new(flow: FlowKey, total_sent: Option<u64>, total_recv: Option<u64>) -> Self {
        Self {
            flow,
            total_sent,
            total_recv,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsQuery {
    pub qname: String,
    pub qtype: u16,
    pub txid: Option<u16>,
    pub server: Option<SocketAddr>,
}

impl DnsQuery {
    pub fn new(
        qname: impl Into<String>,
        qtype: u16,
        txid: Option<u16>,
        server: Option<SocketAddr>,
    ) -> Self {
        Self {
            qname: qname.into(),
            qtype,
            txid,
            server,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsAnswer {
    pub qname: String,
    pub qtype: u16,
    pub rcode: u16,
    pub answers: Vec<DnsRecord>,
    pub ttl_min: Option<u32>,
}

impl DnsAnswer {
    pub fn new(
        qname: impl Into<String>,
        qtype: u16,
        rcode: u16,
        answers: Vec<DnsRecord>,
        ttl_min: Option<u32>,
    ) -> Self {
        Self {
            qname: qname.into(),
            qtype,
            rcode,
            answers,
            ttl_min,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsSni {
    pub flow: FlowKey,
    pub sni: String,
    pub alpn: Vec<String>,
}

impl TlsSni {
    pub fn new(flow: FlowKey, sni: impl Into<String>, alpn: Vec<String>) -> Self {
        Self {
            flow,
            sni: sni.into(),
            alpn,
        }
    }
}

// --- protocol (proxy / uprobe) --------------------------------------------------

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRequest {
    pub req_id: u64,
    pub client: SocketAddr,
    pub upstream: Option<FlowKey>,
    pub method: String,
    /// Full URL after redaction.
    pub url: Redacted,
    pub http_version: String,
    /// Whitelisted header names only. Values are redacted before persistence.
    pub headers: HeaderList,
    pub body_bytes: u64,
    pub body_digest: Option<BodyDigestRef>,
}

impl HttpRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        req_id: u64,
        client: impl Into<SocketAddr>,
        upstream: Option<FlowKey>,
        method: impl Into<String>,
        url: impl Into<Redacted>,
        http_version: impl Into<String>,
        headers: HeaderList,
        body_bytes: u64,
        body_digest: Option<BodyDigestRef>,
    ) -> Self {
        Self {
            req_id,
            client: client.into(),
            upstream,
            method: method.into(),
            url: url.into(),
            http_version: http_version.into(),
            headers,
            body_bytes,
            body_digest,
        }
    }
}

impl fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpRequest")
            .field("req_id", &self.req_id)
            .field("client", &self.client)
            .field("upstream", &self.upstream)
            .field("method", &self.method)
            .field("url", &self.url)
            .field("http_version", &self.http_version)
            .field("headers", &self.headers)
            .field("body_bytes", &self.body_bytes)
            .field("body_digest", &self.body_digest)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpResponse {
    pub req_id: u64,
    pub status: u16,
    pub headers: HeaderList,
    pub body_bytes: u64,
    pub duration_ms: u32,
}

impl HttpResponse {
    pub fn new(
        req_id: u64,
        status: u16,
        headers: HeaderList,
        body_bytes: u64,
        duration_ms: u32,
    ) -> Self {
        Self {
            req_id,
            status,
            headers,
            body_bytes,
            duration_ms,
        }
    }
}

impl fmt::Debug for HttpResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpResponse")
            .field("req_id", &self.req_id)
            .field("status", &self.status)
            .field("headers", &self.headers)
            .field("body_bytes", &self.body_bytes)
            .field("duration_ms", &self.duration_ms)
            .finish()
    }
}

// --- agent self-report (E3) -----------------------------------------------------

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentToolCall {
    pub agent: String,
    pub agent_session: Option<String>,
    pub tool: String,
    pub phase: ToolPhase,
    /// Structured argument summary, already redacted and truncated.
    pub summary: Value,
    pub call_id: Option<String>,
}

impl AgentToolCall {
    pub fn new(
        agent: impl Into<String>,
        agent_session: Option<String>,
        tool: impl Into<String>,
        phase: ToolPhase,
        summary: Value,
        call_id: Option<String>,
    ) -> Self {
        Self {
            agent: agent.into(),
            agent_session,
            tool: tool.into(),
            phase,
            summary,
            call_id,
        }
    }
}

impl fmt::Debug for AgentToolCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentToolCall")
            .field("agent", &self.agent)
            .field(
                "agent_session",
                &self.agent_session.as_ref().map(|s| redacted_len(s.len())),
            )
            .field("tool", &self.tool)
            .field("phase", &self.phase)
            .field("summary", &"<redacted>")
            .field(
                "call_id",
                &self.call_id.as_ref().map(|s| redacted_len(s.len())),
            )
            .finish()
    }
}

// --- local IPC (P6) -------------------------------------------------------------

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpcOpen {
    /// Channel type. Renamed on the wire: the event tag already occupies `kind`.
    #[serde(rename = "ipc_kind")]
    pub kind: IpcKind,
    /// `None` when the peer could not be identified. Callers then mark `peer` NA.
    pub peer: Option<ProcRef>,
    /// Socket path, pipe name, or loopback port. Redacted before persistence.
    pub name: Option<String>,
}

impl IpcOpen {
    pub fn new(kind: IpcKind, peer: Option<ProcRef>, name: Option<String>) -> Self {
        Self { kind, peer, name }
    }
}

impl fmt::Debug for IpcOpen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IpcOpen")
            .field("kind", &self.kind)
            .field("peer", &self.peer)
            .field("name", &self.name.as_ref().map(|n| redacted_len(n.len())))
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpcTransfer {
    /// Collector-local channel id, paired with [`IpcOpen`] / [`IpcClose`].
    pub channel: u64,
    pub direction: IpcDirection,
    pub bytes: u64,
}

impl IpcTransfer {
    pub fn new(channel: u64, direction: IpcDirection, bytes: u64) -> Self {
        Self {
            channel,
            direction,
            bytes,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpcClose {
    pub channel: u64,
    pub total_a_to_b: Option<u64>,
    pub total_b_to_a: Option<u64>,
}

impl IpcClose {
    pub fn new(channel: u64, total_a_to_b: Option<u64>, total_b_to_a: Option<u64>) -> Self {
        Self {
            channel,
            total_a_to_b,
            total_b_to_a,
        }
    }
}

/// Protocol metadata from mcp-tap or the proxy.
///
/// There is deliberately no field for argument or result *content* (P6-CORE-01).
/// `arg_shape` is names mapped to `{type, len}` only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentRpc {
    pub method: String,
    pub target: Option<String>,
    pub arg_shape: Option<Value>,
    pub req_bytes: Option<u64>,
    pub resp_bytes: Option<u64>,
    pub is_error: Option<bool>,
    pub duration_ns: Option<u64>,
}

impl AgentRpc {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        method: impl Into<String>,
        target: Option<String>,
        arg_shape: Option<Value>,
        req_bytes: Option<u64>,
        resp_bytes: Option<u64>,
        is_error: Option<bool>,
        duration_ns: Option<u64>,
    ) -> Self {
        Self {
            method: method.into(),
            target,
            arg_shape,
            req_bytes,
            resp_bytes,
            is_error,
            duration_ns,
        }
    }
}

// --- gap ------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gap {
    pub collector: Source,
    pub gap_kind: GapKind,
    /// Event classes affected, for example `"file"`, `"net"`.
    pub affects: Vec<String>,
    pub from_mono_ns: u64,
    pub to_mono_ns: u64,
    /// Known loss count. `None` when the count itself is unknown.
    pub count: Option<u64>,
    pub detail: Option<String>,
}

impl Gap {
    pub fn new(
        collector: impl Into<Source>,
        gap_kind: GapKind,
        affects: Vec<String>,
        from_mono_ns: u64,
        to_mono_ns: u64,
        count: Option<u64>,
        detail: Option<String>,
    ) -> Self {
        Self {
            collector: collector.into(),
            gap_kind,
            affects,
            from_mono_ns,
            to_mono_ns,
            count,
            detail,
        }
    }
}
