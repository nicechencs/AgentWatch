# 统一事件模型

> 状态：草案
> 最后更新：2026-10-06
> 关联：REQ-02~06、[ADR-0004](../03-adr/0004-evidence-levels.md)、[ADR-0007](../03-adr/0007-process-identity.md)、[storage](storage.md)、[pipeline](pipeline.md)

`RawEvent` 是采集层与管道之间**唯一的契约**，定义在 `aw-core::event`。采集器不得绕过它直接写存储。聚合后的记录（`Record`）见 [storage](storage.md)。

## 1. 设计要点

- **一个结构 + 一个枚举**：公共字段放在 `RawEvent`，类型特有字段放在 `EventKind` 的各变体中。
- **可缺字段用 `Option` + 字段级证据**：不用 0 或空串代表“不知道”。不可得时在 `field_evidence` 中给出 `NA(reason)`。
- **进程用 `ProcUid` 引用**：不单独用 PID。PID 作为辅助字段保留，便于显示。
- **两个时间戳**：单调时间用于排序和计算间隔，墙钟时间用于展示。采集器按平台把内核时间换算到统一时钟域（§4）。
- **可序列化为 JSONL**：`fixtures/` 录制、回放、调试导出都使用同一格式。

## 2. Rust 结构草案

```rust
// crates/aw-core/src/event.rs
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use std::collections::BTreeMap;

pub const SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawEvent {
    /// 事件 schema 版本，见 §6。
    pub v: u16,
    /// daemon 内单调递增序号；用于恢复顺序和去重。
    pub seq: u64,
    /// 单调时钟（纳秒，daemon 启动为原点的统一时钟域）。
    pub ts_mono_ns: u64,
    /// 墙钟时间（Unix 纪元纳秒，UTC）。
    pub ts_wall_ns: i64,
    /// 所属会话；范围过滤前为 None。
    pub session_id: Option<SessionId>,
    /// 事件主体进程。对 Gap 等非进程事件为 None。
    pub proc: Option<ProcRef>,
    /// 产生该事件的采集器 + 子源，如 "linux.ebpf/tcp_sendmsg"。
    pub source: SmolStr,
    /// 记录级证据等级。
    pub evidence: Evidence,
    /// 字段级证据（仅在与记录级不同时出现）。key 为字段路径，如 "bytes"。
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub field_evidence: BTreeMap<SmolStr, Evidence>,
    /// 事件体。
    #[serde(flatten)]
    pub kind: EventKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub u64);   // 存储中为 INTEGER；展示为 base32 短串

/// 进程唯一 ID：hash(pid, start_time_ns, boot_id)。见 process-tracking §2。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcUid(pub u64);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcRef {
    pub uid: ProcUid,
    pub pid: u32,
    /// 线程 ID；平台提供时填写。
    pub tid: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "level", content = "reason")]
pub enum Evidence {
    E1,
    E2,
    E3,
    S,
    I,
    NA(NaReason),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NaReason {
    EsNoReadEvent, MmapNotObservable, TlsNoProxy, DirectBypassProxy, CertPinned,
    Quic, Ech, NoDnsObserved, Preexisting, CollectorUnavailable, Redacted, AttributionBreak,
    PartialClientHello, H2Hpack, TooLarge, FileChanged,
    #[serde(other)] Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IoVia { Syscall, Mmap, Sendfile, Splice, CopyFileRange, #[serde(other)] Unknown }

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventKind {
    // ---------- 进程 ----------
    ProcessStart {
        ppid: u32,
        parent_uid: Option<ProcUid>,
        start_time_ns: i64,
        exe: Option<String>,
        /// 已脱敏（脱敏发生在管道 Redact 阶段，采集器输出原始值仅停留在内存）。
        argv: Option<Vec<String>>,
        cwd: Option<String>,
        user: Option<UserRef>,
        /// 是 fork（未 exec）还是 exec。Windows 上只有 Exec。
        how: StartHow,
        /// 仅在输出白名单内的变量名时保留，值脱敏。
        env: Option<BTreeMap<String, String>>,
        /// 代码签名 / 平台标识（macOS signing_id、Windows 签名者）。
        signer: Option<String>,
    },
    ProcessExit {
        exit_code: Option<i32>,
        signal: Option<i32>,
    },

    // ---------- 文件 ----------
    FileOpen {
        /// 采集器内的句柄标识：Linux (pid, fd) 组合；Windows FileObject；macOS 无则为 None。
        handle: Option<u64>,
        path: String,
        access: FileAccessMode,   // read / write / read_write / exec / unknown
        created: Option<bool>,
        truncated: Option<bool>,
        /// 打开失败时的错误码（如 EACCES）。
        result: Option<i32>,
        /// 访问途径：普通 open / mmap 映射。
        via: Option<IoVia>,
        /// 路径是否已解析为绝对规范路径（否则可能是相对路径或被截断）。
        path_resolved: bool,
    },
    FileRead  { handle: Option<u64>, path: Option<String>, bytes: Option<u64>, offset: Option<u64>, via: Option<IoVia> },
    FileWrite { handle: Option<u64>, path: Option<String>, bytes: Option<u64>, offset: Option<u64> },
    FileClose { handle: Option<u64>, path: Option<String>, modified: Option<bool> },
    FileCreate { path: String, is_dir: bool },
    FileDelete { path: String, is_dir: Option<bool> },
    FileRename { from: String, to: String },

    // ---------- 网络 ----------
    NetConnect {
        flow: FlowKey,
        /// 主动连接 / 被动接受 / UDP 首包。
        direction: FlowDirection,
        result: Option<i32>,
    },
    /// via=sendfile/splice 时表示数据直接来自文件描述符（仍只是 I 级线索）。
    NetSend { flow: FlowKey, bytes: u64, via: Option<IoVia> },
    NetRecv { flow: FlowKey, bytes: u64 },
    NetClose {
        flow: FlowKey,
        /// 平台提供的累计值（如 sock_diag / nettop），用于校准。
        total_sent: Option<u64>,
        total_recv: Option<u64>,
    },
    DnsQuery  { qname: String, qtype: u16, txid: Option<u16>, server: Option<std::net::IpAddr> },
    DnsAnswer { qname: String, qtype: u16, rcode: u16, answers: Vec<DnsRecord>, ttl_min: Option<u32> },
    TlsSni    { flow: FlowKey, sni: String, alpn: Vec<String> },

    // ---------- 协议（代理 / uprobe） ----------
    HttpRequest {
        /// 代理侧请求 ID，与 Response 配对。
        req_id: u64,
        /// 代理看到的客户端端点，用于归属到进程。
        client: std::net::SocketAddr,
        upstream: Option<FlowKey>,
        method: String,
        /// 已脱敏的完整 URL。
        url: String,
        http_version: String,
        /// 仅白名单请求头，值脱敏。
        headers: Vec<(String, String)>,
        body_bytes: u64,
        /// 分块哈希结果的引用（不含内容），见 evidence-model §6。
        body_digest: Option<BodyDigestRef>,
    },
    HttpResponse {
        req_id: u64,
        status: u16,
        headers: Vec<(String, String)>,
        body_bytes: u64,
        duration_ms: u32,
    },

    // ---------- Agent 自报告（E3） ----------
    AgentToolCall {
        agent: SmolStr,            // "claude-code" / "codex" / ...
        agent_session: Option<String>,
        tool: String,              // "Bash" / "Read" / "WebFetch" / ...
        phase: ToolPhase,          // pre / post
        /// 结构化参数摘要（已脱敏、已截断）。
        summary: serde_json::Value,
        call_id: Option<String>,
    },

    // ---------- 采集缺口 ----------
    Gap {
        collector: SmolStr,
        gap_kind: GapKind,          // 取值见下表 GapKind
        /// 影响的事件类别，如 ["file", "net"]。
        affects: Vec<SmolStr>,
        from_mono_ns: u64,
        to_mono_ns: u64,
        /// 已知丢失数量（不可知为 None）。
        count: Option<u64>,
        detail: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowKey {
    pub proto: L4Proto,                     // tcp / udp
    pub local: std::net::SocketAddr,
    pub remote: std::net::SocketAddr,
    /// 平台 socket 标识（Linux inode / sock 指针哈希；Windows 无则 None），用于区分复用的四元组。
    pub sock_id: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord { pub rtype: u16, pub data: String }   // A/AAAA 为 IP 字符串；CNAME 为名称

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRef { pub id: String, pub name: Option<String> }  // Unix uid / Windows SID

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BodyDigestRef { pub chunks: u32, pub digest_set_id: u64 }
```

枚举辅助类型取值：

| 类型 | 取值 |
|---|---|
| `StartHow` | `fork`, `exec`, `spawn`（Windows CreateProcess）, `snapshot`（附着快照生成） |
| `FileAccessMode` | `read`, `write`, `read_write`, `exec`, `unknown` |
| `FlowDirection` | `outbound`, `inbound`, `unknown` |
| `L4Proto` | `tcp`, `udp` |
| `ToolPhase` | `pre`, `post` |
| `GapKind` | `dropped`（管道内队列满）, `lost_by_os`（ETW EventsLost / ring buffer 丢失）, `restart`, `rate_limited`, `permission`, `attach_window`, `unsupported`, `scope_race`（进程纳入范围前的窗口）, `collector_disconnected`（采集器/扩展连接断开）, `self_report_dropped`（E3 事件丢弃）, `attribution_unknown`（事件无法归属到进程，如 fanotify pid=0）, `cache_evicted`（句柄/路径缓存淘汰）, `parse_error`（外部工具输出无法解析，如 eslogger）, `rule_state_evicted`（关联引擎状态窗口溢出） |

### 2.1 `source` 采集器前缀登记

格式为 `<采集器>/<子源>`。子源的完整列表由对应平台文档维护；采集器前缀在这里统一登记。

| 前缀 | 含义 | 子源示例 | 定义处 |
|---|---|---|---|
| `linux.ebpf` | Linux eBPF 探针 | `tcp_sendmsg`, `lsm_file_open` | [linux](../02-platforms/linux.md) |
| `linux.afpacket` | Linux AF_PACKET 兜底抓首包 | `sni` | [linux](../02-platforms/linux.md) |
| `windows.pktmon` | Windows pktmon（可选） | `sni` | [windows](../02-platforms/windows.md) |
| `linux.legacy` | Linux 降级采集（proc connector / fanotify / sock_diag） | `proc_connector`, `fanotify`, `sock_diag` | [linux](../02-platforms/linux.md) |
| `linux.uprobe` | Linux TLS uprobe（可选） | `openssl`, `go_tls` | [network-attribution](network-attribution.md) |
| `windows.etw` | Windows ETW | `kernel_process`, `kernel_file`, `kernel_network`, `dns_client` | [windows](../02-platforms/windows.md) |
| `macos.eslogger` | macOS eslogger 子进程（M1 档） | `exec`, `open` | [macos](../02-platforms/macos.md) |
| `macos.es` | macOS 原生 Endpoint Security（M2 档） | `exec`, `open` | [macos](../02-platforms/macos.md) |
| `macos.nettop` / `macos.pktap` | macOS 流量采样 / 抓包 | `flow` / `dns`, `sni` | [macos](../02-platforms/macos.md) |
| `macos.ne` | macOS Network Extension | `flow` | [macos](../02-platforms/macos.md) |
| `poll` | 跨平台轮询兜底 | `procs`, `sockets` | [fallback-poll](../02-platforms/fallback-poll.md) |
| `proxy` | aw-proxy MITM 代理 | `http`, `mitm` | [network-attribution](network-attribution.md) |
| `agent.<id>` | Agent 自报告（E3） | `hook`, `otel`, `transcript` | [process-tracking](process-tracking.md) |

## 3. 各事件的必填与常见证据

| 事件 | 必填 | 典型证据 | 备注 |
|---|---|---|---|
| `ProcessStart` | ppid, start_time_ns, how | E1；快照为 S | argv 可能为 S（补读） |
| `ProcessExit` | — | E1 | exit_code 平台可能不提供 |
| `FileOpen` | path, access | E1 | 失败的 open 也要记录，探测敏感文件但被拒也属于事实 |
| `FileRead`/`FileWrite` | bytes | E1 | 管道聚合后不单独存储 |
| `FileClose` | — | E1 | macOS 的 `modified` 来自 ES CLOSE |
| `NetConnect` | flow | E1 / S | |
| `NetSend`/`NetRecv` | flow, bytes | E1 / S | 口径见 network-attribution §2 |
| `DnsQuery`/`DnsAnswer` | qname, qtype | E1 | |
| `TlsSni` | flow, sni | E1 | |
| `HttpRequest`/`HttpResponse` | req_id, method, url | E2 | proc 由管道按 client 端口反查 |
| `AgentToolCall` | agent, tool, phase | E3 | |
| `Gap` | collector, gap_kind, 时间范围 | —（固定为 E1：缺口本身是事实） | |

## 4. 时钟域

| 平台 | 内核时间 | 换算 |
|---|---|---|
| Linux | eBPF `bpf_ktime_get_ns()`（CLOCK_MONOTONIC）或 `bpf_ktime_get_boot_ns()` | 启动时读取一次 `(MONOTONIC, REALTIME)` 对，墙钟 = 单调 + 偏移；每 60 秒重新校准 |
| Windows | ETW 事件时间戳（QPC 或 FILETIME，取决于会话 ClockType） | 会话使用 QPC，按 `QueryPerformanceFrequency` 换算；【待验证】ferrisetw 是否直接给出 FILETIME，见 [SPIKE-02](../06-research/SPIKE-02-windows-etw-poc.md) |
| macOS | ES `mach_time`；eslogger JSON 中的 `mach_time` 与 `time` | `mach_timebase_info` 换算；【待验证】[SPIKE-03](../06-research/SPIKE-03-macos-eslogger-poc.md) |
| 代理 / 轮询 / E3 | 用户态单调时钟 | 直接使用 daemon 的 `Instant` |

各来源之间可能有毫秒级偏差。关联规则的时间窗口不得小于 `correlation.clock_skew_tolerance_ms`（默认 50 ms）。

## 5. JSONL 序列化示例

每行一个事件，字段顺序固定（便于 diff）。下面连续 8 行对应“读取 SSH 密钥后发起 HTTPS 请求”：

```jsonl
{"v":1,"seq":101,"ts_mono_ns":5021000000,"ts_wall_ns":1791273662000000000,"session_id":7,"proc":{"uid":"0x9f3a11c2d4e5f601","pid":5120,"tid":5120},"source":"linux.ebpf/sched_process_exec","evidence":{"level":"E1"},"kind":"process_start","ppid":5101,"parent_uid":"0x1b2c3d4e5f607182","start_time_ns":1791273661998000000,"exe":"/usr/bin/cat","argv":["cat","/home/u/.ssh/id_rsa"],"cwd":"/home/u/proj","user":{"id":"1000","name":"u"},"how":"exec","env":null,"signer":null}
{"v":1,"seq":102,"ts_mono_ns":5021300000,"ts_wall_ns":1791273662000300000,"session_id":7,"proc":{"uid":"0x9f3a11c2d4e5f601","pid":5120,"tid":5120},"source":"linux.ebpf/lsm_file_open","evidence":{"level":"E1"},"kind":"file_open","handle":21990232555523,"path":"/home/u/.ssh/id_rsa","access":"read","created":false,"truncated":false,"result":0,"via":"syscall","path_resolved":true}
{"v":1,"seq":103,"ts_mono_ns":5021350000,"ts_wall_ns":1791273662000350000,"session_id":7,"proc":{"uid":"0x9f3a11c2d4e5f601","pid":5120,"tid":5120},"source":"linux.ebpf/sys_exit_read","evidence":{"level":"E1"},"kind":"file_read","handle":21990232555523,"path":null,"bytes":412,"offset":0}
{"v":1,"seq":104,"ts_mono_ns":5021400000,"ts_wall_ns":1791273662000400000,"session_id":7,"proc":{"uid":"0x9f3a11c2d4e5f601","pid":5120,"tid":5120},"source":"linux.ebpf/sys_enter_close","evidence":{"level":"E1"},"kind":"file_close","handle":21990232555523,"path":null,"modified":false}
{"v":1,"seq":120,"ts_mono_ns":8100000000,"ts_wall_ns":1791273665079000000,"session_id":7,"proc":{"uid":"0x1b2c3d4e5f607182","pid":4412,"tid":4431},"source":"linux.ebpf/udp_dns","evidence":{"level":"E1"},"kind":"dns_answer","qname":"api.example.com","qtype":1,"rcode":0,"answers":[{"rtype":1,"data":"203.0.113.10"}],"ttl_min":60}
{"v":1,"seq":121,"ts_mono_ns":8120000000,"ts_wall_ns":1791273665099000000,"session_id":7,"proc":{"uid":"0x1b2c3d4e5f607182","pid":4412,"tid":4431},"source":"linux.ebpf/tcp_connect","evidence":{"level":"E1"},"kind":"net_connect","flow":{"proto":"tcp","local":"10.0.0.5:51544","remote":"203.0.113.10:443","sock_id":88123},"direction":"outbound","result":0}
{"v":1,"seq":122,"ts_mono_ns":8140000000,"ts_wall_ns":1791273665119000000,"session_id":7,"proc":{"uid":"0x1b2c3d4e5f607182","pid":4412,"tid":4431},"source":"linux.ebpf/tls_clienthello","evidence":{"level":"E1"},"kind":"tls_sni","flow":{"proto":"tcp","local":"10.0.0.5:51544","remote":"203.0.113.10:443","sock_id":88123},"sni":"api.example.com","alpn":["h2","http/1.1"]}
{"v":1,"seq":123,"ts_mono_ns":8160000000,"ts_wall_ns":1791273665139000000,"session_id":7,"proc":{"uid":"0x1b2c3d4e5f607182","pid":4412,"tid":4431},"source":"linux.ebpf/tcp_sendmsg","evidence":{"level":"E1"},"kind":"net_send","flow":{"proto":"tcp","local":"10.0.0.5:51544","remote":"203.0.113.10:443","sock_id":88123},"bytes":5240}
```

macOS 上字段级 NA 的示例：

```json
{"v":1,"seq":55,"ts_mono_ns":120000,"ts_wall_ns":1791273600000000000,"session_id":3,"proc":{"uid":"0x77","pid":801,"tid":null},"source":"macos.eslogger/open","evidence":{"level":"E1"},"field_evidence":{"bytes":{"level":"NA","reason":"es_no_read_event"}},"kind":"file_open","handle":null,"path":"/Users/u/.aws/credentials","access":"read","created":null,"truncated":null,"result":0,"via":"syscall","path_resolved":true}
```

约定：
- `ProcUid` 序列化为 `0x` 开头的 16 进制字符串，避免 JavaScript 丢失 64 位精度。
- `SocketAddr` 序列化为字符串：IPv4 为 `ip:port`，IPv6 为 `[ip]:port`。
- `None` 字段写为 `null`，不省略。`field_evidence` 为空时可以省略。

## 6. Schema 版本策略

- `SCHEMA_VERSION` 为单调递增的整数，写在每条事件的 `v` 字段和 fixtures 文件头中。
- **兼容变更（不升版本）**：新增可选字段、新增 `NaReason` / `GapKind` 取值、新增 `source` 子源名。反序列化侧必须容忍未知字段和未知枚举值，枚举用 `#[serde(other)] Unknown` 兜底。
- **不兼容变更（升版本）**：删除字段、字段改名、改变语义或单位、新增 `EventKind` 变体。
  - 新增变体算不兼容，是因为旧管道不应静默丢弃未知事件。
  - 升版本时在 `aw-core::event::migrate` 中提供 `v(n-1) → v(n)` 的 JSON 转换。`fixtures/` 中的旧文件在加载时自动迁移；也可以用 `aw fixtures upgrade` 重写。
- 存储 schema 版本独立管理，见 [storage §6](storage.md#6-迁移策略)。
- 任何 schema 变更都必须同时：更新本文档；在 `fixtures/` 增加或更新样例；通过 `cargo test -p aw-core schema_roundtrip`。

## 7. 采集器实现检查清单

- [ ] 每种产生的事件都在 `capabilities()` 中声明，并写明证据等级。
- [ ] 拿不到的字段填 `None` 并写 `field_evidence`，不填 0。
- [ ] 源头丢失（ring buffer 满、ETW EventsLost）转换为 `Gap`。
- [ ] `source` 使用「采集器名/子源」格式，子源名写入对应平台文档。
- [ ] 提供录制开关：`--record fixtures/xxx.jsonl` 时输出脱敏前的事件，并附带警告。仅用于开发，提交到仓库前必须用 `aw fixtures scrub` 处理。
