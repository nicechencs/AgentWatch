# Agent 间通信监控

> 状态：草案
> 最后更新：2026-10-07
> 关联：REQ-11、CAP-IPC、[ADR-0013](../03-adr/0013-inter-agent-observation.md)、[SPIKE-09](../06-research/SPIKE-09-ipc-peer-attribution.md)、[P6 任务](../04-plan/tasks/P6-inter-agent.md)

## 1. 问题

一个工作流里常常同时跑着多个 Agent，比如：

- 主 Agent 派生子 Agent（subagent、`codex exec`）；
- Agent 调用 MCP server，MCP server 又去读文件、联网；
- 编排器把任务分给多个并行 Agent，它们通过共享目录或 git 仓库交换结果；
- 本机 Agent 与远端 Agent 经 A2A 一类协议对话。

审计时需要回答三个问题：**谁和谁通信了、通过什么通道、传了多少**；以及一个敏感操作的**委托链路**，即它是不是由另一个 Agent 间接触发的。

本文档沿用[证据模型](evidence-model.md)：能证明的只是“存在通信通道且传输了 N 字节”。“A 指示 B 做了某事”只有在协议层可见（E2）或自报告（E3）时才能呈现，而且结论仍是推测。

## 2. 通信形态与可观测性

| # | 形态 | 典型例子 | 能观测到什么 | 最高等级 |
|---|---|---|---|---|
| T1 | 父子派生 + 管道 | 主 Agent 启动子 Agent 并经 stdin/stdout 传任务；MCP stdio server | 进程树（已有）；管道两端与字节数；MCP 的 JSON-RPC method / tool 名 | E1（通道与字节）/ E2（协议元数据） |
| T2 | 本机 socket | MCP over HTTP/SSE、streamable HTTP（回环 TCP）；Unix socket；Windows 命名管道 | 两端进程、字节数；经本地代理时可见 HTTP 元数据 | E1 / E2 |
| T3 | 跨主机网络 | A2A、自建编排服务、经云 API 中转 | 本机一侧的连接与字节（已有）；对端是否为 Agent、对端做了什么 | E1（本机侧）；对端 NA，除非多机关联 |
| T4 | 间接通信 | 共享文件/目录（任务队列、计划文件）、git 仓库、本地数据库、剪贴板 | A 写了 X、B 之后读了 X | **I**（时序推测） |
| T5 | 同一进程内多 Agent | LangGraph / AutoGen / CrewAI 在单个 Python 进程内多角色 | OS 层面完全不可见 | **E3**（框架 OTEL span / hooks） |

结论：T1/T2 是本功能的重点，可以拿到 E1 证据；T3 要靠多机关联（可选扩展）；T4 只能推测；T5 只能靠自报告。UI 必须按形态如实标注等级。

## 3. 概念模型

### 3.1 Agent 实例（AgentInstance）

会话内被识别为 Agent 的进程子树。识别依据：`AgentProfile` 匹配（[process-tracking §7](process-tracking.md#7-agent-识别)）、MCP server 特征（由 Agent 以 stdio 方式拉起、命令行匹配 MCP 配置）、或用户手工标注。

```rust
pub struct AgentInstance {
    pub id: AgentInstanceId,
    pub session_id: SessionId,
    pub root: ProcUid,            // 该 Agent 的根进程
    pub profile: Option<String>,  // AgentProfile.id，如 "claude-code" / "mcp-server"
    pub role: AgentRole,          // Primary / SubAgent / McpServer / Tool / Unknown
    pub parent: Option<AgentInstanceId>,  // 派生关系（T1）
    pub evidence: Evidence,       // 识别依据的等级：规则匹配为 I，自报告为 E3，用户标注单独标记
}
```

> “这是一个 Agent”本身是判断，不是事实：UI 中显示“识别为 Claude Code（规则匹配）”。

### 3.2 通信通道（Channel）与通信边（AgentLink）

- **Channel**：一条可以确定两端进程的本机 IPC 通道，包括匿名管道、Unix socket、命名管道、回环 TCP/UDP。记录两端 ProcUid、类型、各方向字节数、起止时间，以及识别出的应用协议。
- **AgentLink**：Agent 实例之间的汇总边，由底层证据聚合而来。每条边带 `kind` 与证据等级：

| kind | 来源 | 等级 |
|---|---|---|
| `spawned` | 进程树：A 的子树中启动了 B 的根 | E1 |
| `ipc` | Channel：两端分别属于 A、B | E1 |
| `rpc` | Channel 上识别出 JSON-RPC / HTTP 请求（如 MCP `tools/call`） | E2 |
| `self_reported` | Agent 自报告“把任务交给了 B”（subagent 调用、OTEL span link） | E3 |
| `shared_artifact` | A 写入或修改文件 X，之后 B 读取 X | I |
| `remote` | 两台受监控主机上，一端的出站连接与另一端的入站连接五元组对应 | E1（两侧各自）+ I（配对） |

### 3.3 监控组（Watch Group）

现有会话是“一个根进程加一棵树”。多 Agent 场景有两种形态：

1. **同一棵树**（主 Agent 派生子 Agent 或 MCP server）：不需要新概念，在会话内识别多个 AgentInstance 即可。
2. **各自独立启动**（两个终端分别跑两个 Agent，或一个 Agent 连到已在运行的 MCP server）：引入**监控组**。一个组包含多个会话，组内会话之间的通道会被配对。

```
aw group create review-flow
aw run --group review-flow --agent claude -- claude
aw attach --group review-flow --pid 5120           # 已在运行的 MCP server 或其他 Agent
aw group graph review-flow                         # 输出 Agent 通信图
```

**对端不在任何会话内时**，就是普通的“与会话外进程通信”：记录对端的 PID、可执行文件和字节数，但不追踪对端的行为。对端属于已知守护进程时，按归属中断处理（[process-tracking §6](process-tracking.md#6-归属中断的识别)）。对端被 `AgentProfile` 识别为 Agent 时，在 UI 中提示“建议把该进程加入监控组”。

## 4. 平台采集方案

编号见能力矩阵 [CAP-IPC](../02-platforms/capability-matrix.md#10-agent-间通信cap-ipc)。下表各项均待验证，对应 [SPIKE-09](../06-research/SPIKE-09-ipc-peer-attribution.md)。

| 能力 | Linux | Windows | macOS |
|---|---|---|---|
| 匿名管道两端 | `pipe2` / `dup2` / fork 继承链 + eBPF `pipe_write` / `pipe_read`（或 vfs_write 过滤 pipefs）计字节；用 pipe inode 配对两端 | CreateProcess 的 `hStdInput/Output` 继承关系只能近似推断；字节数可用 Kernel-File 对 NPFS 的 Read/Write【待验证】 | ES 没有管道读写事件；进程树 E1，字节数 NA；M2 可评估 libproc `PROC_PIDFDPIPEINFO` 采样配对（S） |
| Unix socket / 命名管道 | eBPF `unix_stream_sendmsg` / `unix_dgram_sendmsg` 计字节；`unix_stream_connect` 取对端 sock 配对；兜底 `sock_diag`（UNIX_DIAG_PEER）采样 | 命名管道 = NPFS 文件：Kernel-File Create 给出 `\\Device\\NamedPipe\\<name>` 和打开方进程；服务端用 `GetNamedPipeServerProcessId` 或快照推断 | ES `uipc_connect` / `uipc_bind` 拿到两端路径；字节数 NA（M1）；M2 可评估 libproc 采样 |
| 回环 TCP/UDP | 已有的 TCP 探针；用两端的五元组互为镜像配对 | Kernel-Network 回环事件带两端 PID【待验证】 | M1：nettop + libproc 快照配对（S）；M2：NE 不覆盖回环，仍为 S【待验证】 |
| 协议识别（E2） | 对已配对的 Agent 通道，在用户态解析前 N 字节：管道内容需要 eBPF 读取缓冲区（可选、默认关闭）或在启动模式下注入包装器（见 §5） | 同左，只用包装器方案 | 同左，只用包装器方案 |

**资源控制**：管道和 Unix socket 的流量很大（编译器、shell 管道）。只对**两端都属于不同 AgentInstance**、或一端是 Agent 且另一端在会话外的通道做按字节计数；同一 Agent 内部的管道只统计总数。过滤在内核侧完成（Linux：用 BPF map 保存“Agent 根 ProcUid 集合”）。汇聚沿用 5 秒桶（[ADR-0011](../03-adr/0011-aggregate-first.md)）。

## 5. 协议层（E2）：MCP 与常见 Agent 协议

### 5.1 为什么单独处理 MCP

MCP 是目前 Agent 调用外部能力的主要通道。审计者最关心的是“哪个工具被调用、由哪个 MCP server 执行、该 server 随后做了什么”。把 `tools/call` 与 server 进程的文件和网络事件对齐，就能得到委托链路。

### 5.2 采集方式

| 传输 | 方式 | 注意 |
|---|---|---|
| stdio | **启动模式下的透明包装器**：`aw run --mcp-tap` 生成一份临时 MCP 配置，把每个 server 命令替换为 `aw mcp-tap -- <原命令>`。包装器原样转发 stdin/stdout，只解析 JSON-RPC 帧头。 | 需要 Agent 支持通过参数或环境变量指定 MCP 配置文件【待验证，SPIKE-09】。不修改用户的原始配置文件 |
| HTTP / SSE / streamable HTTP | 复用 aw-proxy：回环地址默认不经代理（`NO_PROXY`），`--mcp-tap` 时改为对已知 MCP 端口做反向代理 | TLS 回环很少见；若使用 TLS，按代理规则处理 |
| 未启用 tap | 只有 §4 的通道与字节（E1）；工具名为 NA（`protocol_not_observed`） | 可用 Agent 自报告（PreToolUse 中的 `mcp__server__tool`）作为 E3 补充 |

### 5.3 记录内容（默认）

- 记录：JSON-RPC `method`（`initialize`、`tools/list`、`tools/call`、`resources/read`…）、`params.name`（工具名）、`id`、请求/响应字节数、耗时、是否出错、server 的 `serverInfo.name/version`。
- 不记录：`arguments` 和 `result` 的内容。只记录参数键名列表和值的类型与长度；`resources/read` 的 URI 经脱敏后记录。
- 内容哈希：启用 `--mcp-tap` 时，可以对 `arguments` 做与代理相同的分块哈希，用来发现“敏感文件内容被作为参数传给工具”（内容匹配证据，规则同 [evidence-model §6](evidence-model.md#6-内容哈希匹配i--内容匹配证据的唯一升级路径)）。

### 5.4 其他协议

| 协议 | 识别方式 | 阶段 |
|---|---|---|
| A2A（Agent2Agent） | 经代理时按 Agent Card 路径（`/.well-known/agent.json` 一类）与 JSON-RPC method 识别【待验证：协议细节以实施时的规范为准】 | P6 |
| LSP / DAP | 编辑器类 Agent（Cursor）与语言服务器之间的 stdio；只记录 method 与字节 | 可选 |
| 自定义 | 用户编写协议描述（帧格式 + method 字段路径），放在 `aw-agent-adapters` 中 | 以后扩展 |

## 6. 间接通信（T4）与委托链路

### 6.1 共享工件关联

新增内置规则 `agent_shared_artifact`（I 级）：AgentInstance A 写入或修改文件 X（`file_access.modified=1`），之后 AgentInstance B 以读方式打开 X。

- 过滤噪声：排除构建产物目录、缓存、锁文件、`.git/objects`。可配置“协作目录”以提高优先级。
- git 特例：A 提交或推送、B 拉取时，按 `.git/refs` 的写与读关联。
- 措辞：“【推测·共享文件】A 在 10:01 修改了 `plan.md`，B 在 10:03 读取了该文件。这说明两者可能通过该文件交换信息；没有证据表明 B 的后续行为由此触发。”

### 6.2 委托链路（Delegation Chain）

审计的核心视图：从一个敏感事件（如读取 `~/.ssh/id_rsa`、向未知域名外发）出发，向上回溯：

```
[E1] mcp-server-fs(pid 7001) 读取 ~/.ssh/id_rsa
  ↑ [E2] 10:01:02.120 tools/call read_file（经 mcp-tap）
  ↑ [E1] claude(pid 4412) ↔ mcp-server-fs  stdio 管道，发送 1.2 KB / 接收 3.4 KB
  ↑ [E3] PreToolUse mcp__fs__read_file（Claude Code hook）
  ↑ [E1] claude(pid 4412) 由用户终端启动（aw run）
```

规则：
- 每一跳单独标注等级，**整条链的结论等级取各跳中最弱的一级**；链路中只要有一跳是 I，结论就只能是推测。
- E2/E1 按时间和通道对齐：只有 `tools/call` 的请求与响应之间、由同一 server 进程子树产生的事件，才归入该次调用。并发调用重叠时标注“无法区分是哪一次调用”。
- 禁止措辞：“A 让 B 窃取了…”“A 通过 B 上传了…”。允许的措辞见 evidence-model 中的 `ipc.*` / `delegation.*` 模板。

## 7. 存储

新增表（迁移在 P6-STORE-01）：

```sql
CREATE TABLE agent_instances (
  id            INTEGER PRIMARY KEY,
  session_id    INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  root_proc_uid INTEGER NOT NULL,
  profile       TEXT,
  role          TEXT NOT NULL,             -- primary / sub_agent / mcp_server / tool / unknown
  parent_id     INTEGER REFERENCES agent_instances(id),
  evidence      TEXT NOT NULL,
  label         TEXT                       -- 用户标注的名称
);

CREATE TABLE ipc_channels (
  id            INTEGER PRIMARY KEY,
  session_id    INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  kind          TEXT NOT NULL,             -- pipe / unix_stream / unix_dgram / named_pipe / loopback_tcp / loopback_udp
  a_proc_uid    INTEGER NOT NULL,
  b_proc_uid    INTEGER,                   -- NULL = 对端未知（见 field_evidence）
  b_session_id  INTEGER,                   -- 对端在同组另一个会话中时填写
  name          TEXT,                      -- socket 路径 / 管道名 / 端口（已脱敏）
  a_to_b_bytes  INTEGER,
  b_to_a_bytes  INTEGER,
  protocol      TEXT,                      -- mcp / a2a / lsp / http / unknown
  first_ns      INTEGER NOT NULL,
  last_ns       INTEGER NOT NULL,
  evidence      TEXT NOT NULL,
  field_evidence TEXT,
  source        TEXT NOT NULL
);
CREATE INDEX idx_ipc_session ON ipc_channels(session_id, first_ns);

CREATE TABLE agent_rpc (
  id            INTEGER PRIMARY KEY,
  channel_id    INTEGER NOT NULL REFERENCES ipc_channels(id) ON DELETE CASCADE,
  ts_ns         INTEGER NOT NULL,
  duration_ns   INTEGER,
  method        TEXT NOT NULL,             -- tools/call / resources/read / ...
  target        TEXT,                      -- 工具名 / 资源 URI（已脱敏）
  arg_shape     TEXT,                      -- JSON：键名 → {type, len}
  req_bytes     INTEGER,
  resp_bytes    INTEGER,
  is_error      INTEGER,
  content_match TEXT,                      -- 内容哈希命中的文件引用（可选）
  evidence      TEXT NOT NULL              -- E2
);

CREATE TABLE agent_links (                 -- 由管道 Correlate 阶段生成的汇总边
  id            INTEGER PRIMARY KEY,
  group_id      INTEGER,                   -- 监控组；单会话时为 NULL
  session_id    INTEGER NOT NULL,
  from_agent    INTEGER NOT NULL REFERENCES agent_instances(id),
  to_agent      INTEGER REFERENCES agent_instances(id),
  to_external   TEXT,                      -- 对端不在监控范围内时的描述（exe / 主机）
  kind          TEXT NOT NULL,             -- spawned / ipc / rpc / self_reported / shared_artifact / remote
  bytes         INTEGER,
  count         INTEGER NOT NULL DEFAULT 1,
  first_ns      INTEGER NOT NULL,
  last_ns       INTEGER NOT NULL,
  evidence      TEXT NOT NULL,
  refs          TEXT NOT NULL              -- JSON：依据记录
);

CREATE TABLE watch_groups (
  id            INTEGER PRIMARY KEY,
  name          TEXT NOT NULL UNIQUE,
  created_ns    INTEGER NOT NULL
);
-- sessions 表新增列：group_id INTEGER REFERENCES watch_groups(id)
```

新增事件类型（`EventKind`，属于兼容变更）：`IpcOpen { kind, peer, name }`、`IpcTransfer { channel, direction, bytes }`、`IpcClose`、`AgentRpc { method, target, arg_shape, req_bytes, resp_bytes, is_error }`。

## 8. CLI 与 UI

**CLI**（写入 [api-and-cli](api-and-cli.md)）：

```
aw group create|list|show|delete <name>
aw run|attach ... --group <name> [--mcp-tap]
aw agents <SESSION|--group NAME>            Agent 实例列表与角色
aw links <SESSION|--group NAME> [--kind ...] [--min-evidence E1]
aw rpc <SESSION> [--method tools/call] [--target <glob>]
aw chain <SESSION> <TABLE>:<ID>             从某条记录回溯委托链路
aw group graph <name> [--format dot|mermaid|json]
aw mcp-tap -- <cmd>                          （内部使用）stdio 透明包装器
```

**UI**（写入 [ui](ui.md)）：
- **Agent 通信图**（`/s/:sid/agents`、`/g/:gid`）：节点为 AgentInstance，边的线型表示等级（实线 E1、点划线 E2、虚线 E3 或 I），线宽表示字节数；点击边显示依据记录。
- **MCP 调用列表**：按 server 和 工具分组，展开后显示该次调用期间 server 子树的文件与网络事件。
- **委托链路面板**：在时间线任一事件上右键 → “追溯来源”。

## 9. 跨主机（T3）—— 可选扩展

1.0 不做集中式监控（见 requirements 非目标）。实用的中间方案是**离线合并**：

1. 各主机独立采集，用 `aw export --format jsonl` 导出会话；
2. `aw merge a.jsonl b.jsonl -o merged.db` 在一台机器上合并，按连接五元组镜像配对（需要考虑 NAT，配不上时保持为单侧），并结合时钟偏差估计对齐时间线；
3. 配对成功的连接生成 `remote` 边，配对本身为 I 级。

实时的多机汇聚留待 1.x 之后评估，并需要单独的威胁模型（网络传输、鉴权、多用户隐私）。

## 10. 隐私与安全

- Agent 间通信的内容往往包含提示词、代码甚至凭证，**默认不存内容**，只存 method、工具名、参数形状和字节数。
- `mcp-tap` 包装器以用户权限运行，经本地 socket 把元数据发给 daemon；解析失败时必须原样透传，不影响 Agent 运行（fail-open），并写缺口。
- 使用 eBPF 读取管道缓冲区（仅 Linux、默认关闭）与 TLS uprobe 的审批级别相同：需要显式配置 `collectors.linux.ipc_payload_peek`，UI 显著提示。
- 威胁模型补充见 [security-privacy](security-privacy.md)：包装器被劫持、伪造 MCP 元数据（只影响 E2，不影响 E1 的通道与字节）。

## 11. 开放问题

1. 各 Agent 是否支持外部指定 MCP 配置，从而让 `--mcp-tap` 无侵入生效？（SPIKE-09）
2. Windows 上匿名管道的两端配对精度？（SPIKE-09）
3. macOS M1/M2 下 Unix socket 字节数是否只能 NA？（SPIKE-09）
4. 同进程多 Agent 框架（T5）的 OTEL 语义约定是否足够稳定，可以通用解析？（P6-AGENT-02 调研）
