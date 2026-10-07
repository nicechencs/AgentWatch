# 术语表

> 状态：草案
> 最后更新：2026-10-07
> 关联：[event-schema](../01-architecture/event-schema.md)、[evidence-model](../01-architecture/evidence-model.md)、[inter-agent-communication](../01-architecture/inter-agent-communication.md)

按类别排列。代码中的名称用反引号标出，文档和代码必须保持一致。

## 产品概念

| 术语 | 代码名 | 定义 |
|---|---|---|
| 会话 | `Session` | 一次监控过程：从 `aw run` / `aw attach` 开始，到范围内进程全部退出或用户停止为止。所有记录都属于某个会话 |
| 启动模式 | `ScopeMode::Launch` | 由 AgentWatch 创建目标进程，可以在创建前就把它放进范围容器（cgroup / Job Object） |
| 附着模式 | `ScopeMode::Attach` | 选择已有进程作为根，快照其后代并跟踪新进程 |
| 范围 | `Scope` | 判定“某进程是否属于当前会话”的集合与规则 |
| 根进程 | `root_proc` | 会话的起始进程 |
| Agent 画像 | `AgentProfile` | 对某类 Agent 的识别规则（可执行名、参数特征、自报告接入方式） |
| Agent 实例 | `AgentInstance` | 会话内被识别为 Agent 的进程子树（主 Agent / 子 Agent / MCP server）；识别本身带证据等级 |
| 通信通道 | `Channel` / `ipc_channels` | 一条可以确定两端进程的本机 IPC（管道、Unix socket、命名管道、回环） |
| 通信边 | `AgentLink` | Agent 实例之间的汇总边（`spawned` / `ipc` / `rpc` / `self_reported` / `shared_artifact` / `remote`） |
| 监控组 | `WatchGroup` | 把独立启动的多个会话组合在一起，配对组内会话之间的通道 |
| 委托链路 | `DelegationChain` | 从一条记录回溯到触发它的 Agent；每一跳标注等级，整条链取最弱一跳 |
| mcp-tap | `mcp-tap` | 启动模式下的 stdio 透明包装器，只解析 JSON-RPC 元数据，不存参数和结果内容 |
| 发现 | `Finding` | 由规则生成的结论条目，如“读取敏感文件”“时序相关的外发”；只能是 E1 事实的汇总或 I 级推测 |
| 缺口 | `Gap` | 一段时间内某类数据可能不完整的记录（丢事件、采集器重启、权限不足、限流） |
| 敏感路径规则 | `SensitivePathRule` | 标记凭证类文件的 glob 规则；命中只用于高亮，不触发额外读取 |

## 证据相关

| 术语 | 代码名 | 定义 |
|---|---|---|
| 证据等级 | `Evidence` | E1 / E2 / E3 / S / I / NA，见 [evidence-model](../01-architecture/evidence-model.md) |
| 数据来源 | `Source` | 产生该记录的具体采集器，如 `linux.ebpf/tcp_sendmsg`、`windows.etw/kernel_file`、`proxy` |
| 内容匹配证据 | `ContentMatch` | 代理模式下请求体分块哈希与本地文件分块哈希匹配；是“文件被上传”唯一可接受的证据 |
| 直连 | `direct` | 启用代理的会话中，未经过代理的外连；URL 不可得 |
| 归属中断 | `attribution_break` | 行为被委托给会话外的进程（守护进程、服务管理器），无法继续归属到会话 |

## 进程与事件

| 术语 | 代码名 | 定义 |
|---|---|---|
| 进程唯一 ID | `ProcUid` | `(pid, start_time)` 的 64 位哈希，规避 PID 复用，见 [process-tracking](../01-architecture/process-tracking.md) |
| 原始事件 | `RawEvent` | 采集器输出的统一事件 |
| 记录 | `Record` | 管道聚合后写入存储的行，如 `file_access`、`net_flows` |
| 文件访问记录 | `FileAccess` | open 到 close 之间同一句柄的聚合 |
| 网络流 | `NetFlow` | 一条传输层连接（TCP）或一组同五元组 UDP 报文的聚合 |
| 流量桶 | `FlowBucket` | 某条网络流在固定时间窗（默认 5 秒）内的字节计数 |
| 单调时间 | `ts_mono_ns` | 本次 daemon 启动后的单调纳秒，用于排序和间隔计算 |
| 墙钟时间 | `ts_wall_ns` | Unix 纪元纳秒（UTC），用于展示和跨会话查询 |

## 平台与技术

| 术语 | 定义 |
|---|---|
| eBPF | Linux 内核内的安全沙箱程序，用于在 tracepoint / kprobe / LSM 钩子上采集事件 |
| CO-RE / BTF | Compile Once – Run Everywhere；依赖内核类型信息（BTF）让一份 eBPF 字节码适配多个内核 |
| fanotify | Linux 文件系统事件通知接口，含进程 PID |
| sock_diag | Linux netlink 接口，可查询 socket 状态及字节统计 |
| ETW | Event Tracing for Windows，Windows 内核与系统组件的事件框架 |
| Job Object | Windows 进程分组机制，子进程默认继承 |
| ES | macOS Endpoint Security 框架，需要 Apple 授予的 entitlement |
| eslogger | macOS 13+ 自带命令行工具，把 ES 事件输出为 JSON；不需要自带 entitlement |
| NE | macOS Network Extension；内容过滤器（content filter）可按流观察并归属进程 |
| pktap | macOS 带进程元数据的虚拟抓包接口 |
| SNI | TLS ClientHello 中的服务器名称扩展，明文可见（ECH 除外） |
| MITM 代理 | 由 AgentWatch 本地启动的 HTTPS 显式代理，使用本地生成的 CA 解密被监控进程的流量元数据 |
| ECH | Encrypted Client Hello，会隐藏 SNI |
