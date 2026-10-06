# Windows 采集器

> 状态：草案
> 最后更新：2026-10-06
> 关联：REQ-01~04、ADR-0008、SPIKE-02、SPIKE-05、[capability-matrix](capability-matrix.md)

涉及 crate：`aw-collector-windows`，依赖 `ferrisetw` 和 `windows` crate。

## 1. 总体方案

只用 ETW，**不写内核驱动**，理由见 [ADR-0008](../03-adr/0008-windows-etw-no-driver.md)。daemon 以 Windows 服务（LocalSystem）身份运行，创建一个实时 ETW 会话 `AgentWatch-<boot>`，并启用下列 provider。

```
ETW providers ──► 实时会话(ferrisetw UserTrace) ──► 回调线程: 按 PID 范围集合立即丢弃无关事件
                                                   ──► FileObject→路径 缓存
                                                   ──► 解码 → RawEvent → aw-pipeline
会话统计(EventsLost/BuffersLost) ──► 每 5 s 查询 → Gap
```

## 2. Provider 与事件

> 以下 GUID、事件 ID 和字段名是根据公开资料整理的，**全部【待验证 SPIKE-02】**。以本机实测为准：用 `logman query providers "<名称>"` 和 `wevtutil gp <名称> /ge /gm` 导出 manifest。

### 2.1 Microsoft-Windows-Kernel-Process

GUID `{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}`，关键字：`WINEVENT_KEYWORD_PROCESS`（0x10）、`WINEVENT_KEYWORD_IMAGE`（0x40，可选）。

| 事件 ID | 名称 | 关键字段 | EventKind |
|---|---|---|---|
| 1 | ProcessStart | ProcessID, CreateTime, ParentProcessID, SessionID, ImageName | ProcessStart |
| 2 | ProcessStop | ProcessID, CreateTime, ExitTime, ExitCode, ImageName | ProcessExit |
| 5 | ImageLoad（可选） | ImageBase, ImageSize, ProcessID, ImageName | —（只用来探测 TLS 库，可选） |

- **命令行**：Kernel-Process 的 ProcessStart 不一定带 CommandLine【待验证】。拿到事件后要立即用 `NtQueryInformationProcess(ProcessCommandLineInformation)`（Win8.1+）补读，这存在竞态：短命进程可能已经退出，读到的结果标 S。
  - 备选方案 A：系统日志会话（NT Kernel Logger 或 Win10+ 的 System Trace Provider）中的 `Process_TypeGroup1` Start 事件带 CommandLine，可得 E1。代价是系统内只能有一个 NT Kernel Logger（可能与其他工具冲突）；Win11 支持多个系统日志会话【待验证】。
  - SPIKE-02 要定下来：命令行以哪个来源为主。
- **cwd**：读目标进程 PEB 中 `ProcessParameters->CurrentDirectory`，需要 `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`，结果标 S。
- **进程身份**：用 `(pid, CreateTime)`，对应 ADR-0007。

### 2.2 Microsoft-Windows-Kernel-File

GUID `{EDD08927-9CC4-4E65-B970-C2560FB5C289}`。关键字按需开启：FILENAME 0x10、FILEIO 0x20、OP_END 0x40、CREATE 0x80、READ 0x100、WRITE 0x200、DELETE_PATH 0x400、RENAME_SETLINK_PATH 0x800、CREATE_NEW_FILE 0x1000【待验证】。

| 事件 ID | 名称 | 关键字段 | EventKind |
|---|---|---|---|
| 10 | NameCreate | FileKey, FileName | （建立 FileKey→路径缓存） |
| 11 | NameDelete | FileKey | （清理缓存） |
| 12 | Create | Irp, FileObject, IssuingThreadId, CreateOptions, CreateAttributes, ShareAccess, FileName | FileOpen（CreateDisposition 为新建时是 FileCreate） |
| 14 | Close | FileObject, FileKey | FileClose |
| 15 | Read | ByteOffset, FileObject, FileKey, IOSize, IOFlags | FileRead（聚合） |
| 16 | Write | 同上 | FileWrite（聚合） |
| 26 | DeletePath | FileObject, FileKey, FilePath | FileDelete |
| 27 | RenamePath | FileObject, FileKey, FilePath（新路径） | FileRename |
| 30 | CreateNewFile | FileObject, FileName | FileCreate |

- **进程归属**：事件头里的 ProcessId 通常就是发起进程。但缓存管理器的延迟写和预读会归到 System（PID 4），这部分 I/O 会丢失归属。所以要以 **Create 事件时的进程**作为 FileObject 的归属，写入归入该 FileObject【待验证】。
- **路径格式**：得到的是 `\Device\HarddiskVolume3\...`。启动时用 `QueryDosDeviceW` 建立卷到盘符的映射，卷变化时刷新；网络路径以 `\Device\Mup\` 开头。
- **事件量**：系统级的文件事件可以达到每秒数万条，而 ETW 无法按 PID 在内核里过滤（CAP-PRIV-04）。回调中第一步就是查 PID 是否在范围集合里，用无锁结构实现，不在就立即返回，不做任何解析。【待验证】事件头里的 ProcessId 在 ferrisetw 中能否不解析 schema 就拿到。
- 也可以用 `EVENT_FILTER_TYPE_PID` 过滤：它对 manifest provider 有效、最多 8 个 PID，而且不支持动态追加子进程，所以不采用【待验证】。

### 2.3 Microsoft-Windows-Kernel-Network

GUID `{7DD42A49-5329-4832-8DFD-43D979153A88}`。

| 事件 ID | 名称 | 关键字段 | EventKind |
|---|---|---|---|
| 10 / 26 | TCP 发送（IPv4 / IPv6） | PID, size, daddr, saddr, dport, sport, connid | NetSend（聚合） |
| 11 / 27 | TCP 接收 | 同上 | NetRecv（聚合） |
| 12 / 28 | TCP 连接建立 | 同上 + mss 等 | NetConnect |
| 13 / 29 | TCP 断开 | 同上 | NetClose |
| 15 / 31 | TCP 接受 | 同上 | NetConnect（inbound） |
| 42 / 58 | UDP 发送 | PID, size, daddr, dport, … | NetSend |
| 43 / 59 | UDP 接收 | 同上 | NetRecv |

- 字节口径：`size` 是 TCP 载荷字节，包含 TLS 开销、不含头部【待验证：是否包含重传】。
- 回环流量也会产生事件。代理模式下，目标进程到 aw-proxy 的这段回环流量要与 aw-proxy 的出站流量做映射，避免重复计数（见 network-attribution）。

### 2.4 Microsoft-Windows-DNS-Client

GUID `{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}`。

| 事件 ID | 含义 | 关键字段 | EventKind |
|---|---|---|---|
| 3006 | 发起查询 | QueryName, QueryType, 事件头 PID | DnsQuery |
| 3008 | 查询完成 | QueryName, QueryStatus, QueryResults（以 `;` 分隔的地址列表） | DnsAnswer |
| 3020 | 收到应答（来自指定服务器） | 同上 | DnsAnswer（补充） |

- 在 Dnscache 代为查询的情况下，事件头 PID 是否为原始请求方【待验证 SPIKE-02，关键】。
- 自己发 UDP 53 查询、不走系统解析器的程序（如部分 Go 程序、DoH），不会产生这些事件。只能从 Kernel-Network 看到 53 端口流量；DoH 则完全不可见。

### 2.5 可选 provider

| Provider | 用途 | 备注 |
|---|---|---|
| Microsoft-Windows-WinINet / Microsoft-Windows-WinHttp | WinINet/WinHTTP 的 URL（CAP-URL-03） | 覆盖面窄，P3 以后再评估 |
| Microsoft-Windows-TCPIP | 更细的连接状态 | 事件量大，默认关闭 |
| Sysmon（如已安装） | 作为第二数据源：进程启动（事件 1，带 CommandLine）、网络（3）、DNS（22）、文件创建（11）、文件删除（23/26） | Sysmon 没有文件读取事件；只读取已有配置，不替用户安装 |

### 2.6 SNI

ETW 不提供 TLS 载荷。可选方案：
1. **pktmon**（Win10 2004+ 系统自带）：只抓 443 端口连接的前几个包，用五元组和 Kernel-Network 事件对应。【待验证】pktmon 能否以实时方式被程序读取（它本身也是 ETW provider `Microsoft-Windows-PktMon`）。
2. **WinDivert**（SNIFF 模式）：需要携带一个已签名驱动，许可证是 LGPLv3/GPLv2 双授权，作为可选组件。
3. 不采集 SNI，只用 DNS 回填域名（这是 P1 的默认做法）。

## 3. 到 RawEvent 的映射汇总

| EventKind | 来源 | 等级 | 备注 |
|---|---|---|---|
| ProcessStart / ProcessExit | Kernel-Process 1/2 | E1（命令行如果是补读的，则为 S） | |
| FileOpen / FileCreate | Kernel-File 12/30 | E1 | |
| FileRead / FileWrite | Kernel-File 15/16 聚合 | E1 | 延迟写可能丢失归属 |
| FileClose | Kernel-File 14 | E1 | |
| FileDelete / FileRename | Kernel-File 26/27 | E1 | |
| NetConnect / NetClose / NetSend / NetRecv | Kernel-Network | E1 | |
| DnsQuery / DnsAnswer | DNS-Client 3006/3008 | E1 | |
| TlsSni | pktmon / WinDivert（可选） | E1 | |
| HttpRequest / HttpResponse | aw-proxy | E2 | |
| Gap | EventsLost、会话被停止、provider 启用失败 | — | |

## 4. 范围追踪

### 4.1 启动模式

1. CLI（普通权限）用 `CREATE_SUSPENDED` 创建目标进程，这样继承用户桌面、令牌和控制台。
2. CLI 创建 Job Object，调用 `AssignProcessToJobObject`，然后把 Job 句柄的副本交给 daemon：可以通过 `DuplicateHandle` 到 daemon 进程，或者给 Job 命名【待验证 SPIKE-05】。
3. 用 `JobObjectAssociateCompletionPortInformation` 关联一个 IOCP，接收 `JOB_OBJECT_MSG_NEW_PROCESS` 和 `JOB_OBJECT_MSG_EXIT_PROCESS`，并更新范围集合。
4. `ResumeThread`。
5. **不**设置 `JOB_OBJECT_LIMIT_BREAKAWAY_OK`。子进程如果尝试用 `CREATE_BREAKAWAY_FROM_JOB` 脱离，会失败。【待验证】这是否会影响某些程序正常运行，比如 Chrome、VS Code 会自己用 Job。Win8+ 支持嵌套 Job。
6. 在 IOCP 消息到达之前，ETW 事件可能已经到了，所以需要**一个小的待定缓冲**：未知 PID 的事件暂存 200 ms，再用 ProcessStart 的 ParentProcessID 判断是否属于范围。

### 4.2 附着模式

- 用 `CreateToolhelp32Snapshot` 拿快照，按父 PID 建树。注意 Windows 的父 PID 可能已经被复用，要校验父进程的 CreateTime 是否早于子进程。
- 之后依靠 Kernel-Process 的 ProcessStart.ParentProcessID 增量维护。
- 不对已在运行的进程加 Job，以免改变目标行为。

## 5. 权限与安装

- 服务名 `AgentWatch`，以 LocalSystem 运行，启动类型可以选“手动”（由 CLI 请求启动）或“自动（延迟）”。
- 创建 ETW 实时会话，需要管理员、`Performance Log Users` 组或 SYSTEM 身份。
- 读取其他进程的 PEB 需要 `SeDebugPrivilege`；PPL 保护的进程读不了，对 Agent 场景影响不大。
- 安装包：MSI（WiX），或用 `dist` 生成的安装器。代码签名用 OV/EV 证书，也可以用 Azure Trusted Signing，可以减少 SmartScreen 警告。
- 服务崩溃自动重启：`sc failure` 配置 3 次重启。
- ETW 会话在进程异常退出后会残留。启动时先按名字 `ControlTrace(STOP)` 停掉旧会话。

## 6. 已知坑

| 问题 | 对策 |
|---|---|
| ETW 实时缓冲区被压满时会丢事件 | `BufferSize=256KB`、`MinimumBuffers=64`、`MaximumBuffers=1024`【待调优】；回调里不做阻塞操作，只把事件推入有界通道；`EventsLost` 增长时写 Gap |
| FileObject 地址会被复用 | 在 Close 时删除映射；以 `(FileObject, Create 时间)` 为唯一键 |
| 开启代码完整性或 HVCI 的机器 | 不影响 ETW |
| Defender 等 EDR 也在使用 ETW | 互不干扰；但 NT Kernel Logger 是独占的 |
| 大量来自杀软、索引服务、搜索服务的文件事件 | 按 PID 范围尽早丢弃 |
| 句柄继承和 `DuplicateHandle` | 文件可以由 A 打开、由 B 读取。归属以实际发起 I/O 的进程为准，同时保留打开者字段 |
| WSL2 内部的进程 | 在 Windows 侧只能看到 `vmmem`/`wsl.exe`；WSL2 内部要单独运行 Linux 采集器。标为“链路中断” |

## 7. 测试方法

- 单元测试：将 ETW 事件序列化到 `fixtures/windows/*.jsonl`，以此测试解码和 FileObject 缓存。
- 端到端：GitHub 托管的 `windows-latest` runner 默认是管理员身份，可以创建 ETW 会话【待验证】，在上面跑 `sim/` 剧本。
- 对照验证：用 Process Monitor（Sysinternals）人工核对文件事件；用 `pktmon` 核对流量。

## 8. 可参考的开源项目

| 项目 | 许可证 | 参考什么 |
|---|---|---|
| ferrisetw | MIT / Apache-2.0 | 直接依赖 |
| krabsetw（Microsoft） | MIT | API 用法、性能实践 |
| SilkETW | Apache-2.0 | provider 配置、事件字段说明 |
| Sealighter | BSD-3-Clause【待验证】 | provider 与关键字的组合 |
| PerfView / TraceEvent | MIT | 内核事件解析、FileObject 映射 |
| bandwhich | MIT | Windows 上进程与连接的映射 |
| WinDivert | LGPLv3 / GPLv2 | 可选的抓包组件 |
