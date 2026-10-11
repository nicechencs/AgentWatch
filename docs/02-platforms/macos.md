# macOS 采集器

> 状态：草案
> 最后更新：2026-10-07
> 关联：REQ-01~04、REQ-11、ADR-0009、ADR-0013、SPIKE-03、SPIKE-05、SPIKE-08、SPIKE-09、[capability-matrix](capability-matrix.md)、[inter-agent-communication](../01-architecture/inter-agent-communication.md)

涉及 crate 和目录：`aw-collector-macos`（Rust）、`macos-ext/`（Swift 编写的 Network Extension 系统扩展，第二步才用）。

macOS 是三平台中**风险最高**的一个：原生能力依赖 Apple 审批的授权（entitlement），而且 CI 上无法做全自动的端到端测试。因此采用**两步走**，见 [ADR-0009](../03-adr/0009-macos-two-step.md)。

| | 第一步 M1（P1–P3） | 第二步 M2（P4） |
|---|---|---|
| 进程与文件 | 系统自带的 `eslogger`，输出 JSON | 用 `endpoint-sec` crate 直接调用 ES API |
| 网络字节 | `nettop` 采样 | NE 内容过滤（`NEFilterDataProvider`） |
| DNS / SNI | pktap（`tcpdump -i pktap -k`） | NE + pktap |
| 授权 | 不需要；只要 root 和完全磁盘访问 | ES 授权、NE 授权、Developer ID 签名、公证 |
| 打包 | 命令行工具加 LaunchDaemon | `.app` 包含系统扩展，分发为 pkg |
| 网络等级 | S | E1 |

## 1. 第一步：eslogger + nettop + pktap

### 1.1 eslogger（进程与文件）

- macOS 13 起系统自带 `/usr/bin/eslogger`，用法是 `eslogger <event types...>`，向 stdout 输出每行一条的 JSON。需要 root，并且要给**调用它的进程**（即我们的 daemon）授予完全磁盘访问（TCC）。
- Apple 声明其输出格式**不保证稳定**。应对措施：
  - 解析器做成宽松模式，未知字段忽略、缺失字段置为 NA。
  - 按 macOS 主版本录制 fixture：`fixtures/macos/eslogger-<ver>/`。
  - 输出里的 `version` 字段（ES 消息版本）要记录下来。
- 订阅的事件（名称与 ES 的 `ES_EVENT_TYPE_NOTIFY_*` 对应）：

| eslogger 事件 | ES 类型 | 关键字段（JSON 路径【待验证 SPIKE-03】） | EventKind |
|---|---|---|---|
| `exec` | NOTIFY_EXEC | `event.exec.target.executable.path`、`event.exec.args`、`event.exec.cwd.path`、`process.audit_token.pid`、`process.ppid`、`process.responsible_audit_token` | ProcessStart |
| `fork` | NOTIFY_FORK | `event.fork.child.audit_token` | ProcessStart（`exec=false`） |
| `exit` | NOTIFY_EXIT | `event.exit.stat` | ProcessExit |
| `open` | NOTIFY_OPEN | `event.open.file.path`、`event.open.fflag` | FileOpen |
| `close` | NOTIFY_CLOSE | `event.close.target.path`、`event.close.modified` | FileClose（`modified=true` 时同时生成一条不带字节数的 FileWrite） |
| `create` | NOTIFY_CREATE | `event.create.destination` | FileCreate |
| `write` | NOTIFY_WRITE | `event.write.target.path` | FileWrite（事件量大，默认关闭，用 close.modified 代替） |
| `unlink` | NOTIFY_UNLINK | `event.unlink.target.path` | FileDelete |
| `rename` | NOTIFY_RENAME | `event.rename.source.path`、`event.rename.destination` | FileRename |
| `truncate` | NOTIFY_TRUNCATE | `event.truncate.target.path` | FileWrite |
| `mmap`（可选） | NOTIFY_MMAP | `event.mmap.source.path`、protection | FileOpen（`via=mmap`） |

- **eslogger 不支持按进程过滤**：它会输出全系统事件，`open` 事件量非常大，可能达到每秒上万条。所以：
  - JSON 解析前先做快速过滤：用 `memchr` 找到 `"pid":` 后的数字，不在范围集合内就丢弃。
  - 要测量常驻开销。如果不可接受，就不订阅 `open`，只用 `close.modified`、`create`、`unlink`、`rename`【待验证 SPIKE-03】。
- 丢失检测：检查 `seq_num`（每种事件各自计数）和 `global_seq_num` 是否连续，出现跳号就写 Gap。
- 进程管理：daemon 以子进程方式启动 eslogger，它意外退出时写 Gap 并重启，重启间隔按指数退避增长。

### 1.2 nettop（网络字节）

- 命令：`nettop -L 0 -s <间隔> -x -J bytes_in,bytes_out -m tcp` 等，输出 CSV。参数细节【待验证 SPIKE-03】：
  - `-L 0` 表示无限次采样；
  - `-P` 只给进程级汇总，不加则给出每条连接；
  - 进程列的格式是 `name.pid`。
- 采样间隔默认 1 s，取累计值做差分。寿命短于一个采样间隔的连接会被漏掉，所以等级为 **S**。
- 是否包含 UDP/QUIC【待验证】。
- 仅用作兜底时，也可以用 libproc：`proc_pidinfo(PROC_PIDLISTFDS)` + `proc_pidfdinfo(PROC_PIDFDSOCKETINFO)` 查出进程持有的 socket 及其五元组，但拿不到字节数。
- 私有框架 `NetworkStatistics.framework`（nettop 底层就是它）可以拿到实时回调。这是私有 API，**不采用**，只在此记录。

### 1.3 pktap（DNS 与 SNI）

- `tcpdump -i pktap,all -k NP -w - 'port 53 or (tcp port 443 and tcp[tcpflags] & tcp-push != 0)'`。加 `-k` 时，包元数据里带进程名和 PID【待验证 SPIKE-03：参数与 pcapng 输出中元数据的解析方式】。
- 也可以让 daemon 用 libpcap 直接打开 pktap 接口，省掉一个子进程。
- DNS 归属：系统解析走 mDNSResponder，抓到的包都属于 mDNSResponder，**原始请求进程不可得**（CAP-DNS-02）。处理办法：把解析结果放进全局 DNS 缓存，再用目标 IP 回填域名，等级为 I。

## 2. 第二步：原生 ES + Network Extension

### 2.1 原生 ES（替换 eslogger）

- 用 `endpoint-sec` crate（封装 `EndpointSecurity.framework`）在 daemon 内创建 ES client。
- 优势如下：
  - **反向 mute**（macOS 13+）：用 `es_invert_muting(ES_MUTE_INVERSE_TYPE_PROCESS)` 只接收目标进程的事件，开销大幅下降。
  - 可以按路径前缀做 mute，去掉噪声。
  - 拿到的是结构化的 `es_message_t`，没有 JSON 解析开销。
- 授权：`com.apple.developer.endpoint-security.client`。只订阅 NOTIFY 事件，不用 AUTH，因为本工具只审计、不拦截。
- 可以做成 LaunchDaemon（带授权的可执行文件），而不必做成系统扩展；但可执行文件必须放在 app bundle 内，授权才能生效【待验证 SPIKE-08】。

### 2.2 Network Extension（按连接统计字节）

- `macos-ext/`：Swift 编写的系统扩展，实现 `NEFilterDataProvider`。
  - `handleNewFlow`：记录 `sourceAppAuditToken`（从中取 PID）、`remoteEndpoint`、`remoteHostname`（有时能拿到应用请求的主机名）。
  - 返回 `.filterDataVerdict(withFilterInbound: true, peekInboundBytes: …, filterOutbound: true, peekOutboundBytes: …)`，在数据回调里累计字节数，始终放行。
  - 【待验证】全量 peek 的性能代价；以及能否改用 `NEFilterReport` 或流结束时的报告只拿到字节总数。
- 与 daemon 通信：系统扩展通过 XPC（Mach service）把流事件推给 daemon。消息结构要简单，字段与 RawEvent 一一对应。
- 生命周期：
  1. 主 app 用 `OSSystemExtensionRequest.activationRequest` 安装扩展；
  2. 用户在“系统设置 → 通用 → 登录项与扩展”中批准；
  3. 用 `NEFilterManager` 启用过滤器。
  卸载时要发送 `deactivationRequest`，对应 NFR-09。
- 注意：内容过滤器挂了会影响系统全局网络。扩展崩溃时要 fail-open，不能断网。这是实现时的硬性要求。

### 2.3 Apple 授权申请流程（SPIKE-08 负责跟踪）

1. 注册 Apple Developer Program。建议用组织账号；个人账号也可以申请。年费约 99 美元。
2. **Endpoint Security**：在开发者网站提交 *Endpoint Security entitlement* 申请表，说明用途（本地审计、只用 NOTIFY 事件、不采集内容、不外发数据）。审批周期从数天到数周不等【待验证】。
3. **Network Extension**：`com.apple.developer.networking.networkextension` 中的 `content-filter-provider-systemextension`。以 Developer ID 分发时，能否在开发者后台自助勾选、是否还需要单独申请【待验证】。
4. **System Extension**：`com.apple.developer.system-extension.install`。
5. 创建带上述授权的 Developer ID provisioning profile，并嵌入 app bundle。
6. 签名要用 Developer ID Application 证书，开启 Hardened Runtime；然后用 `notarytool submit` 公证，再 `stapler staple`。
7. CI：证书和 App Store Connect API Key 存入 GitHub Secrets，由 `ci-release.md` 描述的 macOS 发布任务完成签名和公证。
8. 本地开发可以关闭 SIP 和 AMFI 用于调试（`csrutil disable`），**只限专用测试机**。

> 授权未下来之前，产品保持在 M1 档位。能力矩阵和 UI 如实显示“网络：采样（S）”。

## 3. 到 RawEvent 的映射汇总

| EventKind | M1 来源 | M2 来源 | 等级（M1/M2） |
|---|---|---|---|
| ProcessStart / ProcessExit | eslogger exec/fork/exit | ES | E1 / E1 |
| FileOpen / FileCreate / FileClose / FileDelete / FileRename | eslogger | ES | E1 / E1 |
| FileRead | 只能从 open 的 fflag 得知“以读方式打开”；字节数 NA | 同左 | E1（动作），字节数 NA |
| FileWrite | close.modified / truncate | ES write（可选） | E1，字节数 NA |
| NetConnect / NetClose | nettop 快照的差分 | NE handleNewFlow / 流结束 | S / E1 |
| NetSend / NetRecv | nettop | NE 数据回调 | S / E1 |
| DnsQuery / DnsAnswer | pktap（归属于 mDNSResponder） | 同左 | E1（但发起进程为 I） |
| TlsSni | pktap | NE `remoteHostname` + pktap | E1 |
| HttpRequest / HttpResponse | aw-proxy | aw-proxy | E2 |
| IpcOpen / IpcClose | ES `uipc_connect` / `uipc_bind`；管道用进程树 + libproc `PROC_PIDFDPIPEINFO` 采样（CAP-IPC，P6） | 同左 | 连接 E1 / 配对 S / 字节 NA；机制待 SPIKE-09 |
| AgentRpc | `mcp-tap` / `proxy/mcp` | 同左 | E2 |
| Gap | seq_num 跳号、eslogger/nettop 退出 | seq_num 跳号、扩展断连 | — |

## 4. 范围追踪

macOS 没有与 cgroup 或 Job 等价的、能自动覆盖后代进程的公开机制。所以统一采用**进程树跟踪**：

1. 启动模式：`aw run` 和后台新建会话都经 `aw-platform` 起一个闸门，闸门是本程序自己的一份副本。闸门用写死的环境启动（只有 `PATH=/usr/bin:/bin`），工作目录是 `/`，argv 只有 `aw-mac-gate`。程序、工作目录、环境变量都当数据写进一根管道，不放进闸门自己的环境、参数或工作目录。闸门堵住读这根管道：读到放行的一个字节才继续，读到 EOF（创建者已死，或还没放行就中止）则不 exec 直接退出。放行之后闸门先切身份（见下），再进入调用方的工作目录，再用调用方的环境 `execve` 目标。放行之后程序不再读这根管道，所以后台重启程序继续跑。不另起看门狗，也不按 pid 发 `SIGKILL`。【待验证】这根管道和身份切换都还没在真机 macOS 上跑过。`aw run` 这条路径上，`aw` 自己是创建者：它先挂住，等后台确认纳入范围后再放行；放行前任何失败都关掉管道（闸门读到 EOF 退出）并 `waitpid`。`--cwd` 两条路径都支持：闸门切完身份（或确认不用切）之后才 `chdir`。后台新建会话时，root 后台不直接以 root 运行程序：闸门在还是 root 时不碰调用方的任何东西，先 `initgroups` → `setgid` → `setuid`，确认真实/有效 uid 都已是调用方且 `setuid(0)` 失败，才 `chdir` 再 exec；调用方就是后台自己的账户时跳过切换，其余相同。每一步失败有自己的退出码，记在日志里，不显示给用户：读不到规格 121，`initgroups` 122，`setgid` 123，`setuid` 124，切换自检失败（uid 没切过去，或 `setuid(0)` 仍成功）125，`chdir` 126，`exec` 127。调用方身份只来自连接上的 `getpeereid`（uid、gid）和 `LOCAL_PEERPID`（pid），经 `IdentifiedCaller::from_peer` 传入；认不出就拒绝，不退回后台自己的身份。
2. daemon 在 ES 的 `fork` 事件上：父进程在范围内，就把子进程加入。使用原生 ES 时，同时把它加入 inverse mute 的范围。
3. 辅助判断：`responsible_audit_token` 可以识别那些由 launchd 代为启动、但“责任进程”仍是目标的进程，比如 XPC 服务。这类归属标为 I。
4. 经 `launchctl` 或 `open` 命令拉起的程序，父进程是 launchd，按 CAP-SCOPE-03 记为“链路中断”。
5. M1 阶段有一处竞态：eslogger 是异步输出的，子进程的前几条事件可能先于 fork 事件到达。处理办法：未知 PID 的事件先暂存 200 ms；另外用 `ppid` 字段做兼容判断。

## 5. 权限与安装

| 项 | M1 | M2 |
|---|---|---|
| daemon | `/Library/LaunchDaemons/dev.agentwatch.daemon.plist`，以 root 运行 | 同左，但可执行文件位于 `.app` 内 |
| TCC | 用户要手动在“完全磁盘访问”里添加 daemon 可执行文件；`aw doctor` 负责检测并给出引导 | 同左（ES client 仍需完全磁盘访问） |
| 系统扩展 | 无 | 需要用户批准 |
| 分发 | Homebrew tap（formula/cask）+ tar.gz | 签名并公证的 pkg |

## 6. 已知坑

| 问题 | 对策 |
|---|---|
| eslogger 全系统事件量大 | 在 JSON 解析前按 PID 过滤；必要时不订阅 open；尽早进入 M2 |
| eslogger 输出格式随系统版本变化 | 宽松解析；每个主版本录制 fixture；在 CI 里用 fixture 做回归测试 |
| ES 客户端处理太慢会被系统断开（AUTH 事件） | 只用 NOTIFY；回调里只拷贝必要字段，然后放进通道 |
| 签名与授权配置错误的错误码不直观（如 `ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED`） | `aw doctor` 把常见错误码翻译成可操作的提示 |
| Apple Silicon 与 Intel | 发布 universal2 二进制 |
| 容器与虚拟机（Docker Desktop、OrbStack） | 容器里的进程在 VM 内，宿主机上只能看到 VM 进程；标“链路中断” |
| Unix 套接字路径超过 104 字节时报 `os error 22` | 见下。daemon 绑定和客户端连接前都先检查长度，超限给出中文说明（写明上限和实际长度），不再只剩一句 `invalid argument` |


### 套接字路径过长（`os error 22`）

macOS 的 `sockaddr_un` 是 `sun_len: u8`、`sun_family`、`sun_path: [c_char; 104]`。路径按字节算，**104 字节及以上就不能用**（还要留一个结尾的空字节）。默认路径都不超：`/var/run/agentwatch/api.sock` 是 28 字节，`$HOME/Library/Application Support/AgentWatch/api.sock` 在常见用户名下也在 80 字节以内。会超的是 `AW_SOCKET` 指到一个很长的临时目录下面。

报错的来源要分清：

- Rust 标准库在发起系统调用**之前**就自己检查长度，超限返回 `ErrorKind::InvalidInput`，错误文本是 `path must be shorter than SUN_LEN`。它的 `Display` 在某些路径上只显示 `invalid argument`。
- 真正的 `EINVAL`（errno 22）只有路径穿过了这层检查、由内核拒绝时才会出现。两者看起来都像 `os error 22`，但多数时候根本没有系统调用。

所以 daemon 的 `bind` 和客户端的 `connect` 都在调用前先量长度，超限直接给出「套接字路径太长：N 字节，这个系统的上限是 104 字节」。Linux 的上限是 108，同一段检查按系统取数。

**还需要真机确认的：** 104 这个上限来自 `libc` 里 `sun_path` 的数组长度，没有在 macOS 上实际绑过一个 103 字节和一个 104 字节的路径来对照。标准库的提前拒绝也意味着过长路径到不了内核，真机上能验证的是「103 字节能绑定、104 字节被我们的检查拒绝」。

## 7. 测试方法

> **未在真机验证。** 下面这些都只在 Linux 上交叉编译过（`aarch64-apple-darwin` 的 `aw-platform` 通过 clippy；`aw-cli` 与 `aw-daemon` 的 macOS 目标编不过，因为 `ring`、`aws-lc-sys`、`libsqlite3-sys` 的构建脚本需要 macOS SDK），没有在一台 Mac 上运行过：
>
> - 闸门管道：创建者被杀（写端关闭、闸门读到 EOF）后，程序是否还没 exec 就退出；放行（写入一个字节）之后程序是否跑起来，并且不再因为后台重启被杀掉。
> - 闸门进程的 `initgroups` / `setgid` / `setuid` 是否把附加组也带上，以及 `setuid(0)` 的自检。切换发生在 `chdir` 和使用调用方环境之前；闸门自己的环境只有 `PATH=/usr/bin:/bin`。
> - 长程序能被采样：后台启动 `sleep 20`，会话的进程列表里出现这个 pid。CI 上这条不需要 root。
> - `proc_pidinfo(PROC_PIDTBSDINFO)` 读出的 uid/gid 与启动时间，和 `KERN_PROCARGS2` 的 argv 布局。
> - `getpeereid` 与 `LOCAL_PEERPID` 是否对本地套接字给出对端 uid 和 pid。
> - `kern.osproductversion` 的返回格式。
> - 套接字路径 103 字节能绑定、104 字节被拒绝（见 §6）。

- 单元测试：eslogger JSON、nettop CSV、pcapng 的 fixture 回放，可以在任意平台的 CI 上跑。
- 端到端：GitHub 托管的 macOS runner 上无法通过交互方式授予完全磁盘访问【待验证：能否用 tccutil 或预置的 TCC 数据库绕过】。规划如下：
  - 手动触发的 workflow，跑在自托管 runner（一台专用 Mac）上；
  - 或者每个里程碑在本地人工跑一次 `sim/` 剧本，并把结果提交到 `docs/06-research/`。
- 对照验证：用 Objective-See 的 ProcessMonitor/FileMonitor 以及 `fs_usage` 人工核对。

## 8. 可参考的开源项目

| 项目 | 许可证 | 参考什么 |
|---|---|---|
| endpoint-sec（Rust crate） | MIT / Apache-2.0【待验证】 | 直接依赖 |
| Santa | Apache-2.0 | ES client 架构、系统扩展打包 |
| Objective-See ProcessMonitor / FileMonitor | GPL-3.0【待验证】 | 只参考思路，不复制代码 |
| LuLu | GPL-3.0 | NE 过滤器的生命周期。**只看不抄** |
| Apple 示例 SimpleFirewall（Filtering Network Traffic） | Apple Sample Code License | NE 内容过滤器与 XPC 通信，可以直接改写 |
| bandwhich | MIT | macOS 上 socket 与进程的映射 |
