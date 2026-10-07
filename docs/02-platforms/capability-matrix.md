# 平台能力矩阵

> 状态：草案
> 最后更新：2026-10-07
> 关联：REQ-01~07、ADR-0008、ADR-0009、ADR-0010、SPIKE-01~09

本文件是**平台能力的唯一事实来源**。平台文档、UI 的“能力说明”和 `aw doctor` 的输出都以这里为准。

- 证据等级的定义见 [evidence-model](../01-architecture/evidence-model.md)。
- 本表中所有内容在完成对应 SPIKE 之前都视为【待验证】。验证通过后，把“验证”列改成 `✅ SPIKE-NN`；验证不通过，改成 `❌ SPIKE-NN` 并同时修改“机制”列。

## 0. 读表说明

| 列 | 含义 |
|---|---|
| 机制 | 首选采集手段；`→` 后是降级手段 |
| 等级 | 首选手段的证据等级；`/` 后是降级手段的等级 |
| 最低版本 | 首选手段要求的最低 OS 或内核版本 |
| 权限 | 运行时需要的权限 |
| 验证 | `⏳ SPIKE-NN` 待验证 · `✅` 已验证 · `❌` 不可行 |

平台缩写：**L** = Linux，**W** = Windows，**M1** = macOS 第一步（eslogger/nettop/pktap），**M2** = macOS 第二步（原生 ES + NE 系统扩展）。详见 [ADR-0009](../03-adr/0009-macos-two-step.md)。

---

## 1. 进程（CAP-PROC）

| 编号 | 能力 | 平台 | 机制 | 等级 | 最低版本 | 权限 | 验证 |
|---|---|---|---|---|---|---|---|
| CAP-PROC-01 | 进程启动，含可执行路径与 argv | L | tracepoint `sched:sched_process_exec` + 读取 `mm->arg_start` → proc connector + `/proc/<pid>/cmdline` | E1 / S | 5.8 | root 或 CAP_BPF+CAP_PERFMON | ⏳ SPIKE-01 |
| | | W | ETW 内核进程事件（Kernel-Process 或系统日志会话 Process/Start） | E1 | Win10 1909 | 管理员 | ⏳ SPIKE-02 |
| | | M1 | `eslogger exec` | E1 | 13.0 | root + 完全磁盘访问 | ⏳ SPIKE-03 |
| | | M2 | ES `ES_EVENT_TYPE_NOTIFY_EXEC` | E1 | 11.0 | ES 授权 + 完全磁盘访问 | ⏳ SPIKE-08 |
| CAP-PROC-02 | 进程退出与退出码 | L | `sched:sched_process_exit`（从 `task->exit_code` 取） | E1 | 5.8 | 同上 | ⏳ SPIKE-01 |
| | | W | ETW Process/Stop（含 ExitCode【待验证】） | E1 | Win10 | 管理员 | ⏳ SPIKE-02 |
| | | M1/M2 | ES `EXIT`（含 stat） | E1 | 13.0 / 11.0 | 同上 | ⏳ SPIKE-03 |
| CAP-PROC-03 | 父子关系与 fork 链 | L | `sched:sched_process_fork` | E1 | 5.8 | 同上 | ⏳ SPIKE-01 |
| | | W | 进程启动事件中的 ParentProcessId | E1 | Win10 | 管理员 | ⏳ SPIKE-02 |
| | | M1/M2 | ES `FORK` + `exec` 中的 ppid、responsible pid 字段【待验证】 | E1 | 13.0 / 11.0 | 同上 | ⏳ SPIKE-03 |
| CAP-PROC-04 | 当前工作目录 | L | 在 exec 时读取 `/proc/<pid>/cwd`（存在竞态） | S | 任意 | root | ⏳ SPIKE-01 |
| | | W | 读取 PEB 中的 `CurrentDirectory`（存在竞态）【待验证】 | S | Win10 | 管理员 | ⏳ SPIKE-02 |
| | | M1/M2 | ES `exec` 事件的 `cwd` 字段 | E1 | 13.0 / 11.0 | 同上 | ⏳ SPIKE-03 |
| CAP-PROC-05 | 附着时的进程快照（已存在的进程） | 全部 | `sysinfo` 或各平台原生枚举接口 | S | — | 普通用户即可看到同用户进程；看其他用户需要特权 | ⏳ SPIKE-05 |
| CAP-PROC-06 | 可执行文件哈希（可选） | 全部 | 在 exec 时异步计算 SHA-256，每个路径+mtime 只算一次 | E1（针对文件本身） | — | 对该文件有读权限 | — |

## 2. 文件（CAP-FILE）

| 编号 | 能力 | 平台 | 机制 | 等级 | 最低版本 | 权限 | 验证 |
|---|---|---|---|---|---|---|---|
| CAP-FILE-01 | 打开文件，含读/写意图 | L | BPF LSM `file_open`；或 fentry `do_filp_open` / tracepoint `syscalls:sys_exit_openat` → fanotify `FAN_OPEN` | E1 / E1 | 5.8（LSM 方案还需要 `lsm=bpf`） | root | ⏳ SPIKE-01 |
| | | W | ETW Kernel-File Create（含 CreateOptions、ShareAccess） | E1 | Win10 | 管理员 | ⏳ SPIKE-02 |
| | | M1/M2 | ES `OPEN`（`fflag`） | E1 | 13.0 / 11.0 | 同上 | ⏳ SPIKE-03 |
| CAP-FILE-02 | 读取次数与字节数 | L | `sys_exit_read`/`pread64`/`readv` 的返回值，按 fd 累加 | E1 | 5.8 | root | ⏳ SPIKE-01 |
| | | W | ETW Kernel-File Read（IOSize） | E1 | Win10 | 管理员 | ⏳ SPIKE-02 |
| | | M1/M2 | **不可得**：ES 没有 read 事件。可选用 `fs_usage` 做 S 级补充【待验证】 | NA / S | — | — | ⏳ SPIKE-03 |
| CAP-FILE-03 | 写入与修改 | L | `sys_exit_write`/`pwrite64`/`writev` 的返回值 | E1 | 5.8 | root | ⏳ SPIKE-01 |
| | | W | ETW Kernel-File Write（IOSize） | E1 | Win10 | 管理员 | ⏳ SPIKE-02 |
| | | M1/M2 | ES `WRITE`（M2 可订阅）、`CLOSE.modified`、`TRUNCATE`；拿不到字节数 | E1（字节数为 NA） | 13.0 / 11.0 | 同上 | ⏳ SPIKE-03 |
| CAP-FILE-04 | 创建文件 | L | `openat` 带 `O_CREAT` 且返回新 inode；或 LSM `inode_create` | E1 | 5.8 | root | ⏳ SPIKE-01 |
| | | W | Kernel-File Create 的 CreateDisposition | E1 | Win10 | 管理员 | ⏳ SPIKE-02 |
| | | M1/M2 | ES `CREATE` | E1 | 13.0 / 11.0 | 同上 | ⏳ SPIKE-03 |
| CAP-FILE-05 | 删除 | L | tracepoint `syscalls:sys_enter_unlinkat` / LSM `path_unlink` → fanotify `FAN_DELETE` | E1 | 5.8 / 5.1 | root | ⏳ SPIKE-01 |
| | | W | Kernel-File Delete / SetDelete（【待验证】事件 ID 26 或 35） | E1 | Win10 | 管理员 | ⏳ SPIKE-02 |
| | | M1/M2 | ES `UNLINK` | E1 | 13.0 / 11.0 | 同上 | ⏳ SPIKE-03 |
| CAP-FILE-06 | 重命名与移动 | L | `sys_enter_renameat2` / LSM `path_rename` → fanotify `FAN_RENAME` | E1 | 5.8 / 5.17 | root | ⏳ SPIKE-01 |
| | | W | Kernel-File Rename / RenamePath【待验证】 | E1 | Win10 | 管理员 | ⏳ SPIKE-02 |
| | | M1/M2 | ES `RENAME` | E1 | 13.0 / 11.0 | 同上 | ⏳ SPIKE-03 |
| CAP-FILE-07 | 关闭，并给出是否被修改 | L | `sys_enter_close` + 内核侧 fd 表 | E1 | 5.8 | root | ⏳ SPIKE-01 |
| | | W | Kernel-File Close / Cleanup | E1 | Win10 | 管理员 | ⏳ SPIKE-02 |
| | | M1/M2 | ES `CLOSE`（`modified`） | E1 | 13.0 / 11.0 | 同上 | ⏳ SPIKE-03 |
| CAP-FILE-08 | 内存映射读写 | 全部 | 只能看到 `mmap`（L：`sys_enter_mmap`；M：ES `MMAP`；W：映像加载等事件），**拿不到实际访问的字节数** | E1（仅映射动作）/ NA（字节数） | — | — | — |

## 3. 网络（CAP-NET）

| 编号 | 能力 | 平台 | 机制 | 等级 | 最低版本 | 权限 | 验证 |
|---|---|---|---|---|---|---|---|
| CAP-NET-01 | TCP 连接建立与接受，含五元组和 PID | L | kprobe/fentry `tcp_connect`、`inet_csk_accept`；tracepoint `sock:inet_sock_set_state` | E1 | 5.8 | root | ⏳ SPIKE-01 |
| | | W | ETW Kernel-Network TCP connect/accept | E1 | Win10 | 管理员 | ⏳ SPIKE-02 |
| | | M1 | `nettop` 快照 + libproc `proc_pidfdinfo` | S | 13.0 | root | ⏳ SPIKE-03 |
| | | M2 | NE `NEFilterDataProvider.handleNewFlow`（带 audit token） | E1 | 11.0 | NE 授权 + 用户批准 | ⏳ SPIKE-08 |
| CAP-NET-02 | 每条 TCP 连接的收发字节数 | L | kprobe `tcp_sendmsg` 返回值、`tcp_cleanup_rbuf(copied)` → sock_diag 轮询 `tcp_info.bytes_acked/bytes_received` | E1 / S | 5.8 / 4.2【待验证】 | root | ⏳ SPIKE-01 |
| | | W | ETW Kernel-Network TCP send/recv（size 字段） | E1 | Win10 | 管理员 | ⏳ SPIKE-02 |
| | | M1 | `nettop -L` 按连接累计的 bytes_in/out（采样） | S | 13.0 | root | ⏳ SPIKE-03 |
| | | M2 | NE 数据流回调中累计字节数【待验证：会拷贝数据，有性能开销】 | E1 | 11.0 | 同上 | ⏳ SPIKE-08 |
| CAP-NET-03 | UDP 收发字节数（含 QUIC） | L | kprobe `udp_sendmsg`/`udpv6_sendmsg`、`udp_recvmsg` | E1 | 5.8 | root | ⏳ SPIKE-01 |
| | | W | ETW Kernel-Network UDP send/recv | E1 | Win10 | 管理员 | ⏳ SPIKE-02 |
| | | M1 | `nettop`（是否包含 UDP【待验证】） | S | 13.0 | root | ⏳ SPIKE-03 |
| | | M2 | NE UDP 流 | E1 | 11.0 | 同上 | ⏳ SPIKE-08 |
| CAP-NET-04 | 连接关闭与生命周期 | L | `inet_sock_set_state` 变为 TCP_CLOSE | E1 | 5.8 | root | ⏳ SPIKE-01 |
| | | W | Kernel-Network disconnect | E1 | Win10 | 管理员 | ⏳ SPIKE-02 |
| | | M1 / M2 | 快照里消失（S）/ NE 流关闭（E1） | S / E1 | — | — | ⏳ SPIKE-03 |
| CAP-NET-05 | 进程级字节总量（不区分连接） | 全部 | 由 CAP-NET-02/03 汇总而来；兜底方案见 [fallback-poll](fallback-poll.md) | 随来源 | — | — | — |
| CAP-NET-06 | 本机回环与 Unix socket / 命名管道 | 全部 | 回环 TCP 和其他 TCP 走同一机制；Unix socket 和命名管道**只记录连接动作，不计字节**；两端配对与字节数由 [CAP-IPC](#10-agent-间通信cap-ipc) 补充（P6） | E1（连接动作） | — | — | — |

## 4. 域名解析（CAP-DNS）

| 编号 | 能力 | 平台 | 机制 | 等级 | 最低版本 | 权限 | 验证 |
|---|---|---|---|---|---|---|---|
| CAP-DNS-01 | 进程发出的 DNS 查询与应答 | L | 用 eBPF 在 `udp_sendmsg`/`udp_recvmsg` 上解析 53 端口载荷，或 `AF_PACKET` 抓包解析 | E1 | 5.8 | root | ⏳ SPIKE-01 |
| | | W | ETW Microsoft-Windows-DNS-Client（带发起方 PID） | E1 | Win10 | 管理员 | ⏳ SPIKE-02 |
| | | M1 | pktap 抓包（`tcpdump -i pktap -k` 带进程信息） | E1（是否能拿到 PID【待验证】） | 13.0 | root | ⏳ SPIKE-03 |
| | | M2 | NE DNS 代理，或继续用 pktap | E1 | 11.0 | 同上 | ⏳ SPIKE-08 |
| CAP-DNS-02 | 系统解析器代理查询时的归属 | L | 进程查询的是 systemd-resolved（127.0.0.53）：查询内容能归属到进程，上游查询属于 resolved | E1 | — | — | ⏳ SPIKE-01 |
| | | W | Dnscache 服务代为查询：DNS-Client ETW 中带原始请求方 PID【待验证】 | E1 | Win10 | — | ⏳ SPIKE-02 |
| | | M | mDNSResponder 代为查询：pktap 只能看到 mDNSResponder，**发起进程不可得**，只能用 IP 回填 | NA → I | — | — | ⏳ SPIKE-03 |
| CAP-DNS-03 | TLS SNI | 全部 | 解析 ClientHello（L：eBPF 或抓包；W：pktmon 或 WinDivert；M：pktap）。ECH 会隐藏 SNI | E1 | — | root / 管理员 | ⏳ SPIKE-01/02/03 |
| CAP-DNS-04 | IP 到域名的回填 | 全部 | 在会话内维护 DNS 应答缓存（带 TTL 和时间窗），按目标 IP 反查；同一 IP 对应多个域名时全部列出 | I（标注“基于 DNS 缓存推断”） | — | — | — |

## 5. URL 与内容（CAP-URL）

| 编号 | 能力 | 平台 | 机制 | 等级 | 最低版本 | 权限 | 验证 |
|---|---|---|---|---|---|---|---|
| CAP-URL-01 | 完整 URL、方法、状态码、body 字节数 | 全部 | 启动模式下的显式 MITM 代理（`aw-proxy`，基于 hudsucker），见 [ADR-0006](../03-adr/0006-explicit-mitm-proxy-for-url.md) | E2 | — | 普通用户即可 | ⏳ SPIKE-04 |
| CAP-URL-02 | TLS 明文 uprobe | L | uprobe 挂在 `SSL_write`/`SSL_read`（OpenSSL、BoringSSL）、Go `crypto/tls`；参考 ecapture。可选功能 | E2 | 5.8 | root | ⏳（P3，可选） |
| | | W/M | 不支持 | NA | — | — | — |
| CAP-URL-03 | WinINet / WinHTTP 的 URL | W | ETW Microsoft-Windows-WinINet、WinHttp provider。**只覆盖用这两套网络栈的程序**，Node/Python/Go/Chromium 都不走 | E1 | Win10 | 管理员 | ⏳ SPIKE-02 |
| CAP-URL-04 | 请求体与本地文件的内容匹配 | 全部 | 只在代理模式下：请求体按分块算哈希，与敏感文件的分块哈希比对，只在内存中进行 | E2（内容匹配证据） | — | — | ⏳（P3） |

## 6. 范围追踪（CAP-SCOPE）

| 编号 | 能力 | 平台 | 机制 | 等级 | 最低版本 | 权限 | 验证 |
|---|---|---|---|---|---|---|---|
| CAP-SCOPE-01 | 启动模式下覆盖全部后代进程 | L | 先建 cgroup v2 子组，再 exec；eBPF 按 `bpf_get_current_cgroup_id()` 过滤 | E1 | 5.8 + cgroup v2 | root（或委托 cgroup） | ⏳ SPIKE-05 |
| | | W | 用 `CREATE_SUSPENDED` 创建进程 → `AssignProcessToJobObject` → 恢复运行；Job 的完成端口会收到 `JOB_OBJECT_MSG_NEW_PROCESS` | E1 | Win8（支持嵌套 Job） | 普通用户即可 | ⏳ SPIKE-05 |
| | | M | 以启动的根 PID 为起点，在 ES 的 fork/exec 流上维护后代集合 | E1 | 13.0 / 11.0 | 同上 | ⏳ SPIKE-05 |
| CAP-SCOPE-02 | 附着模式 | 全部 | 先用 CAP-PROC-05 做快照，再从 fork/exec 事件增量维护后代集合 | S（附着前已发生的事）+ E1（附着后） | — | 特权 | ⏳ SPIKE-05 |
| CAP-SCOPE-03 | 识别归属链路中断 | 全部 | 规则：目标进程连接本机守护进程的 socket 或管道，或调用 `systemd-run`、`launchctl`、`schtasks`、`sc`、`docker` 等命令 → 生成 Gap，类型为“链路中断” | I | — | — | ⏳ SPIKE-05 |
| CAP-SCOPE-04 | 逃逸检测 | L | cgroup 迁移事件（tracepoint `cgroup:cgroup_attach_task`） | E1 | 5.8 | root | ⏳ SPIKE-05 |
| | | W | 用 `JOB_OBJECT_LIMIT_BREAKAWAY_OK` 逃出 Job：默认不设置该标志；被拒绝时记录 | E1 | — | — | ⏳ SPIKE-05 |
| | | M | 不适用（基于进程树跟踪） | — | — | — | — |

## 7. 权限、安装与采集健康（CAP-PRIV）

| 编号 | 能力 | 平台 | 要点 | 验证 |
|---|---|---|---|---|
| CAP-PRIV-01 | 运行所需权限 | L | root，或 `CAP_BPF`+`CAP_PERFMON`+`CAP_SYS_RESOURCE`（5.8+）；fanotify 需要 `CAP_SYS_ADMIN` | ⏳ SPIKE-01 |
| | | W | 管理员令牌；以 Windows 服务（LocalSystem）运行 | ⏳ SPIKE-02 |
| | | M1 | root；终端或 daemon 要有完全磁盘访问 | ⏳ SPIKE-03 |
| | | M2 | `com.apple.developer.endpoint-security.client` 授权、NE 授权、系统扩展经用户批准、公证 | ⏳ SPIKE-08 |
| CAP-PRIV-02 | 安装产物与卸载清理 | 全部 | 服务（systemd unit / Windows Service / LaunchDaemon）、系统扩展（M2）、代理 CA（不装入系统证书库）；卸载时全部清除，对应 NFR-09 | — |
| CAP-PRIV-03 | 事件丢失检测 | L | ringbuf 写满时 `bpf_ringbuf_reserve` 失败，在内核侧计数，用户态定期读取 | ⏳ SPIKE-01 |
| | | W | ETW 会话统计 `EventsLost`、`BuffersLost` | ⏳ SPIKE-02 |
| | | M | ES 消息的 `seq_num` 和 `global_seq_num` 不连续，即为丢失（eslogger JSON 中也有这两个字段【待验证】） | ⏳ SPIKE-03 |
| CAP-PRIV-04 | 内核态过滤能力 | L | 有：按 cgroup id 或 PID 集合在内核侧丢弃无关事件 | ⏳ SPIKE-01 |
| | | W | 无：Kernel-File 和 Kernel-Network 事件不能按 PID 在内核侧过滤，只能在用户态尽早丢弃 | ⏳ SPIKE-02 |
| | | M | 部分有：ES 的 mute 和反向 mute（macOS 13+ 的 `es_invert_muting`）；eslogger 不支持 | ⏳ SPIKE-03 |

---

## 8. 通用限制（UI 中必须如实呈现）

| 限制 | 影响 | 处理与标注 |
|---|---|---|
| **TLS 加密** | 不开代理时只能看到 IP、端口、字节数、DNS 和 SNI | URL 字段写 `NA`，原因：“TLS 加密，未启用代理” |
| **QUIC / HTTP3** | 走 UDP，绕过显式 HTTP 代理；SNI 在加密的 Initial 包里，解析成本高 | 字节数仍然统计（CAP-NET-03）；标为“QUIC 直连，URL 不可得”。启动模式可以尝试用环境变量或参数禁用 QUIC【待验证】 |
| **证书固定 / 不认环境变量** | 代理握手失败，或程序直接直连 | 握手失败记为 Gap；没经过代理的连接标为“直连，未经代理”。各运行时的认可情况见 SPIKE-04 |
| **ECH** | 看不到 SNI | SNI 写 `NA` 并附原因 |
| **mmap** | 读写不产生 read/write 事件 | 只记录映射动作，字节数写 `NA`（CAP-FILE-08） |
| **守护进程委托** | 工作交给 docker daemon、ssh-agent、git credential helper、同步盘、systemd、launchd 后，归属链路断开 | 生成 CAP-SCOPE-03 Gap：“链路中断”。不把守护进程的行为算到会话头上 |
| **DNS 代理解析器** | macOS 的 mDNSResponder、Linux 的 resolved 上游查询不带发起进程 | 用 IP 回填（I），并注明来源 |
| **附着前的历史** | 附着之前已打开的文件和连接，看不到打开动作 | 快照数据标 `S`；时间线在附着时刻显示一条分隔线 |
| **短命进程与短连接（轮询模式）** | 两次轮询之间的进程或连接会漏掉 | 只在 S 级兜底时出现；在会话上标“采样模式，可能遗漏” |
| **对抗** | 同等权限的程序可以卸载探针、杀掉 daemon、伪造自报告（E3） | 不在范围内（见 requirements 非目标）。daemon 被杀或重启时写 Gap；E3 永远不能单独支撑结论 |
| **容器与命名空间（Linux）** | 容器里的 PID 和路径与宿主机不同 | 记录宿主机 PID 和 mount namespace id；路径按宿主机视图解析【待验证】 |

## 9. 维护流程

1. 每完成一个 SPIKE，就更新本表“验证”列和受影响的“机制”“等级”列，并在 SPIKE 文档的“对文档的影响”一节注明改了哪些行。
2. 新增 CAP 时编号顺延，不复用；废弃时把整行加删除线，并注明原因。
3. `aw-core` 中的 `Capability` 枚举与本表编号一一对应。`aw doctor` 按本表输出当前机器的能力报告。

## 10. Agent 间通信（CAP-IPC）

设计见 [inter-agent-communication](../01-architecture/inter-agent-communication.md)。本节全部待 SPIKE-09 验证。只对跨 AgentInstance 的通道按字节计数，过滤在内核侧完成。

| 编号 | 能力 | 平台 | 机制 | 等级 | 最低版本 | 权限 | 验证 |
|---|---|---|---|---|---|---|---|
| CAP-IPC-01 | 匿名管道两端配对与字节数 | L | fork 继承链 + pipe inode 配对；eBPF `pipe_write` / `pipe_read` 计字节 | E1 | 5.8 | root | ⏳ SPIKE-09 |
| | | W | 用进程创建时的句柄继承近似配对；字节数【待验证】 | I / NA | Win10 | 管理员 | ⏳ SPIKE-09 |
| | | M1 / M2 | 进程树（E1）；libproc `PROC_PIDFDPIPEINFO` 采样配对；字节数 NA | S / NA | 13.0 | root | ⏳ SPIKE-09 |
| CAP-IPC-02 | Unix socket / 命名管道两端配对与字节数 | L | eBPF `unix_stream_connect` 配对，`unix_stream_sendmsg` / `unix_dgram_sendmsg` 计字节 → `sock_diag`（UNIX_DIAG_PEER）采样配对，字节 NA | E1 / S | 5.8 / 3.3 | root | ⏳ SPIKE-09 |
| | | W | Kernel-File 中 `\Device\NamedPipe\` 的 Create / Read / Write；服务端 PID 用快照补充 | E1【待验证】 / I | Win10 | 管理员 | ⏳ SPIKE-09 |
| | | M1 / M2 | ES `uipc_connect` / `uipc_bind`，取得两端路径与进程；字节数 NA | E1（连接）/ NA（字节） | 13.0 / 11.0 | root / ES 授权 | ⏳ SPIKE-09 |
| CAP-IPC-03 | 回环 TCP/UDP 两端配对 | L / W | 复用现有 TCP/UDP 采集，按镜像五元组配对 | E1 | 同 CAP-NET-01 | 同 CAP-NET-01 | ⏳ SPIKE-09 |
| | | M1 / M2 | nettop + libproc 快照配对 | S | 13.0 | root | ⏳ SPIKE-09 |
| CAP-IPC-04 | 协议元数据（MCP / A2A 的 method、工具名） | 全部 | 启动模式下用 `--mcp-tap` stdio 包装器；HTTP 走 aw-proxy；未启用时为 NA(`protocol_not_observed`) | E2 | — | 用户权限 | ⏳ SPIKE-09 |
| | | L | 可选 `collectors.linux.ipc_payload_peek`（eBPF 读取缓冲区，默认关闭） | E2 | 5.8 | root | ⏳ SPIKE-09 |
| CAP-IPC-05 | 共享工件（A 写、B 读同一文件） | 全部 | 从 CAP-FILE 的记录出发，经关联规则 `agent_shared_artifact` 推得 | I | — | — | — |
| CAP-IPC-06 | 同一进程内的多个 Agent 角色 | 全部 | 框架的 OTEL span / hooks 自报告；OS 层不可见 | E3 | — | — | — |
