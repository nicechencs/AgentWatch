# Linux 采集器

> 状态：草案
> 最后更新：2026-10-07
> 关联：REQ-01~04、REQ-11、ADR-0010、ADR-0007、ADR-0013、SPIKE-01、SPIKE-05、SPIKE-09、[capability-matrix](capability-matrix.md)、[inter-agent-communication](../01-architecture/inter-agent-communication.md)

本文涵盖 crate：`aw-collector-linux`（用户态）和 `aw-ebpf`（内核态 eBPF 程序，用 Aya 编写）。

## 1. 总体方案

```
            内核态 (aw-ebpf)                         用户态 (aw-collector-linux)
 tracepoint / fentry / kprobe / LSM ──► 过滤(cgroup_id / pid 集合 map)
                                     ──► 内核侧聚合(按 fd/连接累加字节)
                                     ──► BPF ringbuf ─────────────► 解码 → RawEvent → aw-pipeline
                                     ──► 丢失计数 per-CPU map ───────► 定期读取 → Gap
```

三档运行方式，启动时自动探测并选择（也可以用 `--collector` 强制指定）：

| 档位 | 条件 | 组成 | 等级 |
|---|---|---|---|
| **ebpf-full** | 内核 ≥5.8、有 BTF（`/sys/kernel/btf/vmlinux`）、有 root 或对应 CAP | 全部用 eBPF | E1 |
| **ebpf-lite** | 有 BTF，但没有 fentry/LSM（例如 arm64 旧内核、没开 `lsm=bpf`） | tracepoint + kprobe | E1 |
| **legacy** | 无 BTF 或内核 <5.8 | proc connector（进程）+ fanotify（文件）+ sock_diag 轮询（网络）+ `AF_PACKET`（DNS） | 进程和文件为 E1；网络字节为 S；文件读写字节为 NA |
| poll | 没有特权 | 见 [fallback-poll](fallback-poll.md) | S |

> 【待验证 SPIKE-01】主流发行版默认内核是否都能进入 ebpf-full：Ubuntu 22.04/24.04、Debian 12、Fedora 40+、RHEL 9、Arch。已知 BPF LSM 在不少发行版上默认没开，所以 `file_open` 以 fentry/tracepoint 为主、LSM 为可选。

## 2. 采集点详解

### 2.1 进程

| 探针 | 类型 | 取得字段 | 输出 EventKind |
|---|---|---|---|
| `sched:sched_process_fork` | tracepoint | parent_pid, child_pid；`task->start_time` | （更新范围集合）按需发出 ProcessStart，`exec=false` |
| `sched:sched_process_exec` | tracepoint | filename, pid, old_pid；从 `mm->arg_start..arg_end` 拷贝 argv（上限 4 KB，超出部分截断并标记 `truncated`）；uid/gid；cgroup_id | ProcessStart（`exec=true`） |
| `sched:sched_process_exit` | tracepoint | pid, `exit_code`（只在线程组 leader 退出时发出） | ProcessExit |
| `cgroup:cgroup_attach_task` | tracepoint | pid, dst cgroup | （逃逸检测，CAP-SCOPE-04）→ Gap |

- cwd：在用户态处理 exec 事件时读 `/proc/<pid>/cwd`。进程可能已经退出，所以该字段标 S。进阶做法：在内核侧用 `bpf_d_path` 或遍历 `fs->pwd` dentry【待验证】。
- 进程身份：`proc_uid = hash(boot_id, pid, task->start_time)`，见 [ADR-0007](../03-adr/0007-process-identity.md)。`start_time` 用单调时钟纳秒，与 `/proc/<pid>/stat` 第 22 列（单位是 clock ticks）换算后可以对应。
- 线程：只跟踪线程组（tgid），不单独记录线程的创建。

### 2.2 文件

| 探针 | 类型 | 说明 | EventKind |
|---|---|---|---|
| `lsm/file_open` | BPF LSM（可选） | 拿到 `struct file*`，用 `bpf_d_path` 取得规范化的绝对路径；`f_mode` 给出读/写意图 | FileOpen |
| `fexit/do_filp_open` | fentry/fexit（首选的备选） | 返回的 `struct file*` 可以换算成路径（【待验证】`bpf_d_path` 在 fexit 上是否允许用于该函数） | FileOpen |
| `syscalls:sys_enter/exit_openat`、`openat2` | tracepoint（兜底） | 路径是用户传入的原始字符串，可能是相对路径；用户态结合 cwd 规范化，结果标 `path_resolved=false`（尽力规范化） | FileOpen |
| `syscalls:sys_exit_read/pread64/readv/preadv` | tracepoint | 按 `(tgid, fd)` 在内核 map 中累加字节数和次数，**不逐条上报** | FileRead（在 close 或刷新时上报聚合值） |
| `syscalls:sys_exit_write/pwrite64/writev/pwritev` | tracepoint | 同上 | FileWrite |
| `sendfile`、`copy_file_range`、`splice` | tracepoint | 记录源和目标 fd 以及字节数。源是文件、目标是 socket 的情况**要特别标注**：这是较强的线索，但仍然是 I，见 evidence-model | FileRead + NetSend（带 `via=sendfile`） |
| `syscalls:sys_enter_close` | tracepoint | 将该 fd 的聚合计数冲刷出去，并清除 map 条目 | FileClose |
| `unlinkat`、`renameat2`、`mkdirat`、`truncate` | tracepoint（或 LSM `path_unlink`/`path_rename`） | 路径的规范化方式同上 | FileDelete / FileRename / FileCreate |

**fd 类型区分**：read/write 也会发生在 socket 和管道上。在 open/socket/accept 时把 fd 类型记入 `fd_kind` map，只有普通文件产生 FileRead/FileWrite。附着前就已打开的 fd，在用户态用 `/proc/<pid>/fd` 补充类型（S）。

**噪声路径**：`/proc`、`/sys`、`/dev`、动态库加载、locale 文件等，在管道里按规则折叠，而不是在内核里丢掉，以便保留计数。

### 2.3 网络

| 探针 | 类型 | 说明 | EventKind |
|---|---|---|---|
| `fexit/tcp_connect` 或 `kprobe/tcp_connect` | fentry/kprobe | 取 `struct sock` 中的五元组和当前进程；以 sock 指针为键记录归属 | NetConnect |
| `fexit/inet_csk_accept` | fentry | 入站连接 | NetConnect（`direction=inbound`） |
| `sock:inet_sock_set_state` | tracepoint | 状态变为 ESTABLISHED 时补全本地端口；变为 CLOSE 时输出连接的汇总 | NetClose |
| `fexit/tcp_sendmsg` | fentry | 返回值就是实际入队的字节数；按 sock 累加 | NetSend（按时间桶聚合后上报） |
| `kprobe/tcp_cleanup_rbuf` | kprobe | 参数 `copied` 就是应用实际读到的字节数 | NetRecv |
| `kprobe/udp_sendmsg`、`udpv6_sendmsg`、`fexit/udp_recvmsg` | kprobe/fentry | UDP 字节数；目标端口是 53 时把载荷前 512 B 拷贝到 ringbuf 供 DNS 解析 | NetSend / NetRecv / DnsQuery / DnsAnswer |

- 字节口径：应用层入队和出队的字节，包含 TLS 开销，不含 TCP/IP 头和重传。
- 聚合：内核侧用 `sock_stats` hash map（键为 sock 指针）累加，用户态每 1 s 扫一遍。或者用每笔写入一个小事件 + 用户态按 5 s 分桶。两种方案的取舍由 SPIKE-01 给出。
- SNI：在 `tcp_sendmsg` 上对每条连接的**第一笔**写入拷贝前 1 KB（用 `bpf_probe_read_user` 从 iov 读），在用户态解析 ClientHello。【待验证】iov 遍历在 verifier 下是否可行；不行则改用 `AF_PACKET` 抓 443 端口的首包。
- IPv6 以及 IPv4-mapped 地址要统一归一化。

### 2.4 可选：TLS 明文 uprobe（P3，CAP-URL-02）

- 在 `libssl.so` 的 `SSL_write`/`SSL_read` 以及 Go 程序的 `crypto/tls.(*Conn).Write/Read` 上挂 uprobe。只解析 HTTP/1.1 请求行和 HTTP/2 HEADERS 帧（要维护 HPACK 状态，复杂度高）。**不保存 body**。
- Node.js 把 OpenSSL 静态链接进二进制，需要按符号定位。Rust rustls 没有稳定符号，不支持。
- 优先级低于代理模式，只作补充。

## 3. 到 RawEvent 的映射汇总

| EventKind | 主来源 | legacy 来源 | 备注 |
|---|---|---|---|
| ProcessStart / ProcessExit | sched tracepoint | proc connector（`PROC_EVENT_FORK/EXEC/EXIT`）+ `/proc` | proc connector 不带 argv，要读 `/proc/<pid>/cmdline`，存在竞态（S） |
| FileOpen / FileCreate | LSM / fexit / tracepoint | fanotify `FAN_OPEN`、`FAN_CREATE`（5.1+） | fanotify 按 mount 或文件系统标记，需要 `FAN_REPORT_FID` |
| FileRead / FileWrite | sys_exit_* 聚合 | fanotify `FAN_ACCESS`/`FAN_MODIFY`（只有次数，字节数为 NA） | |
| FileClose | sys_enter_close | `FAN_CLOSE_WRITE`/`FAN_CLOSE_NOWRITE` | |
| FileDelete / FileRename | tracepoint / LSM | `FAN_DELETE`（5.1+）/ `FAN_RENAME`（5.17+） | fanotify 事件中的 pid 可能是 0【待验证】 |
| NetConnect / NetClose | tcp_connect / inet_sock_set_state | sock_diag（`NETLINK_INET_DIAG`）轮询差分 | S |
| NetSend / NetRecv | tcp_sendmsg / tcp_cleanup_rbuf | sock_diag `tcp_info.tcpi_bytes_acked` / `tcpi_bytes_received` 差分 | S；socket 的 inode 通过 `/proc/<pid>/fd` 归属到进程 |
| DnsQuery / DnsAnswer | udp kprobe 载荷 | `AF_PACKET` 抓 53 端口 | legacy 模式下用本地端口反查进程（S） |
| TlsSni | tcp_sendmsg 首包 | `AF_PACKET` | |
| HttpRequest / HttpResponse | aw-proxy（通用）、uprobe（可选） | — | E2 |
| IpcOpen / IpcTransfer / IpcClose | eBPF `unix_stream_connect` / `unix_stream_sendmsg` / `pipe_write`（CAP-IPC，P6） | `sock_diag` UNIX_DIAG_PEER 采样配对，字节 NA | E1 / S；机制待 SPIKE-09 |
| AgentRpc | `mcp-tap` / `proxy/mcp` | — | E2 |
| Gap | ringbuf 丢失计数、探针挂载失败、cgroup 逃逸 | — | |

## 4. 范围追踪

### 4.1 启动模式（`aw run`）

1. daemon 创建 `/sys/fs/cgroup/agentwatch.slice/session-<sid>/`。
   - systemd 系统上优先用 `systemd-run --scope --unit=aw-<sid>`，或者通过 D-Bus 调用 `StartTransientUnit`，避免与 systemd 的 cgroup 管理冲突【待验证 SPIKE-05】。
2. CLI 通过 API 向 daemon 请求创建会话。daemon 在 fork 之后、exec 之前把子进程写入 `cgroup.procs`；也可以用 `clone3(CLONE_INTO_CGROUP)`（5.7+）。
   - 被启动的程序以**调用用户身份**运行，而不是 root：daemon 先降权（setuid/setgid/补充组），并继承 CLI 传来的环境变量、cwd 和终端。【待验证】终端处理有两种办法：由 CLI 自己 fork，再请 daemon 把它移入 cgroup（更简单）；或者通过 SCM_RIGHTS 把 pty 传给 daemon。首选前者。
3. 把 cgroup id 写入 eBPF map `scope_cgroups`。所有探针先调用 `bpf_get_current_cgroup_id()`，不在 map 中就直接返回。
4. 优点：守护化、双重 fork、`setsid` 都逃不出 cgroup。只有主动写 `cgroup.procs`（需要权限）或者通过 systemd/D-Bus 让别的进程代为启动，才会离开，这两种都会被检测并记为 Gap。

### 4.2 附着模式（`aw attach`）

- 从 `/proc` 取得目标 PID 及其全部后代的快照，写入 eBPF map `scope_pids`（键为 tgid）。
- eBPF 在 `sched_process_fork` 中：父进程在集合里，就把子进程加入集合。这一步在内核里完成，没有竞态。
- `sched_process_exit` 时从集合中移除。
- 快照和探针生效之间有一小段窗口：先挂探针再做快照，之后重扫一遍补齐。

## 5. 权限与安装

- 以 systemd 服务 `agentwatchd.service` 运行，使用 root；也可以配置 `AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_SYS_RESOURCE CAP_SYS_ADMIN`（fanotify 和 cgroup 需要 SYS_ADMIN）。
- 读 `/proc/<pid>/*` 需要 `CAP_SYS_PTRACE`，或者和目标同 uid。
- 发布形式：静态链接的 musl 二进制【待验证：Aya 在 musl 上是否可用】，打成 `.deb`、`.rpm` 和 tar.gz。eBPF 字节码在编译时嵌入二进制（使用 CO-RE）。
- 需要处理的内核配置与参数：
  - `kernel.unprivileged_bpf_disabled` 不影响 root。
  - lockdown=confidentiality 模式会禁止 `bpf_probe_read_kernel`。遏到这种情况，在 `aw doctor` 中提示，并降级到 legacy 模式。

## 6. 已知坑

| 问题 | 影响 | 对策 |
|---|---|---|
| 内核函数被内联或改名（`tcp_cleanup_rbuf` 等） | kprobe 挂不上 | 挂载时逐个探测，失败就写 Gap，并在能力报告中标黑；各函数的备选探针列表维护在代码里 |
| verifier 对循环和栈大小的限制 | argv 和路径拷贝受限 | 用 per-CPU 数组做暂存区；设置长度上限，超出部分截断并标记 |
| `bpf_d_path` 只能在白名单函数上使用 | 不是哪里都能取到绝对路径 | 取不到时用 dentry 遍历或用户态规范化，并标注 `path_resolved=false` |
| 高频 read/write（如编译、`node_modules`） | ringbuf 压力大 | 在内核侧聚合，不逐条上报；ringbuf 16 MB；丢失时计数 |
| 容器里的进程 | PID 命名空间和路径不一致 | 记录宿主机 tgid 和 `mnt_ns` id；路径以宿主机视角解析【待验证】 |
| io_uring | read/write 不经过系统调用 tracepoint | 挂 `io_uring:io_uring_submit_req` 做计数；字节数标 NA【待验证】 |
| WSL2 | 内核是微软定制的，有 BTF【待验证】 | 当作普通 Linux 处理；需要单独写说明 |

## 7. 测试方法

- **单元测试**：解码器（字节流 → RawEvent）用 `fixtures/linux/*.bin` 做回放测试，无需特权。
- **端到端**：GitHub 托管的 `ubuntu-latest` runner 可以用 sudo 加载 eBPF。在上面跑 `sim/` 剧本，并断言召回率和字节误差。
- **内核矩阵**：用 `vmtest` 或 `virtme-ng` 在 QEMU 里跑 5.8、5.15、6.1、6.6、最新稳定版。还要覆盖一个不带 BTF 的内核，用来验证 legacy 档位【待验证 SPIKE-01】。
- **压测**：对 Linux 内核源码执行 `git status` 和 `rg`，并做一次 `npm install`；测量 CPU 占用和丢失率。

## 8. 可参考的开源项目

| 项目 | 许可证 | 参考什么 |
|---|---|---|
| Aya / aya-template | MIT / Apache-2.0 | 项目骨架、ringbuf 用法、CO-RE |
| bcc libbpf-tools（execsnoop、opensnoop、tcplife、tcptop、filetop） | Apache-2.0（eBPF 部分双授权 GPL） | 探针位置和字段的取法 |
| Tracee | Apache-2.0（eBPF 部分 GPL-2.0） | 路径解析、容器上下文 |
| Tetragon | Apache-2.0（eBPF 部分 GPL-2.0） | 内核侧过滤、进程树缓存 |
| Falco / falcosecurity-libs | Apache-2.0（驱动部分 GPL-2.0） | 系统调用覆盖清单 |
| ecapture | Apache-2.0 | TLS uprobe |
| pspy | GPL-3.0 | 只参考思路（无特权轮询进程），不复制代码 |

> eBPF 程序若要使用 GPL-only 的 helper（如 `bpf_probe_read_kernel` 等），就必须声明 GPL 兼容的许可证。建议 `aw-ebpf` 采用 `MIT OR GPL-2.0` 双授权，用户态代码不受影响。见 ADR-0010。
