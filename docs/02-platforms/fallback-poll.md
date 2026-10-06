# 跨平台轮询兜底采集器

> 状态：草案
> 最后更新：2026-10-06
> 关联：REQ-01、NFR-06、[capability-matrix](capability-matrix.md)

本文对应 crate `aw-collector-poll`。

## 1. 用途

1. **无特权或无原生能力时仍能工作**：用户不愿安装特权服务，或者原生采集器初始化失败，比如缺少 BTF、没有完全磁盘访问。
2. **早期开发的参照实现**：P0/P1 时先把管道、存储和 UI 跑通。
3. **附着模式下的初始快照**：对应 CAP-PROC-05。

轮询采集器产生的所有事件等级都是 **S**。会话上标注“采样模式——短命进程和短连接可能遗漏”。

## 2. 机制

| 内容 | 实现 | 周期 | 产生的 EventKind |
|---|---|---|---|
| 进程列表 | `sysinfo` crate（各平台原生枚举）；以 `(pid, start_time)` 做差分 | 250 ms（可配置） | ProcessStart / ProcessExit（退出码为 NA） |
| 命令行与 cwd | `sysinfo` 或平台接口 | 只在发现新进程时读一次 | 随 ProcessStart |
| 连接列表 | `netstat2` / `listeners` crate（Linux：`/proc/net/*` 或 sock_diag；Windows：`GetExtendedTcpTable`；macOS：libproc） | 1 s | NetConnect / NetClose |
| 连接字节数 | Linux：sock_diag `tcp_info`（同用户无需特权【待验证】）；Windows：`GetPerTcpConnectionEStats`（需要先启用统计，这一步要管理员权限【待验证】）；macOS：`nettop`（要 root） | 1 s | NetSend / NetRecv（由差分得到）。拿不到时为 NA |
| 进程级 I/O 计数 | Linux：`/proc/<pid>/io` 中的 `rchar`/`wchar`；Windows：`GetProcessIoCounters`；macOS：`proc_pid_rusage` | 1 s | （进程级汇总指标，并非文件事件） |
| 打开的文件 | Linux：`/proc/<pid>/fd` 的快照；macOS：libproc `PROC_PIDLISTFDS`；Windows：不支持（句柄枚举代价高） | 2 s | FileOpen（由快照差分得到） |
| 文件变化 | `notify` crate 监视用户指定的目录，默认是工作目录和敏感路径。**无法得知是哪个进程做的** | 事件驱动 | FileWrite / FileCreate / FileDelete / FileRename（进程归属为 NA；由关联层按时间和范围给出 I 级归属） |

## 3. 限制

- **拿不到**：文件读取（只有进程级的 `rchar` 总量）、短命进程的命令行、DNS 和 SNI。
- 进程级的 `rchar`/`wchar` 包含 socket 和管道 I/O。展示时标为“进程 I/O 总量（含非文件）”，不要当作文件读取量。
- 开销与间隔成反比。默认只枚举范围内的 PID；只有发现新子进程时，才做一次全量枚举。

## 4. 与原生采集器共存

- daemon 启动时按优先级尝试采集器：原生 → legacy → poll。每类能力单独选择来源，可以混用；例如 macOS M1 的进程和文件用 eslogger，网络用 nettop。
- 会话元数据里记录**每类能力实际使用的来源**，供 UI 展示和导出。

## 5. 测试

- 可以在所有 CI runner 上无特权运行。用 `sim/` 剧本验证：长命进程和长连接能被捕获，字节误差达标；另外对短命进程的漏报率做度量，只报告、不断言。
