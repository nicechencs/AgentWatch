# 性能与资源预算

> 状态：草案
> 最后更新：2026-10-07
> 关联：NFR-01~08、[pipeline](pipeline.md)、[storage](storage.md)、[SPIKE-06](../06-research/SPIKE-06-sqlite-throughput.md)、[inter-agent-communication](inter-agent-communication.md)

## 1. 预算表

| 指标 | 预算 | 测量场景 | 来源 |
|---|---|---|---|
| daemon 空闲 CPU | < 0.5%（单核占比，60 秒平均） | 无活动会话 | NFR-01 |
| 典型会话 CPU | < 3% | `sim/` 剧本 `typical_agent`：每秒约 200 次 open、20 次 exec、10 个连接 | NFR-01 |
| 开启跨 Agent IPC 后的 CPU 增量 | < 1% | 对比 `typical_agent` 开启 / 关闭 IPC 采集 | NFR-01、REQ-11 |
| 压力会话 CPU | < 15%，且不影响被监控进程的正常运行 | `sim/` 剧本 `storm`：每秒 5 万次 open（编译场景） | NFR-01 |
| 被监控进程减速 | `typical_agent` < 3%；`storm` < 15% | 对比不开监控时的剧本耗时 | — |
| daemon RSS | 空闲 < 30 MB；会话中 < 60 MB | 同上 | NFR-02 |
| 内核侧内存 | eBPF map + ring buffer < 16 MB | Linux | — |
| 磁盘增量 | `typical_agent` 1 小时 < 50 MB | — | NFR-03 |
| 事件延迟 | p99 < 2 s（从事件发生到可以查询） | — | NFR-05 |
| 管道吞吐 | 单核达到每秒 20 万条 RawEvent（回放基准） | `cargo bench -p aw-pipeline` | — |
| SQLite 写入 | 每秒 5 万行（批量写入） | SPIKE-06 | — |
| 查询 | 会话内常用筛选 < 300 ms（100 万条记录）；会话列表 < 100 ms | — | REQ-05 |
| 二进制体积 | `aw` + `agentwatchd` 合计 < 20 MB（已 strip，含 UI） | release 构建 | NFR-04 |
| 增量编译 | `cargo check` < 10 s（改动单个非根 crate） | 开发机 | NFR-08 |

【待验证】上表数值是初始目标。P0/P1 的 spike 结束后会按实测结果调整。实测与目标差距超过 2 倍时，必须写 ADR 说明。

## 2. 开销来源与控制手段

| 来源 | 风险 | 手段 |
|---|---|---|
| Windows Kernel-File ETW | 全系统文件 IO 都会触发回调，内核侧无法按 PID 过滤 | 只启用需要的 keyword（Create、Read、Write、Delete、Rename、Close）；回调里先做 PID 位图判定，不属于会话的事件在解析属性前就丢弃；没有会话时停止 File provider。【待验证】ferrisetw 是否支持先读取头部 PID、再解析属性，见 SPIKE-02 |
| Linux eBPF read/write 探针 | 系统调用频率非常高 | 在内核侧按 cgroup 或 PID 过滤；在内核侧对 `(pid, fd)` 做聚合，只在 close 时或每 N 毫秒提交一次计数。这是重要优化项，可以把事件量降低 1–2 个数量级 |
| macOS ES | 客户端处理过慢会导致丢事件；AUTH 事件会阻塞目标进程 | 只订阅 NOTIFY 事件，不订阅 AUTH；使用 mute / inverted mute；eslogger 模式下用独立线程读取管道并做流式 JSON 解析 |
| 代理 | TLS 加解密与哈希计算 | 叶证书缓存；分块哈希只对请求体计算；请求体超过 `proxy.max_hash_body`（默认 50 MB）时只统计字节数 |
| SQLite | 写放大、fsync | WAL + `synchronous=NORMAL`；批量写入；先聚合再存储 |
| 进程补查 | 系统调用开销 | 缓存；对同一 PID 做频率限制 |
| Linux 管道 / Unix socket 探针 | 编译器、shell 管道流量极大 | 只对跨 AgentInstance 的通道按字节计数，过滤在内核侧完成（BPF map `agent_roots`）；同一 Agent 内部只累加总数；5 秒桶聚合后再写 ring buffer |

## 3. 度量方法

- **自身指标**：daemon 暴露 `/api/v1/health?metrics=1`，内容包括：
  - 各采集器的事件速率、丢失计数；
  - 各队列水位；
  - 管道各阶段耗时的直方图；
  - 批写大小与耗时；
  - RSS、CPU、数据库体积。

  `aw doctor --perf` 以表格形式显示。
- **基准测试**：
  - `aw-pipeline` 与 `aw-store` 使用 criterion，输入为 `fixtures/bench/` 中录制的大样本；
  - CI 在 Linux runner 上运行，结果与主分支对比；
  - 回退超过 15% 时在 PR 中提示，但不阻塞合并。
- **端到端性能测试**：
  - 用 `sim/` 剧本各运行 3 次，取中位数；
  - 指标包括剧本耗时（被监控进程减速）、daemon 的 CPU 时间（取自 `getrusage` 或进程计时）、峰值 RSS、数据库增量；
  - 在 Linux 和 Windows 的托管 runner 上每夜运行。托管机器噪声较大，只用来发现趋势。
- **体积**：CI 报告 release 二进制大小，并用 `cargo bloat` 列出占用最大的 20 项。

## 4. 降级阶梯

降级由下列任一条件触发，按级逐步生效；条件解除 30 秒后逐级恢复。
- 入口队列水位达到 80%；
- 管道 CPU 超过预算的 2 倍并持续 10 秒；
- 单会话体积超过 `max_session_bytes`；
- 磁盘余量不足。

每一级的进入和退出都记录为 `Gap{kind: rate_limited, detail: "degrade L<n>"}`，并在 UI 中显示。

| 级别 | 动作 | 保留 | 损失 |
|---|---|---|---|
| L0 | 正常 | 全部 | — |
| L1 | 关闭重复打开合并窗口之外的细节；合并窗口从 1 秒扩大到 10 秒；桶大小从 5 秒扩大到 30 秒 | 所有记录类型 | 时间精度 |
| L2 | 不再记录非敏感路径上的只读 `file_access`，改为按目录统计计数；关闭代理哈希比对 | 写 / 删 / 改名 / exec / 敏感访问、全部网络 | 普通读取的单文件明细 |
| L3 | 按进程限流，只保留每个进程的前 N 条和计数；关闭 DNS 细节，只保留 IP 到域名的映射结果 | 进程树、敏感访问、删除、网络流总量 | 大部分明细 |
| L4 | 只保留进程事件、敏感访问、网络流总量；在 UI 和终端给出显著警告 | 骨架 | 几乎全部明细 |

应急停止：如果 daemon 自身 RSS 超过 `limits.hard_rss_bytes`（默认 512 MB），按以下顺序处理：
1. 冻结所有采集器；
2. 写入 `Gap{kind: restart}`；
3. 自行重启。

任何情况下都不允许拖垮宿主。
