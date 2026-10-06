# ADR-0007 进程身份使用 pid + 启动时间

> 状态：已接受
> 最后更新：2026-10-06
> 关联：REQ-02、[process-tracking](../01-architecture/process-tracking.md)

## 背景

PID 会被复用。Windows 上复用得很快，Linux 上在 `pid_max` 范围内循环使用。只用 PID 做身份，会把不同进程的事件串在一起。

## 决策

- 进程在存储中的主键为 `proc_uid: u64`，取值为 `xxh3_64(host_boot_id ‖ pid ‖ start_time)`。
- `start_time` 在各平台的来源如下：

| 平台 | 来源 |
|---|---|
| Linux | `task->start_time`，即自开机以来的单调纳秒；用户态对应 `/proc/<pid>/stat` 第 22 列。启动 ID 用 `/proc/sys/kernel/random/boot_id` |
| Windows | 进程 CreateTime（FILETIME）。启动 ID 用启动时间，或者 `GetTickCount64` 推算 |
| macOS | `audit_token` 中的 pidversion（ES 提供），或 `proc_bsdinfo.pbi_start_tvsec/usec`。启动 ID 用 `kern.bootsessionuuid` |

- 同时保留原始的 `pid` 和 `start_time` 字段，用于展示和排障。
- 父子关系存 `parent_proc_uid`。如果父进程启动时间晚于子进程（说明 PID 被复用了），就把父进程置为 NA。
- 不同采集器对同一进程给出的 start_time 精度不同（例如轮询模式只有毫秒），所以哈希前统一截断到 **10 ms** 精度【待验证 SPIKE-01/02/03：同一进程在内核和用户态两个来源下是否得到同一个值】。

## 备选方案

| 方案 | 不选的原因 |
|---|---|
| 自增序列号 | 重启或多个采集器之间无法对齐 |
| Linux pidfd / macOS audit token 等平台特有的方式 | 跨平台不一致；但可以作为辅助字段保留 |

## 后果

- 正面：结果确定；多个采集器可以独立算出同一个 ID。
- 代价：启动时间需要跨来源对齐；10 ms 内 PID 复用的极端情况无法区分。
