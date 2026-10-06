# SPIKE-03 macOS：eslogger + nettop + pktap 概念验证

> 状态：未开始
> 最后更新：2026-10-06
> 关联：CAP-PROC-01~04、CAP-FILE-01~07、CAP-NET-01~04、CAP-DNS-01~03、CAP-PRIV-01/03/04、ADR-0009
> 时间盒：3 人天
> 负责人：

## 1. 问题

1. eslogger 各事件的 JSON 字段路径是什么？在 macOS 13、14、15、26 之间有没有差异？
2. 订阅 `open` 时全系统的事件率是多少？采用“先快速匹配 PID 再解析 JSON”的方案，daemon 的 CPU 开销是多少？不订阅 `open` 时又是多少？
3. `seq_num` 和 `global_seq_num` 是否出现在 eslogger 的输出里，能否用来检测丢失？
4. nettop 用什么参数组合能得到每条连接的累计字节数和 PID？是否包含 UDP/QUIC？字节误差是多少？一个采样间隔内的短连接会漏掉多少？
5. pktap 加 `-k` 能否给出 PID？pcapng 中的进程元数据怎么解析？
6. 用 `POSIX_SPAWN_START_SUSPENDED` 加 `SIGCONT` 的启动方式是否可行？
7. 托管的 macOS runner 上能否以某种方式授予完全磁盘访问？

## 2. 假设

- 不订阅 `open` 时 CPU 开销小于 3%，订阅时可能达到 5%–10%。
- nettop 的字节误差小于 5%。
- pktap 能给出进程信息。

## 3. 方法

- 环境：Apple Silicon 上的 macOS 15 和 26；如果有条件，再加一台 macOS 13 的 Intel 机器。
- 步骤：
  1. 录制每种事件的样本 JSON，存入 `fixtures/macos/eslogger-<ver>/`。
  2. 写一个 Rust 小程序管理 eslogger 和 nettop 子进程，跑 `sim/` 雏形脚本。
  3. 用 Objective-See 工具和 `fs_usage` 做对照。
- 代码位置：`spikes/SPIKE-03/`

## 4. 通过标准

| 指标 | 通过 | 不通过时的预案 |
|---|---|---|
| 进程和文件事件召回率 | ≥95% | 提前做 M2 原型 |
| CPU（不订阅 open） | <3% | 提前做 M2 |
| 网络字节误差（长连接） | <5% | 改用 libproc 或 提前做 NE |

## 5. 结果

（待填）

## 6. 结论

（待填）

## 7. 对文档的影响

- [ ] capability-matrix 的 M1 行
- [ ] macos.md §1：字段路径、命令参数
- [ ] 风险登记：eslogger 输出格式的稳定性
