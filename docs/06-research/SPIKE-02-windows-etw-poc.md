# SPIKE-02 Windows：ETW 概念验证

> 状态：部分完成
> 最后更新：2026-10-07
> 关联：CAP-PROC-01~04、CAP-FILE-01~07、CAP-NET-01~04、CAP-DNS-01~03、CAP-URL-03、CAP-PRIV-01/03/04、ADR-0008
> 时间盒：3 人天
> 负责人：

## 1. 问题

1. ferrisetw 能否在一个实时会话里同时启用 Kernel-Process、Kernel-File、Kernel-Network、DNS-Client 四个 provider？[windows.md](../02-platforms/windows.md) 里列的 GUID、事件 ID 和字段名是否正确？
2. **命令行**从哪里取：Kernel-Process 的事件是否带 CommandLine？如果不带，用系统日志会话的 Process 事件，还是用 `NtQueryInformationProcess` 补读？短命进程（小于 10 ms）的命中率是多少？
3. Kernel-File 事件头里的 PID，对 Read/Write 事件是否可靠？缓存管理器的 I/O 有多少归到了 PID 4？
4. DNS-Client 3006/3008 的 PID 是否是原始请求方？
5. Kernel-Network 的 size 是否包含重传？与已知上传字节数的误差是多少？
6. 系统繁忙时（例如开着 Defender 全盘扫描、同时跑 `npm install`），用户态尽早过滤的方案 CPU 开销是多少？`EventsLost` 是多少？
7. pktmon 能否被程序以实时方式消费，用来取 SNI？
8. 托管的 `windows-latest` runner 上能否创建这些会话？

## 2. 假设

- 四个 provider 都可用；命令行需要补读；系统繁忙时 CPU 开销 3%–5%；DNS 的 PID 是原始请求方。

## 3. 方法

- 环境：Win10 22H2、Win11 24H2、GitHub `windows-latest`。
- 步骤：
  1. 用 `logman query providers` 和 `wevtutil gp /ge /gm` 导出各 provider 的 manifest，存入 `assets/SPIKE-02/`。
  2. 写一个 ferrisetw 程序把事件输出成 JSONL，跑 `sim/` 雏形脚本。
  3. 用 Process Monitor 同时采集，作为对照。
  4. 压测并读取会话统计。
- 代码位置：任务卡 P0-WIN-01 的文件范围是 `crates/aw-collector-windows/examples/`，不是本节原先写的 `spikes/SPIKE-02/`。该目录没有创建。可编译的订阅草稿是 `crates/aw-collector-windows/examples/poc.rs`，依赖钉在该 crate 的 `Cargo.toml`：`ferrisetw = "=1.2.0"`（MIT OR Apache-2.0）。没有改根 `Cargo.toml`。没有 WinDivert，没有内核驱动。

## 4. 通过标准

| 指标 | 通过 | 不通过时的预案 |
|---|---|---|
| 事件召回率（对照 Procmon） | ≥95% | 调整关键字，或增加系统日志会话 |
| 繁忙时 CPU | <5% | 优化过滤路径；仍不达标就重新评估 ADR-0008 |
| EventsLost | 典型场景下为 0 | 调整缓冲区参数 |
| 命令行命中率 | ≥99%（长命进程） | 启用系统日志会话 |

## 5. 结果

2026-10-07，P0-WIN-01 只写出了 PoC 二进制的源码，**没有以提升权限运行**，也没有以任何会打开系统 ETW 会话的方式运行。`cargo check -p aw-collector-windows --all-targets` 只做类型检查，不执行 `main`，不调用 `StartTraceW` / `EnableTraceEx2` / `OpenTraceW`。因此：

- **没有测量。** 事件率、CPU、`EventsLost`、字节误差、命令行命中率都没有数字。下面不填任何估算值。
- 第 4 节的通过标准一条都没有达到，也没有被判定为不通过。
- 没有导出 manifest，没有跑 `sim/`，没有对照 Procmon，没有在 Win10 22H2、Win11 24H2 或 `windows-latest` 上创建会话。

`poc` 在被人从已提权的 shell 启动时，会用 ferrisetw 的**用户态** `UserTrace`（会话名 `AgentWatch-SPIKE-02`）同时启用上面四个 provider，把每条事件打成一行 JSON。它不启动 NT Kernel Logger。`--pid` 只按 ETW 事件头里的进程号过滤，不构建进程树。缺权限时（ferrisetw 把 Win32 错误 5 包成 `io::Error`）打印说明并以退出码 2 结束；不自我重启、不调用 ShellExecute、不弹 UAC、不做第二次尝试。关键字位和属性名是从 windows.md 抄来的，本次没有核实。

## 6. 结论

没有结论。二进制存在并能通过类型检查，但 spike 本身没有执行。第 1 节的八个问题全部仍是【待验证】：

1. 【待验证】四个 provider 能否同处于一个实时会话。windows.md 里的 GUID、事件 ID、关键字位和字段名是否正确。
2. 【待验证】命令行从哪里取：Kernel-Process 事件 1 是否有 `CommandLine`，还是要用 NT Kernel Logger 或 `NtQueryInformationProcess`。短命进程（小于 10 ms）命中率未知。
3. 【待验证】Kernel-File 事件头 PID 对 Read/Write 是否可靠；缓存管理器 I/O 有多少归到 PID 4。
4. 【待验证】DNS-Client 3006/3008 的 PID 是否是原始请求方。
5. 【待验证】Kernel-Network 的 `size` 是否包含重传；与已知上传字节数的误差未知。
6. 【待验证】系统繁忙时的 CPU 开销和 `EventsLost`未知。
7. 【待验证】pktmon 能否被程序以实时方式消费并取到 SNI。
8. 【待验证】托管的 `windows-latest` runner 能否创建这些会话。

windows.md 上现有的【待验证 SPIKE-02】标记不动。

## 7. 对文档的影响

- [ ] capability-matrix 的 Windows 行
- [ ] windows.md：去掉 GUID、事件 ID 的【待验证】标记
- [ ] ADR-0008 是否维持
