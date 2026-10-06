# SPIKE-02 Windows：ETW 概念验证

> 状态：未开始
> 最后更新：2026-10-06
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
- 代码位置：`spikes/SPIKE-02/`

## 4. 通过标准

| 指标 | 通过 | 不通过时的预案 |
|---|---|---|
| 事件召回率（对照 Procmon） | ≥95% | 调整关键字，或增加系统日志会话 |
| 繁忙时 CPU | <5% | 优化过滤路径；仍不达标就重新评估 ADR-0008 |
| EventsLost | 典型场景下为 0 | 调整缓冲区参数 |
| 命令行命中率 | ≥99%（长命进程） | 启用系统日志会话 |

## 5. 结果

（待填）

## 6. 结论

（待填）

## 7. 对文档的影响

- [ ] capability-matrix 的 Windows 行
- [ ] windows.md：去掉 GUID、事件 ID 的【待验证】标记
- [ ] ADR-0008 是否维持
