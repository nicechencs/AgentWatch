# 调研与技术验证（Spike）

> 状态：已确认
> 最后更新：2026-10-06
> 关联：[capability-matrix](../02-platforms/capability-matrix.md)、[roadmap](../04-plan/roadmap.md)

## 规则

1. 文档里带【待验证】的结论，必须能追溯到一个 SPIKE。
2. SPIKE 必须有时间盒。产出的是**结论和数据**，不是产品代码。代码放在仓库的 `spikes/` 目录，可以写得粗糙。
3. 完成后必须处理“对文档的影响”一节的所有勾选项，然后把状态改成“已完成”。
4. 模板见 [spike-template.md](spike-template.md)。

## 索引

| 编号 | 主题 | 平台 | 阶段 | 时间盒 | 状态 |
|---|---|---|---|---|---|
| [SPIKE-01](SPIKE-01-linux-aya-poc.md) | Aya eBPF 概念验证：exec / open / tcp 字节 | Linux | P0 | 3 人天 | 未开始 |
| [SPIKE-02](SPIKE-02-windows-etw-poc.md) | ETW 概念验证：进程 / 文件 / 网络 / DNS | Windows | P0 | 3 人天 | 未开始 |
| [SPIKE-03](SPIKE-03-macos-eslogger-poc.md) | eslogger + nettop + pktap 概念验证 | macOS | P0 | 3 人天 | 未开始 |
| [SPIKE-04](SPIKE-04-proxy-trust-injection.md) | 各运行时对代理和 CA 环境变量的认可度 | 全部 | P0–P1 | 2 人天 | 未开始 |
| [SPIKE-05](SPIKE-05-launch-scoping.md) | 启动模式的范围追踪与权限划分 | 全部 | P0–P1 | 3 人天 | 未开始 |
| [SPIKE-06](SPIKE-06-sqlite-throughput.md) | SQLite 写入吞吐与查询延迟 | 全部 | P0 | 1 人天 | 未开始 |
| [SPIKE-07](SPIKE-07-agent-hooks.md) | Agent 自报告接入方式 | 全部 | P1–P5 | 2 人天 | 未开始 |
| [SPIKE-08](SPIKE-08-apple-entitlements.md) | Apple ES/NE 授权申请与原生原型 | macOS | P0 申请 / P4 实施 | 申请 0.5 人天 + 原型 3 人天 | 未开始 |
| [SPIKE-09](SPIKE-09-ipc-peer-attribution.md) | 本机 IPC 两端配对与 MCP stdio 拦截 | 全部 | P6 | 5 人天 | 未开始 |

## 关键路径

- **SPIKE-08 的授权申请必须在 P0 第一周提交**，审批周期不受我们控制。
- SPIKE-01、02、03 的结果决定 P1 采集器任务的工作量估算。
- SPIKE-04 的结果决定 P3 代理模式能否覆盖主流 Agent。
