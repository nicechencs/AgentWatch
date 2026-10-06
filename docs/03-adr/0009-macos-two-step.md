# ADR-0009 macOS 分两步：先用系统工具，再做原生 ES + NE

> 状态：已接受
> 最后更新：2026-10-06
> 关联：REQ-01、SPIKE-03、SPIKE-08、[macos](../02-platforms/macos.md)

## 背景

macOS 的原生采集接口（Endpoint Security、Network Extension）都需要 Apple 审批的授权，审批周期不确定，而且可能被拒。如果把开发进度绑在审批上，风险太大。

## 决策

- **第一步 M1（P1–P3）**：用系统自带的 `eslogger` 采集进程和文件（E1）；用 `nettop` 采集网络字节（S）；用 pktap 采集 DNS 和 SNI。只需要 root 和完全磁盘访问，不需要任何授权。
- **第二步 M2（P4）**：用 `endpoint-sec` crate 直接调用 ES，并启用反向 mute；用 Swift 写的 NE 内容过滤器系统扩展统计每条连接的字节数（E1）。
- P0 阶段就启动授权申请（SPIKE-08）。
- 两步输出**同一种 RawEvent**。切换到第二步时，管道、存储和 UI 都不用改，只是证据等级提高。
- 如果授权被拒：继续留在 M1，并在文档和 UI 中如实标注。

## 备选方案

| 方案 | 结论 |
|---|---|
| 一开始就等授权下来再做原生 | 进度受 Apple 控制。不选 |
| DTrace / `fs_usage` | 要关闭 SIP，或者是采样性质，输出也不稳定。只作可选补充 |
| 内核扩展（kext） | 已被废弃。不选 |
| OpenBSM 审计（`praudit`） | 自 macOS 11 起已被废弃 |

## 后果

- 正面：macOS 能和其他平台同步进入 MVP。
- 代价：M1 阶段网络只有 S 级；eslogger 全系统事件量大，开销较高；它的输出格式不稳定，引入了维护成本。
- 跟进：SPIKE-03 测量 eslogger 的开销；SPIKE-08 跟踪授权审批。
