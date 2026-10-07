# 架构决策记录（ADR）

> 状态：已确认
> 最后更新：2026-10-06
> 关联：[docs/README.md](../README.md)

## 流程

1. **何时写**：选型、改变模块边界、修改数据模型或证据语义、引入依赖重的组件（驱动、系统扩展、新语言）、需要权衡安全或隐私时。
2. **怎么写**：复制 [template.md](template.md)，取下一个编号，文件名用 `NNNN-kebab-title.md`。初始状态为“提议”。
3. **评审**：以 PR 形式提交，打标签 `type:adr`。合并时状态改为“已接受”。
4. **变更**：已接受的 ADR 不大改，而是新写一篇替代它。旧 ADR 状态改为“已替代（被 ADR-XXXX）”。错别字和链接这类修正可以直接改。
5. **AI 协作**：Agent 在实现中发现需要违背某个 ADR 时，必须停下来提出新的 ADR 提议，不得自行绕开。

## 索引

| 编号 | 标题 | 状态 |
|---|---|---|
| [ADR-0001](0001-rust-workspace.md) | 使用单一 Rust workspace 实现核心 | 已接受 |
| [ADR-0002](0002-embedded-web-ui.md) | UI 采用内嵌 Web UI（React + Vite + rust-embed） | 已接受 |
| [ADR-0003](0003-sqlite-storage.md) | 本地存储采用 SQLite（WAL） | 已接受 |
| [ADR-0004](0004-evidence-levels.md) | 所有记录携带证据等级，关联只产生推测 | 已接受 |
| [ADR-0005](0005-privileged-daemon-split.md) | 特权 daemon 与普通权限 CLI/UI 分离 | 已接受 |
| [ADR-0006](0006-explicit-mitm-proxy-for-url.md) | 完整 URL 通过显式 MITM 代理获取 | 已接受 |
| [ADR-0007](0007-process-identity.md) | 进程身份使用 pid + 启动时间 | 已接受 |
| [ADR-0008](0008-windows-etw-no-driver.md) | Windows 只用 ETW，不开发内核驱动 | 已接受 |
| [ADR-0009](0009-macos-two-step.md) | macOS 分两步：先用系统工具，再做原生 ES + NE | 已接受 |
| [ADR-0010](0010-linux-ebpf-with-fallback.md) | Linux 用 Aya eBPF，并提供非 eBPF 降级 | 已接受 |
| [ADR-0011](0011-aggregate-first.md) | 采集端先聚合再存储 | 已接受 |
| [ADR-0012](0012-no-content-redact-before-write.md) | 不存内容，写入前脱敏 | 已接受 |
| [ADR-0013](0013-inter-agent-observation.md) | 以通道为事实、协议为增强的 Agent 间通信观测 | 提议 |

## 待写的 ADR（候选）

- 网络流量的字节口径定义（目前写在 network-attribution.md 中，SPIKE-01/02 之后定稿）。
- 是否引入 Tauri 桌面外壳（P4）。
- Agent 自报告（E3）的接入协议（SPIKE-07 之后）。
- 数据库加密（SQLCipher）是否默认开启。
