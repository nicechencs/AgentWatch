# ADR-0010 Linux 用 Aya eBPF，并提供非 eBPF 降级

> 状态：已接受
> 最后更新：2026-10-06
> 关联：REQ-01~04、SPIKE-01、[linux](../02-platforms/linux.md)

## 背景

eBPF 是 Linux 上开销最低、能力最全的方式。但内核版本和 BTF 的可用性在各发行版之间差异很大。

## 决策

- 内核态代码用 **Aya**（纯 Rust，不依赖 libbpf 和 clang）编写在 `aw-ebpf` crate 中，使用 CO-RE。字节码在构建时嵌入用户态二进制。
- 三个档位在启动时自动选择：ebpf-full、ebpf-lite、legacy（proc connector + fanotify + sock_diag）。最后还有一层 poll 兜底。
- 最低支持内核 5.8，因为要用 ringbuf 和 `CAP_BPF`。
- 许可证：`aw-ebpf` 采用 `MIT OR GPL-2.0`，这样可以使用 GPL-only 的 helper。

## 备选方案

| 方案 | 结论 |
|---|---|
| libbpf-rs（内核态用 C 编写） | 生态最成熟，可以直接拿 bcc/libbpf-tools 的 C 代码来改；但构建依赖 clang。**作为备选**：如果 SPIKE-01 发现 Aya 在 verifier 兼容性上有硬伤，就切换 |
| 只用 auditd / fanotify | 拿不到按连接的字节数；auditd 开销高，而且和系统自己的 audit 配置会冲突 |
| ptrace | 开销极高，会改变目标行为 |

## 后果

- 正面：全部用 Rust，工具链统一；可以在内核侧做过滤和聚合。
- 代价：需要 nightly 工具链和 `bpf-linker`：Aya 的文档不如 libbpf；AI 对 Aya 的 API 不太熟，需要更多范例。
- 跟进：SPIKE-01 打通 exec、openat、tcp_sendmsg 三个探针并做压测。
