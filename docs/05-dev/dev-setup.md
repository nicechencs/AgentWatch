# 开发环境

> 状态：草案
> 最后更新：2026-10-06
> 关联：NFR-08、[ADR-0001](../03-adr/0001-rust-workspace.md)、[repo-layout](repo-layout.md)、[linux](../02-platforms/linux.md)、[windows](../02-platforms/windows.md)、[macos](../02-platforms/macos.md)

## 1. 通用工具链

| 工具 | 版本 | 用途 |
|---|---|---|
| rustup + stable | 按 `rust-toolchain.toml` | 除 aw-ebpf 外的全部 crate |
| Rust nightly + `rust-src` | 按 `crates/aw-ebpf/rust-toolchain.toml` | 仅编译 aw-ebpf（Linux） |
| `bpf-linker` | 最新 | 链接 eBPF 目标（`cargo install bpf-linker`） |
| Node.js LTS + pnpm | Node ≥ 20、pnpm ≥ 9 | ui/ |
| sccache | 最新 | 编译缓存（可选但推荐） |
| cargo-nextest | 最新 | 更快的测试运行器（可选） |
| cargo-deny、cargo-audit | 最新 | 本地复现 CI 门禁 |
| cargo-insta | 最新 | 审阅快照（`cargo insta review`） |
| gh CLI、PowerShell 7 | 最新 | 同步 Issue 与标签（scripts/） |

一键检查：`cargo xtask doctor-dev`【待实现】输出缺失的工具。

## 2. 各平台额外要求

### 2.1 Linux
- 内核 ≥ 5.8 且开启 BTF（`ls /sys/kernel/btf/vmlinux`）。低于此只能开发降级路径。
- 包：`build-essential`、`clang`、`llvm`、`libelf-dev`、`pkg-config`、`mold`。
- 构建 eBPF：`cargo xtask build-ebpf`（输出到 `target/bpfel-unknown-none/`，由 aw-collector-linux 嵌入）。
- 查看内核日志：`sudo cat /sys/kernel/debug/tracing/trace_pipe`（aya-log 也可用）。

### 2.2 Windows
- Visual Studio 2022 Build Tools（“使用 C++ 的桌面开发”，含 Windows SDK）。
- 链接器：推荐 `rust-lld`（见 §3）。
- 调试 ETW：在**管理员**终端运行；辅助工具 `logman query -ets`（查看已有会话，清理崩溃后残留的 `AgentWatch*` 会话：`logman stop <name> -ets`）、`wpr`/WPA、`tracerpt`。
- 可选：Sysmon（对照数据源）。

### 2.3 macOS
- Xcode（含命令行工具）；macOS ≥ 13。
- 给终端 App（Terminal / iTerm / VS Code）授予**完全磁盘访问**：系统设置 → 隐私与安全性 → 完全磁盘访问。`eslogger` 需要 root + 该权限。
- 验证：`sudo eslogger exec | head -n 3`。
- P4 开发系统扩展时需要：Apple Developer 账号、已获批的 entitlement（见 [SPIKE-08](../06-research/SPIKE-08-apple-entitlements.md)）、开发机上 `systemextensionsctl developer on`（需关闭 SIP 的部分限制【待验证】，建议在虚拟机里做）。

### 2.4 WSL2
- 可以做大部分 Linux 开发，但 eBPF 有限制：
  - 微软内核是否开启 BTF、`CONFIG_BPF_LSM`、所需 kprobe，随版本变化【待验证：SPIKE-01 记录】；可自编译内核或改用虚拟机 / 云主机。
  - WSL2 的网络经过 NAT/虚拟交换机，流量数据与真机不同，**不能用于验收字节误差**。
- 正式验收以真机或完整 VM（Ubuntu 22.04 / 24.04）为准。

## 3. 编译加速

`.cargo/config.toml` 示例（链接器配置可按本机情况注释掉）：

```toml
[alias]
xtask = "run --package xtask --"

[target.x86_64-unknown-linux-gnu]
linker = "clang"
rustflags = ["-C", "link-arg=-fuse-ld=mold"]

[target.x86_64-pc-windows-msvc]
linker = "rust-lld.exe"

# [build]
# rustc-wrapper = "sccache"     # 也可用环境变量 RUSTC_WRAPPER=sccache
```

`Cargo.toml` profile：

```toml
[profile.dev]
debug = "line-tables-only"
[profile.dev.package."*"]
opt-level = 1                   # 依赖稍微优化，运行不至于太慢
[profile.release]
lto = "thin"
codegen-units = 1
strip = true
panic = "abort"                 # 【待定】daemon 是否需要 unwind 以隔离采集线程 panic
```

习惯：
- 日常只跑 `cargo check -p <crate>`；只对改动的 crate 跑测试：`cargo nextest run -p aw-pipeline`。
- 改动 aw-core 会触发全量重编译；把频繁变化的逻辑放在下游 crate。
- UI 开发用 Vite dev server（`pnpm -C ui dev`），通过代理访问本地 daemon API；不需要重编 daemon。daemon 的 `--ui-dir <path>` 开发参数从磁盘读 UI，而不是嵌入版本【待实现】。
- 安全软件实时扫描会明显拖慢 Windows 编译：把 `target/`、`%USERPROFILE%\.cargo`、sccache 缓存目录加入 Defender 排除项，或使用 Dev Drive（ReFS）。

## 4. 特权运行与调试

| 场景 | Linux | Windows | macOS |
|---|---|---|---|
| 单进程调试 | `cargo build && sudo -E target/debug/aw dev -- run -- bash` | 管理员终端：`target\debug\aw.exe dev -- run -- cmd` | `sudo -E target/debug/aw dev -- run -- zsh` |
| 分离运行 | `sudo -E target/debug/agentwatchd --foreground`，另开终端用普通用户跑 `aw` | 管理员运行 `agentwatchd.exe --foreground` | 同 Linux |
| 调试器 | `sudo -E rust-gdb` / VS Code + CodeLLDB（以 root 启动） | VS Code 以管理员身份启动，或 WinDbg | lldb；终端需完全磁盘访问 |
| 日志 | `RUST_LOG=aw=debug` | 同左 | 同左 |

说明：
- `aw dev` 把 daemon 与 CLI 合并为单进程（[architecture §4](../01-architecture/architecture.md#4-进程模型)），数据库默认写到 `./.aw-dev/`，与正式安装隔离。
- `sudo -E` 保留 `RUST_LOG` 与 cargo 相关环境变量；不要用 `sudo cargo`，否则 `target/` 和缓存会变成 root 所有。
- 被 `aw run` 启动的目标进程会降权回原用户（`SUDO_UID`），详见 [process-tracking](../01-architecture/process-tracking.md)。
- 不要在日常使用的主力机上长时间运行调试版 daemon：未优化构建的开销远高于预算。

## 5. 常见问题

| 现象 | 原因 | 处理 |
|---|---|---|
| eBPF 加载报 `Operation not permitted` | 权限不足或 `kernel.unprivileged_bpf_disabled` | 用 root；确认 `CAP_BPF`、`CAP_PERFMON` |
| verifier 拒绝程序 | 循环、栈超过 512 B、未检查指针 | 看完整 verifier 日志（aya 的 `VerifierLogLevel::VERBOSE`） |
| ETW `StartTrace` 返回 `ERROR_ALREADY_EXISTS` | 上次崩溃残留会话 | `logman stop AgentWatch-<n> -ets`；daemon 启动时应自动清理 |
| ETW 只能开一个 NT Kernel Logger | 其他工具（如 Process Monitor、WPR）占用 | 关闭其他工具；设计上优先用普通会话 + Kernel-* provider（见 windows.md） |
| eslogger 报 `Not permitted` | 终端缺少完全磁盘访问 | 授权后重启终端 |
| macOS 上 ES 客户端被杀 | 处理太慢触发 deadline（仅 AUTH） | 本项目只用 NOTIFY；若仍出现请记录到 SPIKE-03 |
| Windows 编译很慢 | Defender 实时扫描 | 加排除项或用 Dev Drive |
| `cargo check --workspace` 在 macOS 报 Windows 依赖错误 | 平台依赖没放进 `target.'cfg'` | 按 [repo-layout §4](repo-layout.md#4-平台隔离) 修正 |
