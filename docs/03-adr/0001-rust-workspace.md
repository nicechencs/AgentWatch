# ADR-0001 使用单一 Rust workspace 实现核心

> 状态：已接受
> 最后更新：2026-10-10
> 关联：REQ-01、NFR-01~04、NFR-07、NFR-08、ADR-0010

## 背景

需要在三个平台上调用底层接口：Linux 上的 eBPF、Windows 上的 ETW、macOS 上的 Endpoint Security。同时要求常驻开销低、安装包小、维护成本低，并且主要由 AI 辅助开发。

## 决策

- 核心（daemon、采集器、管道、存储、代理、CLI）放在**一个 Cargo workspace** 里。crate 划分如下：
  `aw-core`、`aw-pipeline`、`aw-store`、`aw-proxy`、`aw-daemon`、`aw-cli`、`aw-collector-{linux,windows,macos,poll}`、`aw-ebpf`、`aw-agent-adapters`。
- 只有 macOS 的 Network Extension 用 Swift 写（放在 `macos-ext/`），因为系统扩展的入口只能用 Swift/ObjC。
- 前端用 TypeScript，见 ADR-0002。
- 桌面 App 是主要形态（2026-10-10 修订，见 ADR-0002）：外壳用 **Tauri 2（Rust）**，放在 `app/src-tauri/`（crate `aw-desktop`）。它自带一个 `[workspace]`，**不是**根 workspace 的成员：Linux 上编译它需要 webkit2gtk 等系统库，留在根 workspace 会让每个 runner 的 `cargo build/test --workspace` 都依赖这些库。外壳只依赖 Tauri 和标准库，不依赖 `aw-daemon` 等核心 crate，与 daemon 之间只走内部通道（ADR-0005）。
- 不引入 Go。外壳、daemon、CLI 都留在 Rust；本 ADR 的备选表里 Go 的结论不变。
- 依赖方向：平台 crate 只依赖 `aw-core`；`aw-pipeline` 和 `aw-store` 不依赖任何平台 crate；只有 `aw-daemon` 把它们组装起来。
- 编译提速：
  - 平台 crate 用 `cfg(target_os)` 隔离，非当前平台的 crate 编译为空。
  - 日常开发只跑 `cargo check -p <crate>`。
  - 使用 sccache；Linux 上用 mold 链接器，Windows 上用 lld-link。
  - dev profile 把依赖的 `opt-level` 设为 1。
  - 控制依赖数量，禁用不需要的 feature。

## 备选方案

| 方案 | 优点 | 缺点 | 结论 |
|---|---|---|---|
| **Go** | 编译快；`cilium/ebpf` 非常成熟；交叉编译简单；AI 生成的 Go 代码质量也不错 | ETW 生态弱（要自己封装 TDH）；macOS ES 只能经 cgo 调用，交叉编译的优势也就没了；GC 使常驻内存更高；二进制体积相近 | 作为备选。如果 Rust 的编译速度成为主要瓶颈，就重新评估 |
| C++ | 底层接口最直接 | 内存安全问题；跨平台构建体系复杂；AI 生成的代码更难审查 | 不选 |
| 每个平台用各自的原生语言（C#/Swift/Go） | 各平台生态最好 | 三套代码；管道和存储要写三遍，或者拆成跨进程服务 | 不选 |
| Python/Node 调用系统工具 | 原型最快 | 开销高；分发体积大；类型安全弱 | 只用于一次性的 spike 脚本 |

## 后果

- 正面：只发布一个二进制；内存和 CPU 都可控；强类型可以拦住很多 AI 写出的错误；平台无关代码可以在任意平台上测试。
- 代价：冷编译慢（预计全量 release 编译 3–6 分钟【待验证】）；eBPF 部分需要 nightly 工具链和 `bpf-linker`。
- 跟进：P0 里要不要配置 sccache 的远程缓存；CI 使用 `Swatinem/rust-cache`。

## 重新评估的触发条件

- 增量 `cargo check` 长期超过 10 s（违反 NFR-08）。
- Aya 或 ferrisetw 停止维护。
