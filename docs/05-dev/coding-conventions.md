# 编码规范与 AI 协作约定

> 状态：草案
> 最后更新：2026-10-06
> 关联：NFR-07、REQ-06、REQ-07、[ADR-0004](../03-adr/0004-evidence-levels.md)、[ADR-0012](../03-adr/0012-no-content-redact-before-write.md)、[evidence-model](../01-architecture/evidence-model.md)、[AGENTS.md](../../AGENTS.md)

## 1. 错误处理

- **库 crate**（aw-core、aw-pipeline、aw-store、aw-proxy、各 collector、aw-agent-adapters）：用 `thiserror` 定义具体错误枚举，不对外暴露 `anyhow::Error`。
- **二进制 crate**（aw-daemon、aw-cli、sim、xtask）：用 `anyhow`，在边界处 `.context("…")` 补充上下文。
- 禁止在非测试代码中 `unwrap()` / `expect()`，例外：编译期即可确定的不变量（如常量正则），并写明原因。clippy 开启 `unwrap_used`、`expect_used`（测试中放开）。
- 采集器内部可恢复的错误（单条事件解析失败、进程已退出）**不得中断采集**：计数并在超过阈值时生成 `Gap`。
- 采集线程 panic 由上层捕获并重启采集器，同时写入 `Gap { kind: CollectorRestart }`（NFR-06）。

## 2. 日志

- 统一使用 `tracing`。级别含义：

| 级别 | 用途 | 示例 |
|---|---|---|
| `error` | 需要用户处理的问题 | 采集器无法启动、数据库不可写 |
| `warn` | 功能降级 | 回退到轮询、ETW 丢事件 |
| `info` | 生命周期 | 会话开始/结束、采集器启停 |
| `debug` | 开发排查 | 队列水位、批写耗时 |
| `trace` | 逐事件 | **默认编译移除**（`release_max_level_debug`） |

- **禁止在任何级别的日志中输出未脱敏数据**：命令行、环境变量、URL、HTTP 头、文件内容。需要打印事件时只打印已通过 Redact 阶段的记录，或只打印 `seq`、`kind`、`proc.uid`。
- 用于日志的类型实现 `Debug` 时，含敏感字段的结构体要手写 `Debug`（或用 `#[debug(skip)]` 类宏），避免 `{:?}` 泄露原始值。
- daemon 日志轮转：单文件 10 MB、保留 5 个。

## 3. unsafe 与 FFI

- `unsafe` 只允许出现在平台 crate 的 `ffi/` 子模块和 `aw-ebpf` 中；其他 crate 加 `#![forbid(unsafe_code)]`。
- 每个 `unsafe` 块上方写 `// SAFETY:` 注释，说明满足了哪些前提（指针有效、生命周期、对齐、线程安全）。clippy 开启 `undocumented_unsafe_blocks`。
- FFI 层对外只暴露安全封装；句柄类资源（ETW 会话、Job 对象、ES 客户端、BPF link）用 RAII 类型在 `Drop` 中释放。
- 从内核 / 系统读入的二进制结构一律视为不可信：做长度检查，字符串按有损方式（`from_utf8_lossy` / UTF-16 替换字符）解码，并标注 `path_resolved`。

## 4. 依赖引入

- 版本统一写在根 `Cargo.toml` 的 `[workspace.dependencies]`，子 crate 用 `dep = { workspace = true }`。
- 引入新的**直接**依赖前自查：许可证（仅 MIT / Apache-2.0 / BSD / ISC / Zlib / MPL-2.0 / Unicode；禁止 GPL / AGPL / LGPL 静态链接）、维护活跃度、对编译时间和体积的影响。在 PR 描述中说明理由。
- 重量级依赖（异步运行时、TLS 栈、数据库、UI 框架）只能使用 ADR 或设计文档中已列出的；替换或新增须先写 ADR。
- TLS 统一用 rustls，不引入 OpenSSL。
- 关闭用不到的 default features。
- 前端：新增 npm 依赖同样说明理由；优先使用已定的 React、TanStack Table、ECharts。

## 5. 命名

| 对象 | 规则 | 示例 |
|---|---|---|
| crate | `aw-` 前缀，kebab-case | `aw-collector-poll` |
| 二进制 | `aw`、`agentwatchd` | — |
| 事件类型 | Rust `EventKind` 用 PascalCase；JSON `kind` 用 snake_case | `FileOpen` / `"file_open"` |
| 数据库表与列 | snake_case，表名复数 | `file_access`、`net_flows` |
| 配置键 | 点分 snake_case | `proxy.max_hash_body` |
| CLI 参数 | kebab-case | `--no-follow-children` |
| 措辞模板 ID | 点分 | `infer.temporal` |
| 任务编号 | `Pn-AREA-NN` | `P1-WIN-03` |

### 5.1 source 子源命名

`RawEvent.source` 采用 **「采集器/子源」** 格式（[event-schema](../01-architecture/event-schema.md)）：

- 采集器部分用点分：`linux.ebpf`、`linux.fanotify`、`linux.sock_diag`、`windows.etw`、`macos.eslogger`、`macos.es`、`macos.nettop`、`macos.ne`、`poll`、`proxy`、`agent.<name>`。
- 子源部分用 snake_case，一般是探针或 provider/事件名：`linux.ebpf/tcp_sendmsg`、`windows.etw/kernel_file`、`macos.eslogger/open`。
- 各平台完整的子源列表写在对应平台文档中；新增子源时同步更新。

## 6. 证据与措辞

- 所有构造 `RawEvent` 的代码必须显式传入 `evidence` 和 `source`，不得用默认值。
- 拿不到的字段设为 `None` 并写 `field_evidence` 中的 `NA(reason)`，**不得用 0 或空串代替**（ADR-0004）。
- 自动生成的结论文本只能来自 `crates/aw-pipeline/src/wording/` 中的模板。禁用词以 [evidence-model §7](../01-architecture/evidence-model.md#7-禁止的表述反例清单) 为准，包括（不限于）：
  - “上传了文件”“uploaded file”
  - “泄露”“窃取”“外泄”“exfiltrated”“leaked”“stole”
  - “没有上传任何文件”“安全”“no data leaked”
  - “所有流量”
- 这条规则同样适用于 UI 文案（`ui/src/i18n/`）、CLI 输出和导出内容，CI 中由 `cargo xtask wording-lint` 检查。

## 7. 代码风格

- `rustfmt` 默认配置；`clippy` 在 CI 中 `-D warnings`，另开启 `clippy::pedantic` 的少数规则（在根 `Cargo.toml` 的 `[workspace.lints]` 中统一配置）。
- 公开 API 写文档注释；注释中文或英文均可，同一文件保持一致。
- 异步代码不得在 tokio 线程上做阻塞调用（SQLite、ETW 回调处理）；使用专用线程或 `spawn_blocking`，见 [architecture §6](../01-architecture/architecture.md#6-并发与运行时)。
- TypeScript：`strict` 模式，ESLint + Prettier；API 类型由 daemon 的 OpenAPI 描述生成【待定：P2 选型】。

## 8. 提交信息

使用 Conventional Commits，并在末尾带任务编号：

```text
<type>(<scope>): <简要描述> [<任务编号>]

<可选正文：为什么这样改、影响范围>

Refs #<issue>
```

- `type`：`feat` / `fix` / `perf` / `refactor` / `test` / `docs` / `build` / `ci` / `chore`。
- `scope`：crate 名去掉 `aw-` 前缀（`core`、`pipeline`、`collector-windows`），或 `ui`、`sim`、`docs`。
- 示例：`feat(collector-windows): 解析 Kernel-Network TCP send/recv [P1-WIN-04]`。
- 破坏性变更（schema 主版本、数据库不兼容、CLI 参数移除）在 type 后加 `!` 并在正文写 `BREAKING CHANGE:`。
- AI 生成的提交按所用工具的约定附 `Co-Authored-By` 行。

## 9. AI 协作约定

完整规则见仓库根目录 [AGENTS.md](../../AGENTS.md)，要点：

1. **任务卡驱动**：每次开发对应一张任务卡（`docs/04-plan/tasks/`）。开工前读任务卡及其“参考文档”。
2. **不越出文件范围**：只修改任务卡“文件范围”内的文件。确需越界（如给 aw-core 加字段）时在 PR 描述中单独列出，并说明原因。
3. **改设计前先写 ADR**：实现中发现设计不可行时，停下来写 ADR（状态“提议”），而不是静默改变实现。
4. **文档同步**：实现与文档不一致时，在同一 PR 中更新文档；spike 结论回填能力矩阵并去掉【待验证】。
5. **如实自检**：逐条对照验收标准，贴出命令输出；没有在真机验证的平台标为“未验证”，不得声称通过。
6. **不碍特权与凭据**：AI 不得自行安装系统服务、信任 CA、修改系统安全设置或读取真实凭据文件；这些操作由开发者手动完成。
7. **小步提交**：一个 PR 对应一张任务卡；diff 超过约 800 行（不含快照与生成代码）时拆分。
