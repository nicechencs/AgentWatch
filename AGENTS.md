# AGENTS.md — AI 协作规则

本文件面向在本仓库工作的 AI Agent（Claude Code、Codex、Cursor 等）和人类协作者。与 `docs/` 冲突时，以 `docs/` 中状态为“已确认”的文档和 ADR 为准，并在 PR 中指出冲突。

## 1. 项目一句话

AgentWatch 是跨平台进程行为审计工具。它的底线是**如实**：每条记录都带证据等级，推测永远标为推测，拿不到的信息标为不可得并写明原因。所有代码和文案都不得破坏这一点。

## 2. 开工前必读

先读 [docs/README.md](docs/README.md)（目录、编号、写作约定），再按任务类型读：

| 任务类型 | 必读 |
|---|---|
| 任何任务 | 任务卡（`docs/04-plan/tasks/Pn-*.md`）及其「参考文档」；[evidence-model](docs/01-architecture/evidence-model.md) |
| 平台采集器（LNX/WIN/MAC/POLL） | [capability-matrix](docs/02-platforms/capability-matrix.md)、对应 `docs/02-platforms/<平台>.md`、[event-schema](docs/01-architecture/event-schema.md)、[process-tracking](docs/01-architecture/process-tracking.md) |
| 管道 / 关联（PIPE） | [event-schema](docs/01-architecture/event-schema.md)、[pipeline](docs/01-architecture/pipeline.md)、[security-privacy](docs/01-architecture/security-privacy.md) |
| 存储 / 导出（STORE） | [storage](docs/01-architecture/storage.md)、[performance-budget](docs/01-architecture/performance-budget.md) |
| 网络 / 代理（PROXY） | [network-attribution](docs/01-architecture/network-attribution.md)、[ADR-0006](docs/03-adr/0006-explicit-mitm-proxy-for-url.md)、[security-privacy](docs/01-architecture/security-privacy.md) |
| daemon / CLI / API | [architecture](docs/01-architecture/architecture.md)、[api-and-cli](docs/01-architecture/api-and-cli.md)、[ADR-0005](docs/03-adr/0005-privileged-daemon-split.md) |
| UI | [ui](docs/01-architecture/ui.md)、[api-and-cli](docs/01-architecture/api-and-cli.md)、[evidence-model 展示样式与措辞](docs/01-architecture/evidence-model.md) |
| Agent 适配（AGENT） | [process-tracking](docs/01-architecture/process-tracking.md)、[SPIKE-07](docs/06-research/SPIKE-07-agent-hooks.md) |
| 技术验证（spike） | 对应 `docs/06-research/SPIKE-NN-*.md`、[spike-template](docs/06-research/spike-template.md) |
| CI / 发布 | `docs/05-dev/ci-release.md`、`docs/05-dev/github-workflow.md` |

## 3. 任务卡驱动

1. 每次工作对应一张任务卡（`Pn-AREA-NN`）。没有任务卡的改动，先在对应阶段文件中补卡，格式见 [tasks/README](docs/04-plan/tasks/README.md)。
2. **只修改任务卡「文件范围」内的文件**。不得不越界时，改动保持最小，并在 PR 描述中逐一列出。
3. 实现要点是建议，限制是硬性要求，验收标准是完成定义。
4. 任务卡与设计文档矛盾时，停下来说明矛盾，不要自行挑一个。
5. 状态以 GitHub Issue 为准，任务卡文件不记录状态。

## 4. 禁止操作

| 禁止 | 原因 / 替代做法 |
|---|---|
| 把代理 CA 装进系统或用户证书库（包括测试和脚本中） | CA 只通过环境变量注入给被启动的进程（ADR-0006）。`aw proxy trust` 只能由用户显式执行 |
| 在日志、数据库、fixtures、快照、报错信息中写入未脱敏数据 | 先脱敏再写入（ADR-0012）。禁止用 `{:?}` 打印包含 argv、环境变量、URL、请求头的结构体 |
| 保存文件内容、HTTP body、`Authorization` / `Cookie` | 只允许保存长度和分块哈希 |
| 引入 GPL / AGPL / LGPL 代码或依赖，或抄写其实现 | GPL 项目（如 LuLu）只看不抄。依赖由 `cargo-deny` 把关；新增依赖在 PR 中写明许可证 |
| 在开发机上执行破坏性的特权命令 | 例如改系统证书库、装卸驱动或系统扩展、删 `/sys/fs/cgroup` 外的东西、`rm -rf` 会话目录之外的路径、关闭安全软件、重启。特权测试放在 CI 或虚拟机里跑；需要在本机提权时先询问 |
| 产品文案、日志、测试期望值中出现“上传了文件”“泄露了”“窃取”等断定式措辞 | 只能使用 evidence-model 中的固定模板；CI 有禁用词检查 |
| 把推测（I）或自报告（E3）升级为更高等级 | 唯一的升级路径是代理模式下的内容哈希匹配（ADR-0004） |
| 用 0、空串或默认值代表“不知道” | 用 `None`，并在 `field_evidence` 中写 `NA(reason)` |
| 静默丢弃事件 | 任何丢弃、限流、采集器重启都要记为 `Gap` |
| 提交凭证、真实用户名或主机名、未清洗的录制样本 | fixtures 先过 `aw fixtures scrub` |
| 在未经评审的情况下修改已确认设计 | 先写 ADR（见 §7） |

## 5. 常用命令

> 代码骨架由 P0-CI-01 建立；在此之前以下命令尚不可用。

```bash
# Rust（日常优先 check，只测自己改的 crate）
cargo check -p <crate>
cargo test  -p <crate>
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
cargo deny check                      # 许可证与漏洞

# 无特权回放测试：用录制的事件流跑管道，并与快照对比
cargo test -p aw-pipeline --test replay
cargo run -p aw-cli -- fixtures replay fixtures/<case>/events.jsonl --expect fixtures/<case>/expected.snap

# 行为模拟器（需要特权，在 CI 或虚拟机里跑）
cargo run -p sim -- run sim/scenarios/typical_agent.toml

# Web UI（ui/ 目录）
pnpm -C ui install
pnpm -C ui dev                        # 开发服务器，代理到本地 daemon
pnpm -C ui lint && pnpm -C ui test
pnpm -C ui build                      # 产物由 aw-daemon 通过 rust-embed 嵌入

# 任务同步到 GitHub（先 DryRun）
pwsh scripts/sync-issues.ps1 -DryRun -Phase P1
```

具体的 crate、测试名和剧本名以 `docs/05-dev/testing.md` 为准。

## 6. 代码组织与平台隔离

- 依赖方向见 [architecture §3](docs/01-architecture/architecture.md)：采集器之间互不依赖，只依赖 `aw-core`。
- `aw-core`、`aw-pipeline`、`aw-store`、`aw-proxy`、`aw-collector-poll`、`aw-agent-adapters`、`aw-cli` **不得包含平台专用代码**，必须能在任意 runner 上无特权测试。
- 平台代码只放在 `aw-collector-{linux,windows,macos}`、`aw-ebpf`、`macos-ext/` 中。各平台 crate 在 lib.rs 顶层用 `#![cfg(target_os = "...")]` 整体门控，在非目标平台上编译为空壳。
- `aw-daemon` 是唯一用 `cfg` 装配各平台采集器的地方。不要在业务逻辑中散落 `cfg(target_os)`。
- 采集器只做“系统事件 → `RawEvent`”的翻译，不做聚合、关联、脱敏。这些逻辑放进 `aw-pipeline`，用 fixtures 测试。
- 新的平台能力或限制，要同步更新 [capability-matrix](docs/02-platforms/capability-matrix.md) 与对应平台文档。
- `unsafe` 只允许出现在平台 crate 的 FFI 边界，并写 `// SAFETY:` 注释。

## 7. 改设计先写 ADR，改代码同步文档

- 对事件模型、证据规则、存储 schema、权限模型、安装产物、依赖选型的改变，先在 `docs/03-adr/` 新建 ADR（使用 [template](docs/03-adr/template.md)），状态设为“提议”。通过后再改设计文档和代码。
- PR 中实现与文档不一致时，**在同一个 PR 里更新文档**。
- spike 得出结论后，去掉相关文档中的【待验证】标注，或改写为实测结论。

## 8. 并行协作（subagent 分片）

适合并行的分片方式（文件范围互不重叠）：

| 分片方式 | 示例 |
|---|---|
| 按平台 | Windows / Linux / macOS 采集器各一个 subagent。各自只写自己的 crate，都只消费已定稿的 `aw-core` |
| 按 crate | `aw-store`、`aw-pipeline`、`aw-proxy`、`aw-cli` 各一个 subagent |
| 按 UI 页面 | 每个页面一个 subagent，只改 `ui/src/pages/<页面>/`。共享组件由一个 subagent 先行完成 |
| 实现与测试流水 | 一个写实现，一个写 fixtures、模拟器剧本和验收测试 |
| 任务卡并行组 | 各阶段任务总表中的“并行组”列，同组任务可同时分派 |

**不能并行**，必须串行并由一个 Agent 单独完成：

- `aw-core` 的类型变更（`RawEvent`、`EventKind`、`Evidence`、`NaReason`）：它影响所有 crate。先合并类型变更，再并行适配。
- 数据库迁移（`aw-store` 的 migrations）：同一时间只能有一个迁移在进行，编号严格递增。
- HTTP API 契约变更：影响 CLI 和 UI。
- workspace 级配置：根 `Cargo.toml`、`deny.toml`、CI workflow、`ui/package.json` 依赖。
- 证据模型与措辞模板。
- 架构决策、凭证或签名操作、最终验收：由主 Agent 或人完成。

## 9. 完成前自检

- [ ] 逐条对照任务卡「验收标准」，贴出命令输出；未满足的条目如实说明。
- [ ] 只修改了「文件范围」内的文件，或已在 PR 中列出越界改动。
- [ ] `cargo fmt`、`clippy -D warnings`、相关 crate 测试通过；改了 UI 则 `pnpm lint/test/build` 通过。
- [ ] 新增字段或记录都有 `evidence` 和 `source`；拿不到的字段标了 `NA(reason)`。
- [ ] 新增的输出、日志、导出路径都经过脱敏；没有保存内容。
- [ ] 文案中没有断定式措辞；推测使用了固定模板。
- [ ] 丢弃或降级路径会产生 `Gap`。
- [ ] 没有引入 GPL 类依赖；新依赖已写明许可证和理由。
- [ ] 平台代码没有泄漏到平台无关 crate。
- [ ] 相关文档（设计文档、能力矩阵、任务卡、ADR）已同步。
- [ ] PR 描述写明在哪些平台实际验证过；没验证的平台不要勾选。

## 10. 提交与 PR

- 提交信息格式：`<area>: <摘要>`，正文注明任务编号。例如 `win: ETW 会话管理与丢失计数 (P1-WIN-01)`。
- 一个 PR 对应一张任务卡，正文写 `Closes #<issue>`。
- PR 模板见 `.github/pull_request_template.md`，流程见 `docs/05-dev/github-workflow.md`。
