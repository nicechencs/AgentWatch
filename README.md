# AgentWatch

> 跨平台的 AI Agent 行为审计工具：看清一个 Agent 及其子进程访问了哪些文件、执行了什么命令、向哪里发送了多少数据——并且如实区分“观测到的事实”和“推测”。

**状态：开发中，可在本机运行**。仓库里已有可构建的 daemon（`agentwatchd`）、CLI（`aw`）和内嵌的 React Web UI，CI 在 Linux / Windows / macOS 上编译并跑测试。当前 daemon 只接了轮询采集（采样，证据等级 `S`）；ETW / eBPF / Endpoint Security 采集器的代码在仓库里，但还没有接进 daemon。平台相关结论中标注【待验证】的部分，以真机验证为准。

## 核心能力（计划）

| 能力 | 说明 |
|---|---|
| 三平台 | Windows（ETW）、Linux（eBPF，可降级）、macOS（Endpoint Security / eslogger） |
| 进程范围 | 从工具启动程序，或附着到正在运行的进程；自动追踪整棵子进程树 |
| 文件与命令 | 打开、读取、写入、创建、删除、重命名；执行的命令及参数 |
| 网络 | 按进程 / Agent 统计上传与下载字节；本地与目标端口、IP、域名；代理模式下的完整 URL |
| 分析 | 统一时间线、历史查询、筛选、JSONL / CSV 导出、文件与网络事件互相跳转 |
| 本地优先 | 只存本地、无遥测；不存文件与流量内容；凭证自动脱敏；磁盘与资源有上限 |

## 证据与推测分离

每条记录都带证据等级：`E1` 系统观测、`E2` 协议观测、`E3` Agent 自报告、`S` 采样、`I` 推测、`NA` 不可得（附原因）。

- “读取文件后联网”只会被描述为**时序相关的推测**，绝不写成“上传了文件”。
- 采集缺口（丢事件、权限不足）会在时间线上标出来。

详见 [证据模型](docs/01-architecture/evidence-model.md)。

## 本地运行（开发构建）

```bash
pnpm -C ui install --frozen-lockfile && pnpm -C ui build   # 产物在 ui/dist，编译时嵌进 daemon
cargo build --release -p aw-daemon -p aw-cli
./target/release/agentwatchd --foreground --config ./agentwatchd.toml
```

最小配置（只写到自己指定的目录，不碰系统目录）：

```toml
[storage]
data_dir = "/tmp/aw-dev/data"

[api]
http_port = 7456        # 浏览器 UI 的本机端口；0 关闭 HTTP

[debug]
preview_ui = true       # 仅本机预览：打开 http://127.0.0.1:<端口>/ 自动换票进入界面
```

日志在 `<data_dir>/agentwatchd.log`，每行以 UTC 时间（RFC 3339）开头。停止：在 `data_dir` 下创建 `agentwatchd.stop`。

## 用法（命令树；部分子命令仍在接入）

```bash
aw run -- claude                         # 启动并记录一个程序
aw attach --pid 4412                     # 附着到正在运行的进程
aw sessions list
aw timeline @last --filter 'kind:file path:~/.ssh/**'
aw flows @last --group-by domain         # 按域名统计上传/下载
aw export @last --format jsonl -o session.jsonl
aw ui                                    # 打开本地 Web UI
aw doctor                                # 自检权限与平台能力
```

完整命令见 [api-and-cli](docs/01-architecture/api-and-cli.md)。

## 文档入口

| 想了解 | 文档 |
|---|---|
| 文档总索引与写作约定 | [docs/README.md](docs/README.md) |
| 为什么做、需求 | [vision](docs/00-overview/vision.md)、[requirements](docs/00-overview/requirements.md) |
| 总体架构 | [architecture](docs/01-architecture/architecture.md) |
| 各平台能做到什么 | [capability-matrix](docs/02-platforms/capability-matrix.md) |
| 关键决策 | [ADR 索引](docs/03-adr/README.md) |
| 路线图与任务 | [roadmap](docs/04-plan/roadmap.md)、[tasks](docs/04-plan/tasks/README.md) |
| 如何参与开发 | [AGENTS.md](AGENTS.md)、[docs/05-dev](docs/05-dev/) |
| 技术验证 | [06-research](docs/06-research/README.md) |

## 技术栈（计划）

Rust workspace（tokio / axum / rusqlite / Aya / ferrisetw / endpoint-sec / hudsucker）+ React/Vite 内嵌 Web UI + SQLite。macOS 网络扩展用 Swift。理由见 [ADR-0001](docs/03-adr/0001-rust-workspace.md)。

## 任务同步到 GitHub

```powershell
pwsh scripts/sync-labels.ps1 -DryRun     # 预览标签
pwsh scripts/sync-issues.ps1 -DryRun     # 预览 Milestone 与 Issue
pwsh scripts/sync-issues.ps1 -Phase P0   # 同步 P0
```
