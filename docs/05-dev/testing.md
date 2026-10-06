# 测试策略

> 状态：草案
> 最后更新：2026-10-06
> 关联：REQ-02~06、NFR-01~08、[evidence-model §8](../01-architecture/evidence-model.md#8-测试要求)、[performance-budget](../01-architecture/performance-budget.md)、[security-privacy §3.3](../01-architecture/security-privacy.md#33-测试)、[repo-layout §5](repo-layout.md#5-fixtures-目录)

## 1. 测试分层

```text
             ┌──────────┐
             │ 人工验收 │  真实 Agent 会话（每阶段末）
            ┌┴──────────┴┐
            │ 性能基准   │  criterion + sim 压力剧本（每夜）
           ┌┴────────────┴┐
           │ 特权端到端   │  真实采集器 + sim 剧本（Linux/Windows 托管 runner；macOS 手动）
          ┌┴──────────────┴┐
          │ fixtures 回放   │  录制事件流 → 管道 → 存储（无特权，三平台）
         ┌┴────────────────┴┐
         │ 单元 / 属性测试   │  各 crate（无特权，三平台）
         └──────────────────┘
```

原则：
- **业务逻辑尽量在底下两层覆盖**。特权端到端只验证“采集器实际产生了预期事件”和“量化指标达标”。
- 采集器每修复一个真机 bug，就补一个录制的 fixture，使问题以后可以在无特权环境复现。
- 任何影响证据等级或结论措辞的改动（`evidence` 标签）必须有断言 `evidence` 和模板 ID 的测试。

## 2. 单元测试

- 运行：`cargo nextest run --workspace`（或 `cargo test --workspace`）。
- 常用工具：
  - `insta`：JSON / 表格输出快照（事件序列化、CLI 输出、导出格式）。
  - `proptest`：序列化往返、脱敏（随机 token 嵌入任意文本）、聚合不变量（聚合前后字节总和相等）。
  - 内存 SQLite（`:memory:`）或临时目录中的数据库。
- 采集器翻译层：以保存的原始输入（ETW 属性表、eslogger JSON 行、eBPF 事件结构的字节）为输入，断言输出的 `RawEvent`。样例放在各 collector crate 的 `tests/data/`。
- 代码覆盖率（`cargo llvm-cov`）只作参考：平台无关 crate 目标 ≥ 80%，不作为合并门禁。

## 3. fixtures 回放测试

### 3.1 目的
把真机录制或手写的 `RawEvent` 流回放进管道和存储，在无特权、跨平台的环境下验证聚合、归属、脱敏、关联与缺口处理。这是迭代最快的一层，也是 AI 开发管道逻辑时的主要反馈来源。

### 3.2 文件格式
目录结构见 [repo-layout §5](repo-layout.md#5-fixtures-目录)。`events.jsonl` 首行是 header：

```json
{"fixture_header":true,"v":1,"platform":"linux","os_version":"Ubuntu 24.04 / 6.8","collectors":["linux.ebpf"],"recorded_at":"2026-10-20T08:00:00Z","scenario":"read_then_send"}
```

之后每行一个 `RawEvent`（字段见 [event-schema](../01-architecture/event-schema.md)）。回放时以 `ts_mono_ns` 为时间轴，不按真实时间等待。

### 3.3 工具

| 命令 | 作用 |
|---|---|
| `aw fixtures record <SESSION> -o <file>` | 从会话导出原始事件（需要录制时开启 `debug.keep_raw_events` 或使用 `aw run --raw <file>`） |
| `aw fixtures scrub <file>` | 替换用户名、主机名、内网 IP、token 为稳定占位符（如 `/home/u`、`10.0.0.5`），**提交前必须执行** |
| `aw fixtures replay <file> [--expect <snap>]` | 离线跑管道，输出记录与 findings；带 `--expect` 时与快照对比 |
| `aw fixtures upgrade <file>` | 把旧 schema 的 fixture 升级到当前版本 |

### 3.4 在测试中使用

```rust
#[test]
fn read_ssh_key_then_https() {
    let out = aw_pipeline::testing::replay("fixtures/common/read-ssh-key-then-https/events.jsonl");
    insta::assert_yaml_snapshot!(out.records_and_findings());
    assert!(out.findings().iter().all(|f| f.evidence == Evidence::I));
    assert!(out.findings().iter().all(|f| wording::lint(&f.text_zh).is_empty()));
}
```

- 快照文件 `expected.snap` 与 fixture 放在一起（通过 insta 的 `snapshot_path` 设置）。输出中的自增 ID 与时间戳在快照前归一化。
- 可选的 `expected.toml` 写关键断言（记录数、证据等级、模板 ID、缺口数），用于快照常变的用例。
- 快照变更必须在 PR 中由人审阅（`cargo insta review`）；AI 不得一律 `cargo insta accept`。

### 3.5 必备用例（持续补充）

| 用例 | 覆盖 |
|---|---|
| `three-level-spawn` | 进程树、ProcUid、PID 复用 |
| `pid-reuse` | 同 PID 不同启动时间不串号 |
| `read-ssh-key-then-https` | 敏感路径、时序关联（I）、措辞 |
| `proxy-content-match` | 内容哈希匹配升级路径 |
| `macos-open-without-bytes` | 字段级 NA |
| `etw-lost-events` | Gap 生成与时间线展示 |
| `daemon-delegation` | 归属中断标注 |
| `secrets-in-argv` | 命令行脱敏 |

## 4. 行为模拟器

### 4.1 作用
`sim` 按剧本产生**已知的真实行为**，并写出独立的真值日志（ground truth）。将 AgentWatch 的采集结果与真值对比，得到召回率与字节误差。这是各阶段验收的核心，也是“如实”的量化依据。`sim` 不依赖任何 `aw-*` crate。

### 4.2 剧本格式（TOML）

```toml
name = "smoke"
description = "三层派生 + 文件读写 + 已知字节上传"

[setup]
# 在临时目录 $SIM_ROOT 下创建诱饵文件；敏感路径用同名结构模拟
files = [
  { path = "home/.ssh/id_rsa", size = 412, content = "random" },
  { path = "work/data.bin", size = 1_048_576, content = "random" },
]
server = { http = true, https = true }      # 启动 sim serve

[[step]]
action = "spawn"                # 派生子进程，子进程执行嵌套的 steps
id = "child"
steps = [
  { action = "spawn", id = "grandchild", steps = [
      { action = "read_file", path = "home/.ssh/id_rsa" },
      { action = "http_upload", url = "https://127.0.0.1:{https_port}/upload", bytes = 5_120 },
  ]},
]

[[step]]
action = "write_file"
path = "work/out.txt"
bytes = 4096

[[step]]
action = "rename"
from = "work/out.txt"
to = "work/out2.txt"

[[step]]
action = "delete"
path = "work/out2.txt"

[[step]]
action = "dns_lookup"
name = "sim.agentwatch.test"

[[step]]
action = "sleep"
ms = 200

[[step]]
action = "http_download"
url = "http://127.0.0.1:{http_port}/download?bytes=1048576"
```

支持的 `action`：`spawn`、`exec`（执行外部命令，如 `git --version`）、`read_file`（可选 `mode = "read" | "mmap"`）、`write_file`、`create`、`delete`、`rename`、`http_upload`、`http_download`、`dns_lookup`、`udp_send`、`sleep`、`repeat`（`times` + 嵌套 steps，用于压力剧本）、`daemonize`（双 fork 脱离父进程，验证范围追踪）。

### 4.3 真值日志

每个动作完成后写一行 JSON：

```json
{"t_wall_ns":1791273662000300000,"pid":5120,"ppid":5101,"action":"read_file","path":"/tmp/sim-x/home/.ssh/id_rsa","bytes":412,"ok":true}
{"t_wall_ns":1791273662100000000,"pid":5120,"action":"http_upload","local":"127.0.0.1:51544","remote":"127.0.0.1:8443","app_bytes":5120,"ok":true}
```

`sim serve` 也写服务端真值（应用层字节与含 TLS 的字节），用于校准流量口径。

### 4.4 内置剧本

| 剧本 | 内容 | 用途 |
|---|---|---|
| `smoke` | 上例；覆盖每种 action 一次 | P0/P1 烟雾测试 |
| `basic_proc_net` | 派生 3 层子进程、DNS 查询、向本地测试服务器上传/下载已知字节；不含文件动作 | P1 退出标准（进程/网络召回率、字节误差） |
| `fake_agent` | 模拟 Agent 进程形态并触发 hooks 自报告（含故意少报的一次操作） | P5 适配器与 E3/E1 对照 |
| `file_ops` | 诱饵文件的 open/read/write/rename/delete/create 各若干次，含敏感路径 | P2 退出标准（文件召回率） |
| `typical_agent` | 每秒约 200 次 open、20 次 exec、10 个连接，持续 10 分钟（可配置）；模拟读代码、跑 git/npm、调用 API | 资源预算（NFR-01~03）、召回率 |
| `storm` | 每秒 5 万次 open（模拟编译），大量短命进程 | 降级阶梯、丢失计数与 Gap |
| `read_then_send` | 读诱饵文件后上传：三个变体——上传文件原文、上传无关数据、未启用代理 | 内容匹配、哈希未匹配、未启用代理三种结论（evidence-model §8） |
| `escape` | `daemonize`、通过已有守护进程执行【待定：可用的无特权委托方式】 | 范围追踪与归属中断 |

辅助剧本（不作为阶段退出标准）：`secrets`（在命令行、URL、环境变量中放入假凭证，用于脱敏验证）、`proxy_clients`（用 Node / Python / Go / curl / git 客户端访问本地 HTTPS 服务器，用于代理覆盖矩阵）。剧本文件位于 `sim/scenarios/<name>.toml`。

### 4.4.1 sim 命令

| 命令 | 作用 |
|---|---|
| `sim run <scenario.toml> --truth <file>` | 执行剧本，写出真值日志 |
| `sim eval --truth <file> --session <SESSION> [--thresholds <toml>]` | 把采集结果与真值比对，输出召回率和字节误差，不达标时退出码非 0（xtask 别名 `sim-eval`） |
| `sim compare <a> <b> [--kinds proc,net,file,http,findings]` | 比较两次采集或两个平台的结果，用于回归和跨平台差异报告 |
| `sim scan-secrets --db <file> --corpus <secrets.toml>` | 扫描数据库和导出文件，确认剧本中放入的假凭证一个都没有落盘 |
| `sim gen-db --events <N> -o <file>` | 生成指定规模的合成数据库，用于查询性能基准（如 100 万条事件、筛选 <300 ms） |

### 4.5 指标计算

对比工具：`cargo xtask sim-eval --truth truth.jsonl --session <SESSION>`（从数据库或导出的 JSONL 读取采集结果）。

- **匹配规则**：真值动作与采集记录在以下条件全部满足时视为命中：PID 相同；类型对应（`read_file` ↔ `file_access` 且 `ops` 含 read；`http_upload` ↔ `net_flows` 且本地端口相同）；路径或五元组相同；时间差 ≤ 2 s。
- **召回率**（按类别分别计算：proc / file / net / dns）：

  ```text
  recall(c) = |命中的真值动作(c)| / |真值动作(c)|
  ```

  平台能力为 NA 的动作（如 macOS 读取字节数）不计入分母，但单独统计“NA 标注正确率”：对应字段必须为 `None` 且 `field_evidence` 为 NA。
- **字节误差**（按连接与按会话合计两个口径）：

  ```text
  err = |采集字节 − 真值字节| / 真值字节
  ```

  真值字节按 [network-attribution §2](../01-architecture/network-attribution.md) 的口径选取：socket 层载荷用服务端“含 TLS”字节；代理模式的 HTTP body 用客户端 `app_bytes`。
- **误报**：采集到但不属于剧本进程树的记录数（验证范围过滤）。
- **通过门槛**（E1 平台）：各类 recall ≥ 95%；会话合计字节误差 < 5%；范围外误报 = 0。S 级（轮询）平台只报告不设门槛。

### 4.6 报告格式

`sim-eval` 输出 Markdown（贴进 PR）与 JSON（CI 归档）：

```text
scenario: smoke   platform: linux 6.8   collectors: linux.ebpf
| 类别 | 真值 | 命中 | recall | NA 正确 |
| proc |    3 |    3 | 100.0% |   —    |
| file |    5 |    5 | 100.0% |   —    |
| net  |    2 |    2 | 100.0% |   —    |
| dns  |    1 |    1 | 100.0% |   —    |
bytes: session err 0.8%   max per-flow err 2.1%
out-of-scope records: 0   gaps: 0
RESULT: PASS
```

## 5. 特权端到端测试

- 位置：`crates/aw-daemon/tests/e2e/`，用 `#[ignore]` 标记，只在 `cargo xtask e2e` 中以特权运行。
- 流程：启动 daemon（临时数据目录）→ `aw run -- sim run <scenario> --truth truth.jsonl` → 等待会话结束 → `sim-eval` → 断言门槛。
- 各平台：

| 平台 | 环境 | 说明 |
|---|---|---|
| Linux | GitHub 托管 `ubuntu-latest`（sudo 可用） | 另加一个最低内核的 VM 用例【待定：用 LVH / QEMU 镜像】 |
| Windows | GitHub 托管 `windows-latest`（runner 以管理员运行【待验证】） | — |
| macOS | 自托管 runner 或开发者手动运行 `cargo xtask e2e` | 托管 runner 无法授予完全磁盘访问 |

- e2e 失败时上传：daemon 日志、真值日志、导出的会话 JSONL（已脱敏）。

## 6. 性能基准

- **微基准**：`cargo bench -p aw-pipeline`、`cargo bench -p aw-store`（criterion），输入 `fixtures/bench/*.jsonl.zst`。指标：管道吞吐（条/秒）、批写吞吐（行/秒）、常用查询耗时。
- **端到端性能**：`cargo xtask bench-e2e --scenario typical_agent|storm`，各跑 3 次取中位数，指标与预算见 [performance-budget](../01-architecture/performance-budget.md)。同时跑一遍不开监控的剧本，得到“被监控进程减速”。
- 自身指标：`aw doctor --perf` 与 `/api/v1/health?metrics=1`。
- CI：每夜在 Linux、Windows 托管 runner 上运行；与 main 最近 7 次结果对比，回退 > 15% 时在 PR / Issue 中提示，不阻塞合并。

## 7. 脱敏与措辞测试

- **脱敏语料**：`crates/aw-pipeline/tests/redact_corpus/`（可与 `fixtures/redact_corpus/` 共享）。每条规则至少 3 个正例（必须被替换）与 3 个反例（不应被替换）。格式：

  ```text
  redact_corpus/
  ├── argv/positive.txt      每行：原文<TAB>期望输出
  ├── argv/negative.txt      每行：原文（期望不变）
  ├── url/...  env/...  header/...
  ```

- **属性测试**：随机生成 token 嵌入任意文本，断言输出中不含原 token。
- **落盘检查**：e2e 结束后在数据库文件和日志中 grep 剧本里植入的金丝雀 token（如 `AWCANARY-<uuid>`），必须为 0 命中。
- **措辞**：`cargo xtask wording-lint` 对以下内容运行 `wording::lint`：所有模板的渲染结果、`ui/src/i18n/` 资源、CLI 快照输出。每条关联规则至少一个回放 fixture，断言 `evidence`、模板 ID 与无禁用词。

## 8. 迁移测试

- 每次新增迁移（`crates/aw-store/migrations/`）时，用上一版本生成样例库 `fixtures/db/v<N>.db`（从一个小 fixture 回放得到）。
- 测试从每个历史版本升级到最新版本，断言：迁移成功、行数不变、关键查询结果与直接在新版本回放一致。
- `aw db migrate --dry-run` 对样例库输出与快照一致。
- fixture 的 schema 升级用 `aw fixtures upgrade`，也有对应测试。

## 9. 各层在 CI 中的运行位置

| 层 | 工作流 | 平台 | 触发 | 是否阻塞合并 |
|---|---|---|---|---|
| 单元 + 回放 + 迁移 + 脱敏 | `ci.yml` | 三平台 | PR、push main | 是 |
| 措辞 lint | `ci.yml` | Linux | PR | 是 |
| UI 测试（vitest） | `ci.yml` | Linux | PR（ui/ 变更） | 是 |
| 特权 e2e | `e2e-linux.yml`、`e2e-windows.yml` | Linux / Windows | PR（采集器或 daemon 变更）、每夜 | 是（路径匹配时） |
| 特权 e2e（macOS） | `e2e-macos.yml` | 自托管 / 手动 | `workflow_dispatch` | 否（PR 中需勾选“已在 macOS 手动验证”） |
| 性能基准 | `bench.yml` | Linux / Windows | 每夜、手动 | 否 |
| 文档链接与编号 | `docs-lint.yml` | Linux | PR（docs/ 变更） | 是 |

工作流详情见 [ci-release](ci-release.md)。
