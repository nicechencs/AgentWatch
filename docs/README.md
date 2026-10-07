# AgentWatch 文档中心

> 本文件是所有文档的**索引和写作约定**。新增、改名、删除文档时必须同步更新本文件。

## 1. 文档目录

```
docs/
├── README.md                         ← 本文件：索引 + 约定
├── 00-overview/                      产品层：为什么做、做什么
│   ├── vision.md                     目标、非目标、用户场景
│   ├── requirements.md               需求清单（REQ / NFR 编号，验收口径）
│   └── glossary.md                   术语表
├── 01-architecture/                  设计层：怎么做（平台无关）
│   ├── architecture.md               总体架构、组件、进程模型、数据流
│   ├── evidence-model.md             证据等级、结论措辞、不可得标注
│   ├── event-schema.md               统一事件模型 RawEvent 与归一化记录
│   ├── process-tracking.md           进程身份、范围追踪（启动/附着）、子进程关联
│   ├── pipeline.md                   过滤、丰富、脱敏、聚合、关联、批量写入
│   ├── network-attribution.md        流量统计、DNS/SNI、显式代理与完整 URL
│   ├── storage.md                    SQLite 表结构、索引、保留与轮转、导出
│   ├── api-and-cli.md                daemon 本地 API、CLI 命令、查询/筛选语法
│   ├── ui.md                         Web UI 信息架构与页面
│   ├── security-privacy.md           威胁模型、敏感信息保护、自身安全
│   ├── performance-budget.md         资源预算、限流降级、度量方法
│   └── inter-agent-communication.md  Agent 间通信监控（AgentInstance、IPC 配对、MCP、委托链路）
├── 02-platforms/                     平台层：各 OS 能做什么、怎么做
│   ├── capability-matrix.md          能力矩阵（CAP 编号，权威来源）
│   ├── linux.md
│   ├── windows.md
│   ├── macos.md
│   └── fallback-poll.md              跨平台轮询兜底采集器
├── 03-adr/                           架构决策记录
│   ├── README.md                     ADR 索引与流程
│   ├── template.md
│   └── NNNN-*.md
├── 04-plan/                          计划层：何时做、谁做
│   ├── roadmap.md                    阶段、里程碑、退出标准
│   ├── tasks/                        每阶段一份任务清单（可直接转 GitHub Issue）
│   │   ├── README.md                 任务卡格式、状态流转、同步到 GitHub 的方法
│   │   ├── P0-foundation.md
│   │   ├── P1-mvp.md
│   │   ├── P2-files-ui.md
│   │   ├── P3-url-correlation.md
│   │   ├── P4-native-packaging.md
│   │   ├── P5-agent-adapters.md
│   │   └── P6-inter-agent.md
│   └── risks.md                      风险登记册（RISK 编号）
├── 05-dev/                           工程层：怎么协作开发
│   ├── repo-layout.md                仓库与 crate 结构、依赖方向
│   ├── dev-setup.md                  三平台开发环境、权限、加速编译
│   ├── coding-conventions.md         代码规范、错误处理、日志、AI 协作约定
│   ├── testing.md                    单测 / 回放 / 模拟器 / 端到端 / 性能测试
│   ├── ci-release.md                 CI 矩阵、签名、公证、发布
│   └── github-workflow.md            Issue/标签/Projects/Milestone/PR 流程
└── 06-research/                      调研与技术验证（spike）记录
    ├── README.md                     spike 索引
    ├── spike-template.md
    └── SPIKE-NN-*.md
```

仓库根目录另有：`README.md`（项目简介）、`AGENTS.md`（AI 协作规则，`CLAUDE.md` 引用它）、`.github/`（Issue/PR 模板、标签定义）。

### 阅读路径

| 角色 | 建议顺序 |
|---|---|
| 第一次了解项目 | vision → requirements → architecture → evidence-model → roadmap |
| 开发某平台采集器 | capability-matrix → 对应平台文档 → event-schema → 对应阶段任务卡 |
| 开发管道/存储/UI | event-schema → pipeline → storage → api-and-cli → ui |
| 开发 Agent 间通信 | inter-agent-communication → ADR-0013 → capability-matrix §10 → P6 任务卡 |
| AI Agent 接任务 | AGENTS.md → 任务卡 → 任务卡中“参考文档”列出的文件 |

## 2. 编号规则

| 前缀 | 含义 | 示例 | 定义位置 |
|---|---|---|---|
| `REQ-NN` | 功能需求 | REQ-04 | 00-overview/requirements.md |
| `NFR-NN` | 非功能需求 | NFR-02 | 00-overview/requirements.md |
| `CAP-XXX-NN` | 平台能力项 | CAP-NET-03 | 02-platforms/capability-matrix.md |
| `ADR-NNNN` | 架构决策 | ADR-0004 | 03-adr/ |
| `Pn-AREA-NN` | 开发任务 | P1-LNX-03 | 04-plan/tasks/ |
| `SPIKE-NN` | 技术验证 | SPIKE-03 | 06-research/ |
| `RISK-NN` | 风险 | RISK-01 | 04-plan/risks.md |
| `E1/E2/E3/S/I/NA` | 证据等级 | E1 | 01-architecture/evidence-model.md |

任务 `AREA` 取值（同时是 GitHub 标签 `area:*`）：

| AREA | 范围 | AREA | 范围 |
|---|---|---|---|
| CORE | aw-core 事件模型/公共类型 | LNX | Linux 采集器 + eBPF |
| PIPE | aw-pipeline 处理管道 | WIN | Windows 采集器 |
| STORE | aw-store 存储/保留/导出 | MAC | macOS 采集器 + 系统扩展 |
| PROXY | aw-proxy MITM 代理 | POLL | 轮询兜底采集器 |
| DAEMON | aw-daemon 服务/权限/API | SIM | 行为模拟器与测试夹具 |
| CLI | aw-cli | CI | 构建、CI、发布、签名 |
| UI | Web UI | SEC | 安全、脱敏、威胁模型 |
| AGENT | Agent 适配（E3 数据源） | DOC | 文档 |

编号一经分配**不复用**；废弃时标记“已废弃”并保留条目。

## 3. 写作约定

1. **语言**：文档用中文；代码标识符、命令、字段名保留英文原样，用反引号包裹。
2. **文档头**：每份文档开头使用如下元信息块：

   ```markdown
   # 标题

   > 状态：草案 | 评审中 | 已确认 | 已过时
   > 最后更新：YYYY-MM-DD
   > 关联：REQ-xx, ADR-xxxx, ...
   ```

3. **单一事实来源**：每类信息只在一处定义，其他地方链接过去，不复制。
   - 平台能力 → `capability-matrix.md`；证据等级 → `evidence-model.md`；
   - 字段定义 → `event-schema.md` / `storage.md`；任务 → `04-plan/tasks/`。
4. **未验证即标注**：基于经验、尚未在真机验证的结论，加 `【待验证】` 并指向对应 SPIKE。spike 完成后更新原文并去掉标注。
5. **链接**：用相对路径，如 `[证据模型](../01-architecture/evidence-model.md#2-证据等级)`。
6. **决策变更**：改变已确认的设计时，先新增/更新 ADR，再改设计文档。
7. **图**：优先用 Mermaid 或 ASCII，便于 diff 和 AI 读写。

## 4. 文档与 GitHub 的关系

- 文档是**规格**，GitHub Issue 是**执行**。任务卡在 `04-plan/tasks/` 中定稿后同步为 Issue，Issue 正文链接回任务卡。
- Issue 关闭时，若实现与文档不一致，PR 中必须同步修改文档。
- 详见 [github-workflow.md](05-dev/github-workflow.md)。

## 5. 文档状态总览

| 文档 | 状态 |
|---|---|
| 全部初版 | 草案（2026-10-06 创建，平台相关结论待 P0 spike 验证） |
