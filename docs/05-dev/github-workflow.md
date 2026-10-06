# GitHub 协作流程

> 状态：草案
> 最后更新：2026-10-06
> 关联：REQ-08、[任务卡规范](../04-plan/tasks/README.md)、[roadmap](../04-plan/roadmap.md)、[ci-release](ci-release.md)、[coding-conventions](coding-conventions.md)

原则：**文档是规格，GitHub 是执行**。需求与设计在 `docs/` 中定稿；任务卡同步为 Issue；状态只在 GitHub 上维护。

## 1. 标签体系

标签定义的唯一来源是 `scripts/labels.json`，用 `scripts/sync-labels.ps1` 同步。

| 前缀 | 取值 | 含义 |
|---|---|---|
| `area:` | core、pipe、store、proxy、daemon、cli、ui、agent、lnx、win、mac、poll、sim、ci、sec、doc | 对应 [docs/README §2](../README.md#2-编号规则) 的 AREA |
| `platform:` | linux、windows、macos、all | 涉及的平台 |
| `type:` | feature、bug、spike、chore、docs | 工作类型 |
| `phase:` | P0–P5 | 所属阶段 |
| `size:` | S（≤0.5d）、M（≤2d）、L（≤5d，须拆分） | 规模 |
| `priority:` | M、S、C | 必须 / 应该 / 可选 |
| 单独标签 | `evidence` | 影响证据等级、结论措辞或证据/推测区分，**评审时必须对照 evidence-model** |
| 单独标签 | `status:blocked` | 被外部条件阻塞（如 Apple 授权） |

新增标签：修改 `labels.json` → PR 合并 → 运行 `sync-labels.ps1`。不要在网页上手工创建。

## 2. Issue 表单

`.github/ISSUE_TEMPLATE/`：

| 文件 | 用途 | 关键字段 | 默认标签 |
|---|---|---|---|
| `feature.yml` | 需求 / 功能任务（未经任务卡的临时需求） | 关联 REQ、场景、验收标准、平台、是否影响证据 | `type:feature` |
| `bug.yml` | 缺陷 | 平台与版本、`aw doctor --json` 输出、复现步骤、期望/实际、是否可提供（已 scrub 的）fixture | `type:bug` |
| `platform-research.yml` | 平台能力调研 / spike | 问题、涉及 CAP、假设、方法、通过标准、时间盒；完成时链接 `docs/06-research/SPIKE-NN-*.md` | `type:spike` |
| `config.yml` | 关闭空白 Issue；引导安全问题走私下报告（Security Advisories） | — | — |

bug 表单在提交前提醒：不要粘贴未脱敏的日志、命令行或数据库文件。

## 3. Projects v2

项目名：**AgentWatch**（用户级，编号创建后记录在本节：`#__`）。

| 字段 | 类型 | 取值 | 来源 |
|---|---|---|---|
| Status | 单选 | Todo / In Progress / In Review / Done / Blocked | 手工 + 内置自动化（PR 合并 → Done） |
| Phase | 单选 | P0–P5 | 同步脚本按 `phase:*` 标签填写 |
| Platform | 单选 | linux / windows / macos / all | 同步脚本（多平台取 all） |
| Area | 单选 | AREA 列表 | 同步脚本 |
| Size | 单选 | S / M / L | 同步脚本 |
| Priority | 单选 | M / S / C | 同步脚本 |

推荐视图：
- **看板**：按 Status 分列，筛选当前 Phase。
- **平台**：表格按 Platform 分组，用于平台并行开发。
- **路线图**：Roadmap 视图，按 Milestone。

【待验证】`gh project item-edit` 设置单选字段需要字段 ID 与选项 ID，同步脚本在首次运行时查询并缓存；如果实现成本高，可先只用标签，字段由项目内置工作流或手工填写。

## 4. Milestone

Milestone 与阶段一一对应，名称必须与 [roadmap §1](../04-plan/roadmap.md#1-阶段总览) 和各任务文件头的 `里程碑` 字段完全一致：

| Milestone | 任务文件 |
|---|---|
| `P0 奠基` | `docs/04-plan/tasks/P0-foundation.md` |
| `P1 MVP` | `docs/04-plan/tasks/P1-mvp.md` |
| `P2 文件与 UI` | `docs/04-plan/tasks/P2-files-ui.md` |
| `P3 URL 与关联` | `docs/04-plan/tasks/P3-url-correlation.md` |
| `P4 原生化与打包` | `docs/04-plan/tasks/P4-native-packaging.md` |
| `P5 Agent 适配` | `docs/04-plan/tasks/P5-agent-adapters.md` |

截止日期由同步脚本从任务文件头的 `截止` 字段写入。阶段结束时关闭 Milestone，并在 roadmap §6 写复盘。

## 5. 分支与 PR

### 5.1 分支模型
- `main`：受保护，始终可构建。禁止直接推送与强推。
- 功能分支：`<任务编号小写>-<slug>`，如 `p1-win-03-etw-file-events`。无任务卡的修复用 `fix-<issue号>-<slug>`。
- 合并方式：**squash merge**，PR 标题即最终提交信息（Conventional Commits + 任务编号，见 [coding-conventions §8](coding-conventions.md#8-提交信息)）。

### 5.2 main 分支保护（ruleset）
- 必须通过的检查：`ci / test (ubuntu-latest)`、`ci / test (windows-latest)`、`ci / test (macos-latest)`、`ci / deny`、`ci / wording`；修改 `docs/` 时加 `docs-lint`。
- 要求 PR；单人开发时不强制 approve，但带 `evidence` 或 `area:sec` 标签的 PR 需在描述中完成自审清单。
- 要求分支与 main 保持最新；要求线性历史。

### 5.3 PR 流程
1. 从 Issue 创建分支（`gh issue develop <N> --name <分支名>`），Projects Status → In Progress。
2. 开 Draft PR，正文写 `Closes #N`。
3. 完成后按模板勾选、贴验收证据，转为 Ready → Status → In Review。
4. CI 全绿、自审 / 评审通过后 squash merge，Issue 自动关闭。

### 5.4 PR 模板勾选项（`.github/pull_request_template.md`）

- 关联任务卡编号 与 `Closes #N`
- [ ] 仅修改了任务卡“文件范围”内的文件（越界处已在下方说明）
- [ ] 已逐条对照验收标准，并附命令输出
- 已验证平台：[ ] Linux [ ] Windows [ ] macOS [ ] 仅无特权测试（平台无关）
- [ ] 影响证据等级或结论措辞：已对照 evidence-model，已有断言 evidence 与模板 ID 的测试
- [ ] 日志与落盘内容不含未脱敏数据
- [ ] 快照变更已人工审阅
- [ ] 新增依赖已说明理由与许可证
- [ ] 文档已同步（设计 / 能力矩阵 / 任务卡 / ADR），或无需修改
- [ ] 如有 AI 生成代码，已由人审阅

## 6. 任务卡与 Issue 同步

脚本位于 `scripts/`，需要 PowerShell 7（`pwsh`）和已登录的 gh CLI（`gh auth login`，若使用 Projects 需 `gh auth refresh -s project`）。

| 脚本 | 参数 | 作用 |
|---|---|---|
| `sync-labels.ps1` | `-Repo <owner/name>`（默认当前仓库）、`-DryRun` | 按 `labels.json` 创建 / 更新标签（不删除未列出的标签） |
| `sync-issues.ps1` | `-Phase <P0,P1,…>`、`-DryRun`、`-Repo`、`-ProjectOwner`、`-ProjectNumber` | 解析 `docs/04-plan/tasks/P*.md`，创建 / 更新 Milestone 与 Issue |

```powershell
pwsh scripts/sync-labels.ps1
pwsh scripts/sync-issues.ps1 -DryRun                     # 预览全部阶段
pwsh scripts/sync-issues.ps1 -Phase P0,P1                # 同步 P0、P1
pwsh scripts/sync-issues.ps1 -Phase P1 -ProjectOwner '@me' -ProjectNumber 3
```

同步规则（详见 [任务卡规范 §5](../04-plan/tasks/README.md#5-与-github-同步)）：
- 以标题前缀 `[Pn-AREA-NN]` 为幂等键；重复运行不产生重复 Issue。
- 只追加标签，不删除手工标签；已关闭的 Issue 不更新。
- 依赖中的任务编号替换为 `#N` 链接（被依赖 Issue 尚未创建时保留编号文本）。
- 阶段文件定稿（PR 合并）后再同步；不提前同步仍在变化的后续阶段。

## 7. 文档同步规则

| 变更 | 必须同步 |
|---|---|
| spike 完成 | spike 文档结果、能力矩阵验证状态、平台文档、去掉相关【待验证】、必要时 risks 与任务卡 |
| 事件字段 / 表结构变更 | event-schema / storage；主版本变更加 ADR |
| CLI / API 变更 | api-and-cli |
| 设计决策变更 | 先 ADR（提议 → 已接受），再改设计文档 |
| 新增 / 拆分任务 | 任务卡 + 任务总表 + 依赖图，合并后重新同步 |
| 新增 / 改名文档 | docs/README.md 目录 |

文档与代码在同一个 PR 中修改；`docs-lint` 会拦下坏链接和未定义的编号。

## 8. 初始化仓库（P0-CI-03）

以下命令由开发者手动执行（涉及远端创建与权限设置）：

```powershell
# 1. 创建私有仓库并推送
git init -b main
git add . ; git commit -m "docs: 初始方案与任务规划 [P0-DOC-01]"
gh repo create AgentWatch --private --source . --push

# 2. 仓库设置：只允许 squash、合并后删分支
gh repo edit --enable-squash-merge --enable-merge-commit=false --enable-rebase-merge=false --delete-branch-on-merge

# 3. 标签（删除默认标签为可选操作）
pwsh scripts/sync-labels.ps1

# 4. Projects v2
gh auth refresh -s project
gh project create --owner '@me' --title AgentWatch        # 记录返回的项目编号
gh project field-create <N> --owner '@me' --name Phase --data-type SINGLE_SELECT --single-select-options "P0,P1,P2,P3,P4,P5"
gh project field-create <N> --owner '@me' --name Platform --data-type SINGLE_SELECT --single-select-options "linux,windows,macos,all"
gh project field-create <N> --owner '@me' --name Area --data-type SINGLE_SELECT --single-select-options "CORE,PIPE,STORE,PROXY,DAEMON,CLI,UI,AGENT,LNX,WIN,MAC,POLL,SIM,CI,SEC,DOC"
gh project field-create <N> --owner '@me' --name Size --data-type SINGLE_SELECT --single-select-options "S,M,L"
gh project field-create <N> --owner '@me' --name Priority --data-type SINGLE_SELECT --single-select-options "M,S,C"
gh project link <N> --owner '@me' --repo <owner>/AgentWatch

# 5. Issue 与 Milestone
pwsh scripts/sync-issues.ps1 -DryRun
pwsh scripts/sync-issues.ps1 -Phase P0,P1 -ProjectOwner '@me' -ProjectNumber <N>

# 6. 分支保护：在网页 Settings → Rules → Rulesets 中按 §5.2 配置，
#    或用 gh api repos/<owner>/AgentWatch/rulesets 提交 JSON【待验证：私有仓库的 ruleset 是否需要付费计划】
```

Status 字段由 Projects 自带，需在网页中把选项改为 Todo / In Progress / In Review / Done / Blocked，并启用内置工作流“Item closed → Done”“Pull request merged → Done”。
