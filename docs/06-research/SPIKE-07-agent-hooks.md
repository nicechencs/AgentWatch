# SPIKE-07 Agent 自报告（E3）接入方式

> 状态：部分完成
> 最后更新：2026-10-07
> 关联：REQ-09、ADR-0004、crate `aw-agent-adapters`、任务 P0-AGENT-01
> 时间盒：2 人天
> 负责人：

本次只做文档调研，没有在本机启动任何 Agent，也没有录制 hook stdin。通过标准第 1 条（工具调用结构化覆盖率）和第 2 条（与 exec 事件对齐）都没有实测。接口变化很快；下面每节都写明查阅日期（2026-10-07）和页面自己的版本或日期。页面没有版本号时明确写“页面无版本”。

E3 只能解释意图，不能当作发生过的证据，也不能升级为 E1。与系统事件对上的结果仍是 I。

## 1. 问题

主流 Agent 提供哪些稳定、可以在本地接入的自报告渠道？能否把“工具调用”（读文件、执行命令、网络请求）映射为 `AgentToolCall` 事件，并与 E1 的系统事件对齐？

| Agent | 候选渠道（待确认） | 要确认的问题 |
|---|---|---|
| Claude Code | hooks（`PreToolUse`/`PostToolUse`、`UserPromptSubmit`、`SessionStart`/`SessionEnd` 等，配置在 `settings.json`）、OpenTelemetry 导出（`CLAUDE_CODE_ENABLE_TELEMETRY` + OTLP 端点）、本地会话记录（`~/.claude/projects/**.jsonl`） | hook 的 stdin JSON 结构；能否在启动模式下临时注入 hook，而不改用户的配置文件；OTEL 事件是否包含工具参数 |
| Codex CLI | 本地会话记录（`~/.codex/sessions`）、OTEL 配置、`notify` 脚本 | 哪些渠道稳定；是否记录沙箱内执行的命令 |
| Cursor | hooks（若已提供）、本地日志 | 是否有公开的 hooks 机制；Cursor Agent 的终端命令由哪个进程执行，以便归属 |
| Gemini CLI / Aider | 日志、遥测 | 优先级低 |
| MCP 服务器 | 作为子进程出现在进程树里（E1） | 能否从启动命令识别出 MCP 服务器名 |

## 2. 假设

- Claude Code 的 hooks 可以按工具调用粒度拿到工具名和参数，可以通过一个小的 `aw hook` 子命令转发给 daemon。
- 对齐策略：用时间窗口加进程树将 E3 的工具调用与随后的 E1 事件（如 exec、open）对齐；对齐结果标 I。

文档已支持第一条：`PreToolUse` / `PostToolUse` 的 stdin 含 `tool_name` 与 `tool_input`。第二条未测，仍是假设。

## 3. 方法

- 环境：无本机实测。查阅日期 2026-10-07。只读官方文档页；搜索摘要不当作事实。
- 步骤：按任务卡覆盖 Claude Code、Codex CLI、Cursor、Gemini CLI、Aider，加一条 MCP 子进程识别。记下 URL、页面版本或日期、字段映射和未知项。
- 代码位置：未写。任务卡限制为仅调研文档。`spikes/SPIKE-07/` 仍未建立。

## 4. 通过标准

| 指标 | 通过 | 本次 |
|---|---|---|
| Claude Code 的工具调用 | 能以结构化方式拿到 ≥90%，不改用户的全局配置；或者改动可以自动还原 | 未测。文档上有不改用户文件的注入路径（见 §5.1），覆盖率未知 |
| 对齐 | 模拟会话中 ≥80% 的 Bash 工具调用能对应到 exec 事件 | 未测 |

P0-AGENT-01 的验收是文档覆盖：≥4 个 Agent，每个有接入方式和识别特征。该条已满足（Claude Code、Codex CLI、Cursor、Gemini CLI、Aider）。上表两条实测标准未满足，所以状态是部分完成。

## 5. 结果

### 5.1 Claude Code

查阅日期 2026-10-07。页面没有单一文档版本号；正文按功能标注 CLI 版本（本次读到的注释从 v2.1.152 到 v2.1.290）。当前安装的 `claude -v` 未记录。

| 页面 | URL | 页面版本 / 日期 |
|---|---|---|
| Hooks | <https://code.claude.com/docs/en/hooks> | 无文档日期；正文有 CLI 版本注释 |
| Monitoring | <https://code.claude.com/docs/en/monitoring-usage> | 无文档日期；例如 v2.1.214 / v2.1.268 / v2.1.274 |
| Sessions | <https://code.claude.com/docs/en/sessions> | 无文档日期 |
| CLI reference | <https://code.claude.com/docs/en/cli-reference> | 无文档日期 |
| Settings | <https://code.claude.com/docs/en/settings> | 无文档日期 |
| Environment variables | <https://code.claude.com/docs/en/env-vars> | 无文档日期 |
| MCP | <https://code.claude.com/docs/en/mcp> | 无文档日期 |

**接入方式（优先顺序）**

1. **启动注入的 command hook（推荐）。** `--settings` 接受 JSON 文件路径或内联 JSON 字符串，只对本次会话生效；省略的键保留文件里的值。文件必须是普通文件且 ≤2 MiB。优先级：管理策略 > 命令行 `--settings` > 项目本地 `.claude/settings.local.json` > 共享项目 `.claude/settings.json` > 用户 `~/.claude/settings.json`。同一键在更高层覆盖更低层。hooks 文档另外写明：用户 / 项目 / 本地是**加入** hook，不能拿掉管理策略里的 hook。两条放在一起读：`--settings` 里的 `hooks` 是整键覆盖更低层的 `hooks`，还是和文件里的 hook 数组拼接，页面没有写死。【待验证】。能确定的是：一次启动可以不改 `~/.claude/settings.json`，例如：

   ```text
   claude --settings <临时 JSON 文件>
   ```

   临时文件里只放 `hooks.PreToolUse` 与 `hooks.PostToolUse`，`type` 为 `command`，命令指向 `aw hook`。若实测发现 `--settings` 替换了整个 `hooks` 键，用户自己的 hook 就不会在这次会话里跑；这只影响该次启动，不写用户文件。`--plugin-dir` 也只对本次会话加载一个带 `hooks/hooks.json` 的插件，同样不写用户设置。`CLAUDE_CONFIG_DIR` 能把整棵配置树（设置、会话历史、插件）换到另一个目录，但那是另一套配置，不是叠加；不建议用它做审计注入。

   限制：`--bare` / `CLAUDE_CODE_SIMPLE=1` 会跳过 hook 自动发现；`--safe-mode` 不加载自定义 hook（管理策略里的 hook 仍生效）。云端会话不读本机 `~/.claude/settings.json`。命令或 HTTP hook 超时、脚本缺失、非 2 的退出码，对 `PreToolUse` 是放行：工具继续走普通权限流程。退出码 2 才拦截。审计 hook 必须立刻以 0 退出且不要输出决策 JSON，否则会改变 Agent 的行为。

2. **OpenTelemetry。** `CLAUDE_CODE_ENABLE_TELEMETRY=1` 之后才采集。日志导出器 `OTEL_LOGS_EXPORTER` 可为 `otlp`、`console` 或 `none`；端点用 `OTEL_EXPORTER_OTLP_ENDPOINT`。这些变量只在 shell、用户设置或管理策略里生效，项目和本地 settings 里的值被忽略（文档写明的少数“关闭”值除外）。启动模式可以只在子进程环境里设置，不改用户文件。

3. **本地会话 JSONL（兜底，格式不稳定）。** 默认路径 `~/.claude/projects/<project>/<session-id>.jsonl`。`<project>` 是工作目录路径把非字母数字换成 `-`；超过 200 字符时截断并附上全路径的哈希。每行是一条消息、工具调用或元数据。文档明确写这是内部格式，版本之间会变，直接解析的脚本可能在任何一次发布里失效。`CLAUDE_CODE_SKIP_PROMPT_HISTORY=1` 或 `claude -p --no-session-persistence` 会不写这些文件。保留期默认 30 天（`cleanupPeriodDays`）。

**Hook stdin（文档示例里的字段名）**

共有：`session_id`、`prompt_id`、`transcript_path`、`cwd`、`scratchpad_dir`、`permission_mode`、`effort`、`hook_event_name`。子代理里还有 `agent_id`、`agent_type`。

`PreToolUse` 还有 `tool_name`、`tool_input`（对象，里面是工具参数；Bash 示例含 `command`）、`tool_use_id`。

`PostToolUse` 还有 `tool_response`、可选 `duration_ms`；MCP 工具还有 `mcp_server`（文档写 v2.1.274+）。`PostToolUseFailure` 用 `error`、`is_interrupt`，没有 `tool_response`。权限被拒或校验失败的调用不产生 `PostToolUseFailure`；权限拒绝仍会先有 `PreToolUse`。`EndConversation` 不跑 `PreToolUse` / `PostToolUse`。用 `@` 引入文件不产生 Read 工具调用，因此也没有对应 hook。

**OTEL 是否含工具参数**

默认**不含**。工具结束事件 `claude_code.tool_result` 的常驻字段是 `tool_name`、`tool_use_id`、`success`、`duration_ms`、`error_type`、`decision_type`、`decision_source`、`tool_input_size_bytes`、`tool_result_size_bytes`，以及 MCP 的 `mcp_server_scope`。被拒绝的调用不发这条。`claude_code.tool_decision` 记录 accept/reject 和决策来源，同样默认没有参数。

只有 `OTEL_LOG_TOOL_DETAILS=1` 才附加 `tool_parameters`（JSON 字符串）和 `tool_input`（序列化参数；单值超 512 字符截断，载荷约 4K 字符）。Bash 的 `tool_parameters` 含 `bash_command`、`full_command`。`OTEL_LOG_TOOL_CONTENT=1` 才在追踪的 `tool.output` span 事件里放工具内容，还要开 tracing beta（`CLAUDE_CODE_ENHANCED_TELEMETRY_BETA=1`）。提示词默认是 `<REDACTED>`，要 `OTEL_LOG_USER_PROMPTS=1` 才会出现原文。审计侧不应打开后两个内容开关；即使用户打开了，`summary` 也只能留结构化字段并脱敏，不保存提示词、模型输出或文件内容。

**进程身份（文档写明的部分）**

| 特征 | 文档 |
|---|---|
| 命令名 | `claude`。实际是原生二进制还是脚本包装，【待验证】 |
| 子进程环境 | 它拉起的 Bash / PowerShell / hook / stdio MCP 子进程里有 `CLAUDECODE=1`。`CLAUDE_CODE_CHILD_SESSION=1` 在 Bash、PowerShell、Monitor、hook、状态行子进程里（v2.1.172+），**不**设给 stdio MCP。`CLAUDE_CODE_SESSION_ID` 与 hook JSON 的 `session_id` 一致。`CLAUDE_PID` 是 Claude Code 自身 pid（v2.1.214+） |
| 父进程 | hook 命令的父进程是这个 Claude Code 进程。工具壳用 `CLAUDE_CODE_SHELL` 指定的 bash/zsh，否则按 `$SHELL` 再退回 zsh 再 bash。Windows 上可以走原生 PowerShell 工具（`CLAUDE_CODE_USE_POWERSHELL_TOOL`） |
| argv | 【待验证】。文档没有给出可用于识别的典型 argv。不要把未录制的路径写成已知事实 |

**映射到 `AgentToolCall`**

| 字段 | 来源 |
|---|---|
| `agent` | 固定 `"claude-code"` |
| `agent_session` | hook 的 `session_id`；OTEL 用资源属性里的 session id（默认会带，`OTEL_METRICS_INCLUDE_SESSION_ID=false` 可以去掉） |
| `tool` | `tool_name` / OTEL `tool_name`。缺失则 NA(`protocol_not_observed`) 不适用于本事件；拿不到就不要造一条工具调用 |
| `phase` | `PreToolUse` → `pre`；`PostToolUse` / `PostToolUseFailure` → `post`。OTEL 的 `tool_result` 只有事后，`phase = post`；`tool_decision` 是权限决策，不是工具执行，建议放进 `summary.decision`，不要当成第二条 exec |
| `call_id` | `tool_use_id`（hook 与 OTEL 文档写明两者一致） |
| `summary` | 从 `tool_input` 抽结构：Bash/PowerShell 的 `command`（截断、脱敏）、文件工具的路径、WebFetch 的 URL。不要放 `content`、`tool_response` 正文、提示词。失败时只记 `is_error: true` 和退出码，不要把 `error` 字符串原样入库（里面可能有命令输出） |

来源字段：`agent.claude-code/hook`、`agent.claude-code/otel`、`agent.claude-code/transcript`。证据等级固定 E3。

### 5.2 Codex CLI

查阅日期 2026-10-07。以下是本地 Codex 客户端（CLI / 桌面 / IDE 扩展）的配置文档，不是 OpenAI Agents API。原 `developers.openai.com/codex/config-advanced` 于本次查阅时 308 到下表地址。页面没有文档版本号；高级配置页只提到 Codex 0.134.0 的一处 profile 文件变更。hooks 页写明要以该页为发布参考，因为 `main` 上的 schema 可能还没进当前发布。

| 页面 | URL | 页面版本 / 日期 |
|---|---|---|
| Advanced config | <https://learn.chatgpt.com/docs/config-file/config-advanced> | 无；正文提到 Codex 0.134.0 |
| Config reference | <https://learn.chatgpt.com/docs/config-file/config-reference> | 无 |
| Hooks | <https://learn.chatgpt.com/docs/hooks> | 无 |
| Troubleshooting | <https://learn.chatgpt.com/docs/reference/troubleshooting> | 无 |

**哪些渠道稳定**

文档没有把任何一条标成“稳定 API”。按页面自己的用语：

| 渠道 | 文档怎么说 | 对审计是否够用 |
|---|---|---|
| `hooks.json` / `[hooks]` | 作为发布参考页。事件含 `PreToolUse`、`PostToolUse`、`PermissionRequest`、`SessionStart`、`SessionEnd`、`Stop` 等。非管理 hook 必须先被用户审阅并信任，信任绑定当前内容哈希；改了就跳过，直到再次信任。项目级 `.codex/` 还要该层本身受信任 | 字段够用，但“不改用户配置就注入”文档没有写。`--dangerously-bypass-hook-trust` 只跳过信任提示，不注入新 hook。【待验证】是否有临时配置路径 |
| `notify` | 命令数组。文档只列出 `agent-turn-complete`。JSON 参数含 `type`、`thread-id`、`turn-id`、`cwd`、`input-messages`、`last-assistant-message` | 不能映射单次工具调用。项目级配置不能设置它 |
| `[otel]` | 默认关。项目级配置不能设置，必须写在用户配置。事件名：`codex.conversation_starts`、`codex.api_request`、`codex.sse_event`、`codex.websocket_request`、`codex.websocket_event`、`codex.user_prompt`、`codex.tool_decision`、`codex.tool_result`。指标里的 `tool` 只是内部工具名（文档举例 `apply_patch`、`shell`），**不含实际 shell 命令或补丁**。`codex.tool_result` 是时长、成败和一段输出摘要。`log_user_prompt` 默认 false，提示词保持脱敏，`codex.user_prompt` 记长度 | 默认拿不到命令文本。摘要可能带内容，入库前必须丢掉正文 |
| 会话文件 | 排查页：`$CODEX_HOME/sessions`（默认 `~/.codex/sessions`），归档在 `$CODEX_HOME/archived_sessions`。`history.persistence` 为 `save-all` 或 `none`；`none` 停止写入。另有 `history.jsonl`，`history.max_bytes` 限制大小。`log_dir` 默认 `$CODEX_HOME/log`，设了才写明文 `codex-tui.log` | 排查页没有给出 sessions 目录里的文件格式。【待验证】是否为 JSONL、是否含工具参数。不要把社区文章里的 schema 写进产品 |

**沙箱内命令**

配置有 `sandbox_mode`：`read-only`、`workspace-write`、`danger-full-access`。hooks 页写明 shell / unified exec 的 `tool_name` 匹配 `Bash`，命令在 `tool_input.command`；`apply_patch` 的 `tool_name` 仍是 `apply_patch`，同时也匹配 `Edit` 或 `Write`。文档**没有**说这些字段在沙箱里会被拿掉，也没有说 OTEL 会记下沙箱里的命令文本。沙箱内命令是否仍以完整 `tool_input.command` 出现在 hook 里：【待验证】。

**进程身份**

| 特征 | 文档 |
|---|---|
| 命令名 | 产品命令是 `codex`。实际 exe 名【待验证】 |
| 家目录 | `CODEX_HOME`，默认 `~/.codex`：`config.toml`、`auth.json`、`history.jsonl`、`sessions/` |
| 父进程 | hook 命令在会话 `cwd` 下跑。父进程是否就是 `codex` 进程：【待验证】 |
| argv | 【待验证】。不要用未录制的路径做匹配规则 |

**映射**

`agent = "codex"`。`agent_session` 用 hook 的 `session_id`（`thread-id` 只出现在 notify，不要混用）。`tool` 用 `tool_name`（`Bash` 或 `apply_patch`，保留原名，不要改成 Claude Code 的 `Edit`）。`phase` 同上。`call_id` 用 `tool_use_id`。`summary` 只抽 `tool_input.command` 的截断摘要；OTEL 在没有命令文本时只记工具名、时长和成败，不要把输出摘要当成命令。

### 5.3 Cursor

查阅日期 2026-10-07。有公开 hooks。页面无文档日期；配置 schema 的 `version` 是 `1`；示例里出现过应用版本字符串 `1.7.2`，这不是本次查阅时的产品版本。hooks 在 Cursor 1.7 进入过 beta（变更日志，2025-09-29）；本次读到的 hooks 页没有再标 beta。

| 页面 | URL | 页面版本 / 日期 |
|---|---|---|
| Hooks | <https://cursor.com/docs/hooks> | schema `version: 1`；无文档日期 |
| Agent overview | <https://cursor.com/docs/agent/overview> | 无 |

旧地址 `https://cursor.com/docs/agent/hooks` 会跳到上面的 hooks 页。

**接入方式**

配置在项目 `<project>/.cursor/hooks.json` 或用户 `~/.cursor/hooks.json`。企业级：macOS `/Library/Application Support/Cursor/hooks.json`，Linux/WSL `/etc/cursor/hooks.json`，Windows `C:\ProgramData\Cursor\hooks.json`。文档没有写一次性的启动参数来注入 hook 而不改这些文件。【待验证】。

与工具相关的事件：`preToolUse`、`postToolUse`、`postToolUseFailure`、`beforeShellExecution`、`afterShellExecution`、`beforeMCPExecution`、`afterMCPExecution`、`afterFileEdit`、`beforeReadFile`。还有 `sessionStart` / `sessionEnd`、子代理、`stop`、Tab 编辑。云端 Agent 只跑 command hook；`sessionStart`、MCP 与 Tab hook 在云端不可用或延后。

Hook 是子进程，stdio 上传 JSON。退出 0 读 JSON；退出 2 拦截；其余退出码放行，除非 `failClosed`。审计 hook 必须以 0 退出且不改 `permission`。

`beforeShellExecution` 的 stdin 含 `command`、`cwd`、`sandbox`。`afterShellExecution` 加 `output` 与 `duration`（`output` 不入库）。`preToolUse` 含 `tool_name`、`tool_input`、`tool_use_id`、`cwd`、`agent_message`；文档示例的 `tool_name` 是 `"Shell"`，`tool_input.command` 是命令。`beforeMCPExecution` 含 `tool_name`、`tool_input`、`mcp_server_name`，以及 URL 或 stdio 的 `command`。`preToolUse` 的 `permission: "ask"` 文档写明目前不执行。

**终端命令由谁执行**

Agent 概述只写：Agent 执行终端命令并监看输出；默认用第一个可用的终端配置文件，用户可以用命令面板“Terminal: Select Default Profile”改。**没有写出 OS 进程名、helper 二进制名，也没有写沙箱实现。** hook 环境里有 `CURSOR_PROJECT_DIR` 与 `CURSOR_VERSION`。命令的父进程是 Cursor 主进程、终端宿主还是用户 shell：【待验证】。不要把论坛帖里的进程树写成已确认事实。

**进程身份**

| 特征 | 文档 |
|---|---|
| 产品 | 桌面应用 Cursor（Electron 宿主）。exe 名【待验证】 |
| CLI | 本次没有单独核对 CLI 产品的进程名。【待验证】 |
| hook 环境 | `CURSOR_PROJECT_DIR`、`CURSOR_VERSION` |
| 父进程 | 未记载。【待验证】 |

**映射**

`agent = "cursor"`。shell 用 `beforeShellExecution` 作 `phase = pre`，`tool = "Shell"`（与示例一致），`summary` 只抽 `command` 与 `cwd`，不要抽 `output`。`afterShellExecution` 作 `post`，用同一条命令文本加时间窗口配对，文档没有给 shell 事件 `tool_use_id`，所以 `call_id` 为空。`preToolUse` 有 `tool_use_id` 时用它。MCP 用 `mcp_server_name` 放进 `summary`，不要把服务器名升级成 E1 进程身份。

### 5.4 Gemini CLI（优先级低于前三者，但渠道并不薄）

查阅日期 2026-10-07。命令名文档写的是 `gemini`。

| 页面 | URL | 页面版本 / 日期 |
|---|---|---|
| Hooks reference | <https://geminicli.com/docs/hooks/reference/> | Last updated: Apr 10, 2026；无 hooks 版本号 |
| Telemetry | <https://geminicli.com/docs/cli/telemetry/> | Last updated: Jun 18, 2026；示例 User-Agent 里出现过 CLI `0.34.0`，不是页面版本 |
| Session management | <https://geminicli.com/docs/cli/session-management/> | Updated: Jun 18, 2026 |

Hooks 配在 `settings.json` 的 `hooks` 下。事件：`BeforeTool`、`AfterTool`、`BeforeAgent`、`AfterAgent`、`BeforeModel`、`BeforeToolSelection`、`AfterModel`、`SessionStart`、`SessionEnd`、`Notification`、`PreCompress`。页面有一节“Stable Model API”，说请求/响应形状保证 hook 不会因 SDK 更新而坏；没有把 hooks 标成实验性。

每条 stdin 都有 `session_id`、`transcript_path`、`cwd`、`hook_event_name`、`timestamp`。`BeforeTool` / `AfterTool` 加 `tool_name` 和 `tool_input`（对象，文档写明是模型生成的原始参数）。`AfterTool` 还有 `tool_response`。可选 `mcp_context`、`original_request_name`。MCP 工具名形如 `mcp_<server_name>_<tool_name>`。退出码 2 是 System Block。`BeforeTool` 的 `deny` / `block` 会停掉这次工具但回合继续。审计 hook 不得返回这些决策。

文档没有写一次性启动参数来注入 hook。【待验证】。

遥测默认关（`enabled` / `GEMINI_TELEMETRY_ENABLED` 默认 `false`）。开启后事件 `gemini_cli.tool_call` 的属性包含 `function_name` 和 `function_args`（字符串）。页面没有写这个字段还要另一个开关；更富的 span 属性要 `traces` / `GEMINI_TELEMETRY_TRACES_ENABLED=true`（默认 false）。本地文件用 `outfile` / `GEMINI_TELEMETRY_OUTFILE`，示例路径 `.gemini/telemetry.log`，没有默认路径。OTLP 默认 `http://localhost:4317`（`GEMINI_TELEMETRY_OTLP_ENDPOINT`）。`logPrompts` 默认 true：一旦打开遥测，提示词会进日志。审计接收端必须丢弃提示词与 `function_args` 里的内容字段，只留工具名和结构化摘要。

会话目录：`~/.gemini/tmp/<project_hash>/chats/`。哈希绑定项目根目录。保存的历史包含全部工具执行的输入和输出。页面没有写文件是 JSON 还是 JSONL。【待验证】。因为里面有工具输入输出，不要把这个目录拷贝进 fixtures。

**进程身份**：命令名 `gemini`。发布包是 npm 包 `@google/gemini-cli`，实际进程常常是 `node` 加入口脚本；文档没有写 `ps` 里的进程名。【待验证】exe 名与 argv。父进程未记载。

**映射**：`agent = "gemini-cli"`。`BeforeTool` → `pre`，`AfterTool` → `post`。`tool` = `tool_name`。`agent_session` = `session_id`。文档没有写 `tool_use_id`，`call_id` 为空，除非后续实测在 `tool_input` 里看到稳定 id。OTEL 的 `function_args` 只作摘要来源，默认不要开遥测就为了拿它。

### 5.5 Aider（优先级低；没有工具级自报告）

查阅日期 2026-10-07。两个页面都没有版本号或日期。

| 页面 | URL | 页面版本 / 日期 |
|---|---|---|
| Analytics | <https://aider.chat/docs/more/analytics.html> | 无 |
| Options | <https://aider.chat/docs/config/options.html> | 无 |
| Commands | <https://aider.chat/docs/usage/commands.html> | 本次未逐页核对；下面只采用 options 页写明的开关 |

没有公开的 hooks 或工具调用 OTEL。可用的本地文件：

| 开关 | 默认文件 | 文档说了什么 |
|---|---|---|
| `--chat-history-file` / `AIDER_CHAT_HISTORY_FILE` | `.aider.chat.history.md` | Markdown 聊天记录。没有写成结构化工具事件 |
| `--input-history-file` | `.aider.input.history` | 输入历史 |
| `--llm-history-file` | 示例 `.aider.llm.history`，无默认文件名 | 与 LLM 的对话。没有字段表 |
| `--analytics-log` | 无默认文件名 | 可选的本地分析日志 |

分析是选入的，绑一个随机 UUID。文档写明不采集代码、聊天消息、密钥或个人信息；采集的是模型名、token 数、编辑格式、功能使用次数和异常。没有工具调用事件。`--analytics-disable` 永久关闭；`--no-analytics` 只关本次。`--suggest-shell-commands` 默认开，控制是否提示并提供运行 shell 命令；这不是审计日志。

因此 Aider 的 E3 不能靠自报告拿到工具粒度。进程身份只能靠 E1：命令名文档上是 `aider`，实际常是 `python` / `python -m`，argv 【待验证】。不要从 Markdown 聊天记录里推测“执行过某命令”并升级证据等级。

### 5.6 MCP 服务器（子进程，E1 识别，不是 E3）

查阅日期 2026-10-07。Claude Code MCP 页：<https://code.claude.com/docs/en/mcp>（页面无版本）。

本地 stdio 服务器是子进程。配置键是 `command`、`args`、`env`，`type` 为 `stdio`。项目配置在项目根的 `.mcp.json`（`mcpServers`）；用户与本地项在 `~/.claude.json`。添加命令：

```text
claude mcp add [options] <name> -- <command> [args...]
```

`--` 之后的命令和参数原样传给子进程。文档没有说配置里的 `<name>` 会出现在子进程 argv 里。子进程环境会有 `CLAUDE_PROJECT_DIR`（项目根），以及 `CLAUDECODE=1`；`CLAUDE_CODE_CHILD_SESSION` **不**会设给 stdio MCP。

因此：能从 argv 看到的是 `command` + `args`（常见是 `npx` 加包名，或 `node` 加脚本），**不能**假设配置名就在命令行里。包名可以当作识别特征（I：从 argv 推测），配置名只有在读到用户的 mcp 配置并且命令行对上时才能填；对不上则名称为 NA，不要用空串。Windows 上 `npx` 是否经 `cmd /c` 包一层：本次读的 MCP 页没有写，【待验证】。

Cursor 的 `beforeMCPExecution` 自报告里有 `mcp_server_name`，那是 E3，不能拿来当进程树上的 E1 名称。协议层的 `tools/call` 属于 `AgentRpc`（E2，要 mcp-tap），不是本 spike 的 `AgentToolCall`。

### 5.7 对 `EventKind::AgentToolCall` 的字段建议

现有字段够用，不建议在本次调研上加必填字段。建议在实现时按下面填，仍然全是 E3：

| 字段 | 建议 |
|---|---|
| `agent` | `claude-code` / `codex` / `cursor` / `gemini-cli` / `aider`。不要用显示名 |
| `agent_session` | 各自的 `session_id`。拿不到就是 `None`，不要用 pid 充当 |
| `tool` | 保留对方原始 `tool_name`（`Bash`、`Shell`、`apply_patch`、`mcp_<server>_<tool>`）。不要归一成一套名字再声称那就是对方说的 |
| `phase` | hook 的 pre/post 事件名映射到 `ToolPhase`。只有事后渠道（OTEL tool_result、会话文件）时为 `post` |
| `call_id` | 有 `tool_use_id` 就用（Claude Code hook 与 OTEL、Codex hook、Cursor `preToolUse`）。Cursor shell 事件与 Gemini hook 文档没有这个字段，留 `None` |
| `summary` | 已脱敏、已截断的 JSON。建议键只限：`command`（截断）、`path`、`url`（脱敏）、`mcp_server`、`is_error`、`exit_code`、`decision`。不要有 `content`、`output`、提示词、模型输出、请求头、环境变量值。单条上限仍按存储设计的 4 KB。拿不到的键省略，不要写 0 或空串 |

可选、非破坏的后续字段（本次**不**改 event-schema；若要加，先走 ADR）：

- `channel`：`hook` / `otel` / `transcript`。现在可以放在 `source` 的子源里（`agent.<id>/hook`），不必进事件体。
- 不要加“已被系统证实”类字段。对齐结果是另一条 I，不能写回 E3 事件把它升成 E1。

**不要做的映射**：不要把 E3 的 Bash/Shell 记录合成一条 E1 `ProcessStart`。对不上 exec 时，产生 `Finding{kind: self_report_mismatch}`，证据等级仍是 E1（两份记录不一致这件事），文案用 evidence-model 的固定模板。

## 6. 结论

文档调研可以回答“有哪些本地渠道”，不能回答覆盖率和对齐率。

- Claude Code：可以。启动时用 `--settings` 的临时 JSON 加入 `PreToolUse`/`PostToolUse` command hook，不写用户的 `settings.json`。stdin 有工具名和参数。OTEL 默认不含工具参数，要 `OTEL_LOG_TOOL_DETAILS=1`。会话 JSONL 存在，格式文档明确标为内部且会变。
- Codex CLI：工具级 hook 字段与 Claude Code 接近（`tool_name`、`tool_input.command`），但文档没有不改用户配置的注入方式，且 hook 要信任。`notify` 只有回合结束。OTEL 的工具字段不含命令文本。会话目录存在，格式未记载。
- Cursor：有公开 hooks，含 shell 与 MCP 专用事件。终端命令由哪个 OS 进程执行，官方页没有写。
- Gemini CLI：有 `BeforeTool`/`AfterTool` 和默认关闭的 OTEL；OTEL 的工具事件含 `function_args`。优先级低于前三者只因为产品覆盖面，不是因为渠道缺失。
- Aider：没有工具级渠道。只能靠进程身份（E1），不要解析 Markdown 聊天记录当成工具调用。
- MCP：服务器名不在子进程 argv 里；只能从 `command`/`args` 推测包名，推测结果是 I。

假设第一条（hook 能拿到工具名和参数）对 Claude Code 与文档一致，仍未实测。假设第二条（时间窗口对齐 ≥80%）未验证。

## 7. 对文档的影响

- [ ] 新 ADR：E3 接入协议。本次不建议新开。现有字段够用；渠道差异放在适配器里。
- [ ] event-schema.md 中 AgentToolCall 的字段。本次不改。实现时按 §5.7 填，不要加“已证实”字段。
- [ ] P5 任务卡。开工前按各卡要求再核对一次版本。实测（hook 覆盖率、与 exec 对齐、各 Agent 的真实 exe/argv）仍属于后续 spike 或 P5 适配器卡，不在本文件范围内。
