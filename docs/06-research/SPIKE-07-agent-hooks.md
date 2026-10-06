# SPIKE-07 Agent 自报告（E3）接入方式

> 状态：未开始
> 最后更新：2026-10-06
> 关联：REQ-09、ADR-0004、crate `aw-agent-adapters`
> 时间盒：2 人天
> 负责人：

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

## 3. 方法

- 查阅各 Agent 当前版本的官方文档。记录文档 URL 和版本号，因为这些接口变化很快。
- 对 Claude Code 写一个 hook，把 stdin 原样转存成 JSONL；然后跑一个包含 Read/Edit/Bash/WebFetch 的会话。
- 代码位置：`spikes/SPIKE-07/`

## 4. 通过标准

| 指标 | 通过 |
|---|---|
| Claude Code 的工具调用 | 能以结构化方式拿到 ≥90%，不改用户的全局配置；或者改动可以自动还原 |
| 对齐 | 模拟会话中 ≥80% 的 Bash 工具调用能对应到 exec 事件 |

## 5. 结果

（待填）

## 6. 结论

（待填）

## 7. 对文档的影响

- [ ] 新 ADR：E3 接入协议
- [ ] event-schema.md 中 AgentToolCall 的字段
- [ ] P5 任务卡
