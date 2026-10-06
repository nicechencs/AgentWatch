@AGENTS.md

## Claude Code 补充

- 开工前先判断能否按 AGENTS.md §8 拆成多个 subagent 并行。分派时把任务卡的「文件范围」「限制」「验收标准」原样写进提示词。
- 任务提示词模板见 [docs/04-plan/tasks/README.md §7](docs/04-plan/tasks/README.md)。
- 需要 root 或管理员权限的命令（加载 eBPF、开 ETW 会话、运行 eslogger）不要自行提权执行。先说明命令和用途，由用户确认或放到 CI / 虚拟机中运行。
- 不要不带 `-DryRun` 运行 `scripts/sync-issues.ps1` 或 `scripts/sync-labels.ps1`。写入 GitHub 前要求用户确认。
- Windows 开发机上优先用 PowerShell 7（`pwsh`）运行脚本。
