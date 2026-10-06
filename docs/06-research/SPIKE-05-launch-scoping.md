# SPIKE-05 启动模式的范围追踪与权限划分

> 状态：未开始
> 最后更新：2026-10-06
> 关联：CAP-SCOPE-01~04、CAP-PROC-05、ADR-0005、REQ-02
> 时间盒：3 人天
> 负责人：

## 1. 问题

1. **Linux**：普通用户的 CLI 创建进程后，由 root daemon 把它移入专用 cgroup，与 systemd 的 cgroup 管理是否冲突？与之相比，用 `systemd-run --user --scope` 或者 D-Bus 的 `StartTransientUnit` 更好还是更差？进程在开始执行用户代码之前就被纳入范围，这一点怎么保证？可以考虑用 pipe 同步加 exec。
2. **Windows**：由 CLI 创建 Job 并把句柄交给服务的可行性。按嵌套 Job 的规则，VS Code、Chrome、Node 等在已有 Job 内启动时是否正常？不允许 breakaway 的话，哪些程序会报错？
3. **macOS**：`POSIX_SPAWN_START_SUSPENDED` 加 `SIGCONT`；在 eslogger 的异步延迟下，200 ms 的待定缓冲是否够用。
4. **附着模式**：三个平台上“先挂探针再做快照”之间的窗口有多大，会不会漏掉进程？
5. **链路中断识别**：`docker run`、`ssh`、`git credential`、`systemd-run`、`launchctl`、`schtasks` 各产生什么样的事件特征？以此制定 CAP-SCOPE-03 的初始规则。
6. 终端和交互：被启动的 Agent 是 TUI（例如 Claude Code），需要完整的 TTY、信号转发和窗口尺寸调整。确认“CLI 自己创建进程”的方案能保证这些。

## 2. 假设

由 CLI 自己创建进程、daemon 只负责纳入范围，这个方案在三个平台上都可行，且不影响 TTY。

## 3. 方法

- 三个平台各写一个最小的 `aw run` 原型，用它启动 bash/pwsh，再在里面运行 `nohup`、`setsid`、双重 fork、`start /b`、`open -a` 等操作，验证是否全部还在范围内。
- 用上述原型运行 Claude Code，完成一次交互会话。
- 代码位置：`spikes/SPIKE-05/`

## 4. 通过标准

| 指标 | 通过 |
|---|---|
| 守护化的进程是否仍在范围内 | Linux 和 Windows 上 100%；macOS 上允许经 launchd 代为启动的被识别为链路中断 |
| TUI 体验 | 与直接运行无差别 |
| 启动延迟 | <100 ms |

## 5. 结果

（待填）

## 6. 结论

（待填）

## 7. 对文档的影响

- [ ] process-tracking.md
- [ ] 各平台文档的“范围追踪”一节
- [ ] CAP-SCOPE 各行
