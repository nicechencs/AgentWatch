# SPIKE-05 启动模式的范围追踪与权限划分

> 状态：进行中（仅 Windows 最小 PoC；Linux / macOS 未执行）
> 最后更新：2026-10-07
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

- 代码位置：`crates/aw-daemon/examples/win_job_poc/`（本次实测）。原方案 `spikes/SPIKE-05/` 未建立；任务卡文件范围是 `crates/aw-daemon/examples/`。`aw-daemon` 工作区 `forbid(unsafe_code)` 覆盖 example，且不能在 crate 内覆盖，所以 Win32 调用放在不属于工作区成员的 `win_job_poc`。`examples/win_job_scope.rs` 只负责构建并运行它。
- 环境：Windows 10 Pro for Workstations 10.0.19045，普通用户，未提权。Linux 与 macOS：本机为 Windows，未执行。
- 未跑完整的 `aw run` 原型，未跑 Claude Code，未测 `nohup` / `setsid` / 双重 fork / `start /b` / `open -a`，未经 Task Scheduler 或 WMI 启动进程。

## 4. 通过标准

| 指标 | 通过 |
|---|---|
| 守护化的进程是否仍在范围内 | Linux 和 Windows 上 100%；macOS 上允许经 launchd 代为启动的被识别为链路中断 |
| TUI 体验 | 与直接运行无差别 |
| 启动延迟 | <100 ms |

## 5. 结果

### 5.1 Linux

本机为 Windows，未执行。cgroup v2、`systemd-run --user --scope`、`StartTransientUnit`、pipe 同步后 exec，均【待验证】。

### 5.2 macOS

本机为 Windows，未执行。`POSIX_SPAWN_START_SUSPENDED`、200 ms 待定缓冲、`launchctl` 是否脱离，均【待验证】。

### 5.3 Windows（本机，普通用户，2026-10-07）

命令：

```text
cargo run --quiet --offline --manifest-path crates/aw-daemon/examples/win_job_poc/Cargo.toml --target-dir crates/aw-daemon/examples/win_job_poc/target
```

做法：未命名 Job；`CreateProcessW` 以 `CREATE_SUSPENDED | CREATE_NO_WINDOW` 启动
`C:\Windows\System32\cmd.exe /c C:\Windows\System32\ping.exe 127.0.0.1 -n 30`；
`AssignProcessToJobObject`；查 `JobObjectBasicProcessIdList`；`ResumeThread`；等 1500 ms 再查一次。
只设置 `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`（便于结束本 PoC 自己的子进程）。
`JOB_OBJECT_LIMIT_BREAKAWAY_OK` 与 `JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK` 都没有设置。
未使用计划任务、WMI、`DuplicateHandle`。

先前一次试运行用的是 `timeout.exe /t 30 /nobreak`。它在 stdin 不是控制台时立刻写出
`ERROR: Input redirection is not supported, exiting the process immediately.` 并退出，
查询时作业已空（`child_in_job=false member_count=0`）。这是该程序的行为，不是 Job API 失败。
改用 `ping.exe` 后，单独运行得到 `child_in_job=true member_count=1 still_in_job_after_resume=true`（退出码 0）。

一次复测（同一命令，退出码 0）得到同一形状：`cmd.exe`、其 `conhost.exe`、其 `PING.EXE`，
`child_in_job_while_suspended=true`，`still_in_job_after_resume=true`，`member_count_after_resume=3`。
下面是第一次带镜像名的记录（PID 每次不同）：

```text
{"pid":16268,"parent":34572,"image":"cmd.exe"}
{"pid":34624,"parent":16268,"image":"conhost.exe"}
{"pid":34528,"parent":16268,"image":"PING.EXE"}
summary child_pid=16268 child_in_job_while_suspended=true suspended_member_count=1 still_in_job_after_resume=true member_count_after_resume=3 breakaway_ok=false silent_breakaway_ok=false
```

`34572` 是本 PoC 进程。挂起期间作业里只有被显式加入的 `cmd.exe`。恢复执行 1500 ms 后，
`conhost.exe` 与 `PING.EXE` 也在同一作业里，且父进程都是该 `cmd.exe`。
中间一次只等了 300 ms，此时作业里仍只有 `cmd.exe`：孙子进程还没创建出来，不是它们逃出了作业。

以下没有在本机测，【待验证】：

- 嵌套 Job（从已在 Job 内的 VS Code、Chrome、Node 再启动）。
- 子进程使用 `CREATE_BREAKAWAY_FROM_JOB` 时，在本 Job 不允许 breakaway 的情况下是否失败，以及哪些程序会因此报错。
- 经计划任务、WMI、服务启动的进程是否不在 Job 内。按任务限制，本次没有去启动它们。
- 把 Job 句柄 `DuplicateHandle` 到另一个进程（包括将来的服务），以及命名 Job。
- `CreateProcessAsUser` / `ImpersonateNamedPipeClient`。本次父子进程是同一普通用户。
- TTY、信号转发、窗口尺寸。子进程用了 `CREATE_NO_WINDOW`，没有交互终端。
- 启动延迟是否 <100 ms。本次在恢复后固定等了 1500 ms，不是延迟测量。
- 附着模式的快照窗口，以及 `docker` / `ssh` / `git credential` / `schtasks` 的事件特征。

### 5.4 `cargo test -p aw-daemon`

未通过，且失败点不在本次改动里。`aw-daemon/src/collectors.rs` 仍引用 `aw_core::Placeholder`，
而当前 `aw-core` 已经没有该类型（该 crate 不在本任务文件范围内，未改）：

```text
error[E0425]: cannot find type `Placeholder` in crate `aw_core`
 --> crates\aw-daemon\src\collectors.rs:9:40
  |
9 |         std::any::type_name::<aw_core::Placeholder>(),
  |                                        ^^^^^^^^^^^
error: could not compile `aw-daemon` (bin "agentwatchd" test) due to 1 previous error
```

占位测试 `placeholder` 因此没有被编译。

## 6. 结论

就本机这一次而言：普通用户可以自己创建 Job，把挂起的子进程加入，再恢复它。
孩子和孙子（至少 `cmd.exe` 拉起的 `PING.EXE` 和 `conhost.exe`）仍在该 Job 内。不需要管理员。

与 ADR-0005 一起看，启动模式应该由 **CLI（普通用户）自己创建目标进程并把它加入 Job**，
而不是由以 LocalSystem 运行的 daemon 代为 `CreateProcess`。这次实测支持这一半：同一用户创建、挂起、加入、恢复，API 成功。
daemon 那一半（接收 Job 句柄、用 IOCP 维护范围集合）没有测，【待验证】。

不建议在这次结果上改 ADR-0005。下列仍是设计文档里的说法，不是本次测出的事实：

- daemon 以服务身份持有 Job 句柄后，能否收到 `JOB_OBJECT_MSG_NEW_PROCESS`。
- 不允许 breakaway 会不会让 Chrome / VS Code 等自己使用 Job 的程序失败。Win8+ 嵌套 Job 在这台机器上的实际行为【待验证】。
- 交互式 TTY 是否与直接运行无差别【待验证】。本次子进程没有控制台。

Linux 与 macOS 没有推荐：本机为 Windows，未执行。

## 7. 对文档的影响

- [ ] process-tracking.md（未改；本次只覆盖启动模式的一个普通用户路径，不足以去掉【待验证】）
- [ ] 各平台文档的“范围追踪”一节
- [ ] CAP-SCOPE 各行
