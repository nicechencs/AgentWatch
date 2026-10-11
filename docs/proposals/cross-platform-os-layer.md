# 跨平台包：统一系统接口（linux / macos / windows）

本文件随 `feat/cross-platform` 开单，记录这一包的结构约定；接口代码按下面的约定逐步推上来。本包范围内包含 Windows 的 `aw run --no-daemon`。

## 代码放哪

`crates/aw-platform/src/`：

- `lib.rs`：只放 trait，以及按 `cfg` 挑选本系统模块。
- `linux/`、`macos/`、`windows/`：各自的实现。

`cfg(target_os)` 只允许出现在 `lib.rs` 的模块选择处，以及各系统自己的 crate 里。共用代码里不再写 `target_os` 分支。

## 收进统一接口的部分

### 进程身份与进程表

进程身份按系统取，不混成一套字段：

| 系统 | 身份 |
|---|---|
| Linux / macOS | 真实 / 有效 / 保存三个 uid，加上附加组（groups） |
| Windows | 账户 SID，加上是否提权（elevation） |

认出一个进程靠 **pid 加上启动时间**，防止 pid 复用后认错人。启动时间各系统这样读：

| 系统 | 读法 |
|---|---|
| Linux | `/proc/<pid>/stat` 第 22 字段（自开机起的 clock ticks） |
| macOS | `proc_pidinfo(PROC_PIDTBSDINFO)`，或 `sysctl` `KERN_PROC_PID` 的 `p_starttime`。没有 `/proc`，进程表走 `proc_listpids` / `sysctl` `KERN_PROC_ALL` |
| Windows | `GetProcessTimes` 的创建时间 |

进程表一项包含：pid、ppid、启动时间、可执行文件路径、argv。

### 启动并挂起

拆成两步：先启动并挂住（`spawn_suspended`），接管成功后再放行（`release`）。挂住期间任何一步失败都结束这个程序，不留没人监控的程序。

两阶段，三个系统同一条规则，已定：

- 还挂着：随后台一起死。后台在放行前崩溃或被杀掉，这个程序也结束。
- 已放行：程序继续跑。后台之后重启或退出，不再杀掉它。

已放行之后后台重启，界面、`aw doctor` 和导出里都写这一句，不改写成断定：

「后台重启，记录已中断，程序可能还在运行」

调用方身份是必填参数，没有默认值。类型上就不能退回后台自己的身份：认不出对方，连这个参数都构造不出来。结果只有「认出是谁」和「认不出」两种，认不出一律拒绝。

| 系统 | 怎么认连接方 |
|---|---|
| Linux | `SO_PEERCRED`（现有做法） |
| macOS | unix socket 上 `getpeereid` 取 uid，`LOCAL_PEERPID` 取 pid |
| Windows | 命名管道：`GetNamedPipeClientProcessId`，再 `ImpersonateNamedPipeClient` 取客户端令牌。按这个身份启动，绝不用服务账户。管道创建时带 `PIPE_REJECT_REMOTE_CLIENTS`，并写明 DACL |

### 挂住与放行是两阶段

已定，三个系统同一条规则（见上）。今天 Linux 上，后台启动的程序在后台停止或重启后**不会**跟着死，而是被过继、继续跑、不再被监控。现状**不是**「Linux 用 `PR_SET_PDEATHSIG`」。已经放行的程序**不得**带 `PDEATHSIG`。

**(a) 挂住、尚未放行。** 后台死了，挂住的程序必须跟着死，三个系统一样。

| 系统 | 怎么挂住 | 失败时 | 后台崩溃时 |
|---|---|---|---|
| Linux | 现有的门：`exec` 前堵住读一根管道 | 门不 `exec`，直接退出 | 写端只在后台手里；读到 EOF（后台已死）则门不 `exec` 直接退出。和/或只在挂住阶段设 `PR_SET_PDEATHSIG`，`exec` 前清掉 |
| Windows | `CREATE_SUSPENDED`；`ResumeThread` 之前先放进 Job Object，带 `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`。这个限制只在挂住期间有效 | `TerminateProcess` | Job 句柄随后台关闭，作业里的进程被杀掉 |
| macOS | `posix_spawn`，带 `POSIX_SPAWN_START_SUSPENDED`；放行发 `SIGCONT` | `SIGKILL`，再 `waitpid` | 看门狗管道只覆盖挂住阶段，见下 |

macOS 崩溃兜底用看门狗管道，不用「另起一个小看门狗发 `SIGKILL`」：挂住期间门堵住读一根管道，写端只在后台手里；读到 EOF（后台已死）则门不 `exec` 直接退出。【待验证】这是原型，须在真机 macOS 上确认。

**(b) 已放行、正在跑。** 后台停止或重启时程序继续跑，与「停止记录不结束程序」一致。放行时拆掉「后台死则子死」：

- Linux：若挂住阶段设过 `PR_SET_PDEATHSIG`，`exec` 前清掉；门已经 `exec`，不再堵管道。
- Windows：`ResumeThread` 之前，用 `SetInformationJobObject` 去掉 `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`。
- macOS：放行发 `SIGCONT`；看门狗管道只管挂住阶段，放行（`exec`）之后程序不再读这根管道，不再发信号。

已放行之后后台重启，界面、`aw doctor` 和导出都写这一句，不另起措辞：

「后台重启，记录已中断，程序可能还在运行」

### 仅测试用的挂起延迟

共用测试要能断言「挂住期间杀掉后台 → 程序没了」。三个系统都靠一个只给测试的延迟，把放行往后推：

1. 只在专用 cargo feature `test-hold-delay` 后编译，默认关闭。发布构建里根本没有这段代码；在发布构建里设置环境变量不起任何作用。
2. 环境变量 `AW_TEST_HOLD_DELAY_MS` 让后台在放行前等待，上限 10 秒。
3. CI 有一步：编出发布二进制，用 `strings` 检查开关不在里面（`strings` | grep `AW_TEST_HOLD_DELAY_MS` 无输出），另加一条 `cfg` 单测。

共用测试「挂住期间杀掉后台 → 程序没了」打开这个 feature 来跑。

### 回收退出码

统一函数 `reap_child(pid, start_time)`。停止记录时用它；采样发现后台启动的进程已经不在时也用它（盖住 #146 评审里那种少见的僵尸）。只等后台自己启动的那个子进程。

| 系统 | 做法 |
|---|---|
| Linux / macOS | `waitpid` |
| Windows | `WaitForSingleObject`，再 `GetExitCodeProcess`，然后 `CloseHandle` |

### 数据目录权限

普通用户侧的程序一律经后台读数据，不直接打开数据目录。

| 系统 | 做法 |
|---|---|
| Windows | 关掉 ACL 继承，去掉普通用户；只留 SYSTEM 和管理员 |
| Linux / macOS | 显式权限位：数据目录 `0700`、属 root；套接字 `0660`，放在 `agentwatch` 组里 |

## 约定

1. 系统专属代码只放在各自的 `linux/`、`macos/`、`windows/` 里，编译时按系统挑；共用代码里不再按系统分支。
2. 「还不支持」分两种，一律带上 `os` 和 `capability` 返回，绝不静默给空结果。`aw doctor` 逐项通过这个接口问，不自己猜。
   - `not_in_this_build`：界面显示「本版本未接入」
   - `not_supported_on_this_os`：界面显示「这个系统不支持」
3. Linux 搬进新结构后行为不变：老测试一条不删、断言一条不改。
4. 一套按接口写的共用测试，三个系统都跑：退出码 7、程序名填错、`@last` 隔离、停止记录后回收、后台重启。另加两条：程序还挂住时杀掉后台 → 程序没了（打开 `test-hold-delay`）；放行之后停止或重启后台 → 程序还在。命令按系统准备——Windows 没有 `sh`，退出码 7 用 `cmd /c exit 7`。Windows 上的「后台重启」指重启服务。macOS 和 Windows 的 CI 必须真正跑这套测试（`cargo test`），不能只跑 clippy。
5. 本包范围内包含 Windows 的 `aw run --no-daemon`。
6. 文档跟着各条轨道的 PR 提交一起改：ADR，以及 [api-and-cli.md](../01-architecture/api-and-cli.md) 里「本版本仅 Linux」这类说法，改到和实际进度一致。
