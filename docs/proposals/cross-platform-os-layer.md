# 跨平台包：统一系统接口（linux / macos / windows）

本文件随 `feat/cross-platform` 开单，记录这一包的结构约定；接口代码按下面的约定逐步推上来。本包范围内包含 Windows 的 `aw run --no-daemon`。

下面 A、B、C 三节是已接受的评审结论和开工决定，覆盖本文较早的写法。与之冲突的旧说法（按 pid 加启动时间回收非自有进程、`PeerIdentity` 枚举里带 `NotIdentified`、单独的 `LaunchAs`）不再有效。

## 代码放哪

`crates/aw-platform/src/`：

- `lib.rs`：只放 trait，以及按 `cfg` 挑选本系统模块。
- `linux/`、`macos/`、`windows/`：各自的实现。

`cfg(target_os)` 只允许出现在 `lib.rs` 的模块选择处，以及各系统自己的 crate 里。共用代码里不再写 `target_os` 分支。

## A. 谁来新建这个程序

两条路径，一张表。两条都调用**同一套** `aw-platform` 函数，差别只在调用方身份怎么来：App 路径用 `IdentifiedCaller::from_peer`，`aw run` 路径用 `IdentifiedCaller::current_user`。

| | App 新建会话 | `aw run` / `--no-daemon` |
|---|---|---|
| 谁启动 | 三个系统都是**后台**启动程序 | `aw` 自己按当前用户启动，挂住，再交给后台收养（`--no-daemon`：自己记下，不交给后台） |
| 身份从哪来 | 从连接对端认出，见下 | `IdentifiedCaller::current_user`，就是当前用户 |
| 挂住阶段谁兜底 | 后台。后台在放行前崩溃或被杀掉，程序跟着结束 | `aw`。`aw` 还挂着就崩溃，程序跟着结束 |
| `--env` | 不经本路径 | 只交给被启动的程序。**绝不**发给后台：不进 API、不进日志、不进数据库。有一条测试专门断言这一点 |

App 新建会话，后台按系统认出连接方，再按那个身份启动：

| 系统 | 怎么认、怎么启动 |
|---|---|
| Windows | 从命名管道取出客户端令牌，认出调用方。按**这个身份**以挂起方式创建，绝不用服务账户。Job Object 由后台拿着 |
| macOS | 本地套接字上用 `getpeereid` / `LOCAL_PEERPID` 取出对端 uid，切到这个身份再启动；接口不提供附加组，字段为 `None` |
| Linux | `SO_PEERCRED` 认出 uid，按这个 uid 启动（现有的 launch-as） |

`aw run` 在 Windows 上：`aw` 自己拿着「关闭即杀」的 Job，放行或移交之前先清掉这个限制。

挂起再放行的代码今天在 `crates/aw-cli/src/launch/windows.rs` 和 `unix_macos.rs`。这两份**搬进** `aw-platform/windows` 和 `aw-platform/macos`，不留第二份，搬完旧文件删掉。

### 挂住与放行是两阶段

已定，三个系统同一条规则。挂住期间任何一步失败都结束这个程序，不留没人监控的程序。今天 Linux 上，后台启动的程序在后台停止或重启后**不会**跟着死，而是被过继、继续跑、不再被监控。现状**不是**「Linux 用 `PR_SET_PDEATHSIG`」。已经放行的程序**不得**带 `PDEATHSIG`。

挂住阶段「谁死程序跟着死」按**谁创建了这个程序**算，不一律算到后台头上：

- App 新建会话：后台创建，后台兜底。
- `aw run`：`aw` 创建，`aw` 兜底。

**(a) 挂住、尚未放行。** 创建者死了，挂住的程序必须跟着死。

| 系统 | 怎么挂住 | 失败时 | 创建者崩溃时 |
|---|---|---|---|
| Linux | 现有的门：`exec` 前堵住读一根管道 | 门不 `exec`，直接退出 | 写端只在创建者手里；读到 EOF（创建者已死）则门不 `exec` 直接退出。和/或只在挂住阶段设 `PR_SET_PDEATHSIG`，`exec` 前清掉 |
| Windows | `CREATE_SUSPENDED`；`ResumeThread` 之前先放进 Job Object，带 `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`。这个限制只在挂住期间有效 | `TerminateProcess` | Job 句柄随创建者关闭，作业里的进程被杀掉。`aw run` 这条路径上，`aw` 拿着这个 Job，放行或移交前清掉限制 |
| macOS | `posix_spawn`，带 `POSIX_SPAWN_START_SUSPENDED`；放行发 `SIGCONT` | `SIGKILL`，再 `waitpid` | 看门狗管道只覆盖挂住阶段，见下 |

macOS 崩溃兜底用看门狗管道，不用「另起一个小看门狗发 `SIGKILL`」：挂住期间门堵住读一根管道，写端只在创建者手里；读到 EOF（创建者已死）则门不 `exec` 直接退出。【待验证】这是原型，须在真机 macOS 上确认。

**(b) 已放行、正在跑。** 创建者停止或重启时程序继续跑，与「停止记录不结束程序」一致。放行时拆掉「创建者死则子死」：

- Linux：若挂住阶段设过 `PR_SET_PDEATHSIG`，`exec` 前清掉；门已经 `exec`，不再堵管道。
- Windows：`ResumeThread` 之前，用 `SetInformationJobObject` 去掉 `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`。
- macOS：放行发 `SIGCONT`；看门狗管道只管挂住阶段，放行（`exec`）之后程序不再读这根管道，不再发信号。

已放行之后后台重启，界面、`aw doctor` 和导出里都写这一句，不改写成断定：

「后台重启，记录已中断，程序可能还在运行」

### 进程身份与进程表

进程身份按系统取，不混成一套字段。`Owner` 就这两种，字段不省略：

| 系统 | `Owner` |
|---|---|
| Linux / macOS | `Owner::Unix`：`ruid` / `euid` / `suid`，加上 `rgid` / `egid` / `sgid`，再加上附加组 |
| Windows | `Owner::Windows`：账户 SID，加上是否提权（elevation），再加上完整性级别（integrity level） |

认出一个进程靠 **pid 加上启动时间**，防止 pid 复用后认错人。启动时间各系统这样读：

| 系统 | 读法 |
|---|---|
| Linux | `/proc/<pid>/stat` 第 22 字段（自开机起的 clock ticks） |
| macOS | `proc_pidinfo(PROC_PIDTBSDINFO)`，或 `sysctl` `KERN_PROC_PID` 的 `p_starttime`。没有 `/proc`，进程表走 `proc_listpids` / `sysctl` `KERN_PROC_ALL` |
| Windows | `GetProcessTimes` 的创建时间 |

进程表一项包含：pid、ppid、启动时间、可执行文件路径、argv。

## B. 接口形状

调用方身份是必填参数，没有默认值。类型上就不能退回后台自己的身份。

`PeerIdentity` 是不透明类型：字段私有，只能在 `aw-platform` 内部构造。认连接方的函数按系统分开，不做成一个跨系统枚举：

| 系统 | 函数 |
|---|---|
| Linux / macOS | `identify_unix_peer(&UnixStream)` |
| Windows | `identify_pipe_peer(handle)` |

认不出就是认不出，返回单独的拒绝错误 `PeerNotIdentified`，不塞进身份类型里当一个变体。结果只有「认出是谁」和「认不出」两种，认不出一律拒绝。

管道与套接字的现有约束保持：Linux 用 `SO_PEERCRED`；macOS 用 `getpeereid` 取 uid、`LOCAL_PEERPID` 取 pid；Windows 命名管道用 `GetNamedPipeClientProcessId`，再取客户端令牌，管道创建时带 `PIPE_REJECT_REMOTE_CLIENTS`，并写明 DACL。

挂住的子进程 `HeldChild::release(self)` **消耗**自己，返回 `ReleasedChild`。操作系统句柄只归 `ReleasedChild` 所有：

- `try_reap()`：看一眼，不阻塞。
- `wait()`：一直等到退出。

停止记录，以及「采样发现它已经不在」，都走这个句柄。**不**按 pid 加启动时间去回收自己并不拥有的进程。`watch.rs` 不再另外拿着一个 `Child`。

### 能力查询

能力是一个固定枚举 `Capability`，查询结果三选一：`Available` / `NotInThisBuild` / `NotSupportedOnThisOs`。`aw doctor` 逐项通过这个接口问，不自己猜。两种「还不支持」一律带上 `os` 和 `capability` 返回，绝不静默给空结果：

每个枚举值只有一个稳定英文 `as_str()` 名称，供 JSON 使用；人读的中文名称由 `zh()` 提供。当前名称依次是 `spawn_suspended`（挂起启动）、`spawn_as_caller`（以连接方身份启动）、`process_identity`（进程身份）、`process_table`（进程表）、`peer_identity`（认出连接方）、`secure_data_dir`（数据目录权限）、`exit_code`（退出码）。Linux 的 `spawn_suspended` 仅代表同一后台用户；`spawn_as_caller` 在 `aw-platform` 接入 launch-as 前报告 `NotInThisBuild`。

- `NotInThisBuild`：界面显示「本版本未接入」
- `NotSupportedOnThisOs`：界面显示「这个系统不支持」

### 数据目录权限

普通用户侧的程序一律经后台读数据，不直接打开数据目录。收紧之后各系统这样做：

| 系统 | 做法 |
|---|---|
| Windows | 关掉 ACL 继承，去掉普通用户；只留 SYSTEM 和管理员 |
| Linux / macOS | 显式权限位：数据目录 `0700`、属 root；套接字 `0660`，放在 `agentwatch` 组里 |

在权限真正收紧之前，`secure_data_dir` 在**三个系统上都返回 `NotInThisBuild`**，绝不假装已经成功。

### 仅测试用的挂起延迟

共用测试要能断言「挂住期间杀掉创建者 → 程序没了」。三个系统都靠一个只给测试的延迟，把放行往后推。等待发生在 `release()` 里面：

1. 只在专用 cargo feature `test-hold-delay` 后编译，默认关闭。发布构建里根本没有这段代码；在发布构建里设置环境变量不起任何作用。
2. 环境变量 `AW_TEST_HOLD_DELAY_MS` 让放行前等待，上限 10 秒。
3. CI 编出发布二进制，用 `strings` 检查这个环境变量的**名字不在里面**（`strings` | grep `AW_TEST_HOLD_DELAY_MS` 无输出），**并且**打开这个 feature 把测试跑一遍。

共用测试「挂住期间杀掉创建者 → 程序没了」打开这个 feature 来跑。

## C. 搬走清单

共用代码里剩下的系统分支，按下面归属搬走。一条轨道改自己名下的文件。

| 轨道 | 文件 |
|---|---|
| Linux / 共用 | `aw-daemon` 的 `collectors.rs`、`main.rs`、`sample.rs`、`api/routes.rs`、`api/launch_as.rs`、`api/ipc.rs`、`api/watch_routes.rs`、`collector_state.rs`、`watch.rs` |
| 共用（Windows 与 macOS 共同输入） | `aw-channel` 的 `lib.rs`：套接字路径顺序、命名管道 |
| Windows（Codex） | `aw-cli` 的 `launch/windows.rs`，以及 `cmd/run.rs` 里的 Windows 部分 |
| macOS（Claude Code） | `aw-cli` 的 `launch/unix_macos.rs`，以及 `runtime.rs` 里的套接字长度检查 |
| 共用 | `aw-cli` 的 `cmd/doctor.rs`、`cmd/attach.rs`、`cmd/daemon.rs` |

`crates/aw-daemon/tests/e2e_cli.rs` 必须在 macOS 和 Windows 的 CI 上既能编过、也能跑起来。命令按系统准备：Windows 没有 `sh`，退出码 7 用 `cmd /c exit 7`。

## 约定

1. 系统专属代码只放在各自的 `linux/`、`macos/`、`windows/` 里，编译时按系统挑；共用代码里不再按系统分支。
2. 「还不支持」分两种，一律带上 `os` 和 `capability` 返回，绝不静默给空结果。`aw doctor` 逐项通过 `Capability` 问，不自己猜。
   - `NotInThisBuild`：界面显示「本版本未接入」
   - `NotSupportedOnThisOs`：界面显示「这个系统不支持」
3. Linux 搬进新结构后行为不变：老测试一条不删、断言一条不改。
4. 一套按接口写的共用测试，三个系统都跑：退出码 7、程序名填错、`@last` 隔离、停止记录后回收、后台重启。另加两条：程序还挂住时杀掉创建者 → 程序没了（打开 `test-hold-delay`）；放行之后停止或重启后台 → 程序还在。命令按系统准备——Windows 没有 `sh`，退出码 7 用 `cmd /c exit 7`。Windows 上的「后台重启」指重启服务。macOS 和 Windows 的 CI 必须真正跑这套测试（`cargo test`，含 `e2e_cli.rs`），不能只跑 clippy。
5. 本包范围内包含 Windows 的 `aw run --no-daemon`。`--env` 的值只到被启动的程序，不进后台的 API、日志和数据库。
6. 文档跟着各条轨道的 PR 提交一起改：ADR，以及 [api-and-cli.md](../01-architecture/api-and-cli.md) 里「本版本仅 Linux」这类说法，改到和实际进度一致。
