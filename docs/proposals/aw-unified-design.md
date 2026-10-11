# AgentWatch #147 统一设计：底层五类 + 对外五件事

> 拟提交为 `docs/proposals/aw-unified-design.md`。作者 Coding-bot。第 2 版 2026-10-11 13:45（台北），按 review-bot 13:40 的打回意见（`/workspace/aw-unified-design-review.md`，挡-1～挡-4、拆活前要补 1～11、建议 1～5）、PM 13:04/13:13/13:23/13:24 的决定、UI审查+review 13:25 的决定改过。逐条对照见文末 **I 节**。
> **第 3.3 版 2026-10-11 15:10（台北）**：按 review 对 3.1 的打回（`/workspace/aw-unified-design-review-v3.md`，挡 2、3、4）和 PM 14:31 改：PATH 跳过空项和 `.`、相对名按目标工作目录、两条启动路共用一个查找函数、Windows PATHEXT；新增第 0a 步安全快修；dev 只能手动跑 CI；行 id 新列叫 `sampler`、保留 `id` 主键、计数器归后台不归采样器实例、按列合并、流量用 MAX；其余 8 张表归类；0012 迁移在 207MB 库上实测；FTS 三个删除触发器按 rowid。
> **第 3.1 版 2026-10-11 14:40（台北）**：#147 已合进 dev（f7ea22f），本文改为直接推到 `dev`。加了：A3 行 id 按表分三类、`replay_writes` 去留、seq 分配和迁移；Test-bot 对 6a11d6d 的回归项；A1 PATH 解析、附加组、终端前台、采集 crate 禁用清单；超时常量定为 12 秒；c21dcec 剩下的三处；在 dev tip 上的复测数字（H3）；E 节改成「每一步单独推到 dev」。
> 代码基线：最早按 `origin/feat/cross-platform` = **185fc77**（含 4e6b68a / 95b49ff / 3d95803）核对；第 3.1 版新增内容按 **`origin/dev` = f7ea22f**（跟 feat/cross-platform 的 ef28f88 树完全相同）核对，标了「dev」的 file:line 是这一版的。下文其余 file:line 按 185fc77；标「本地」的是还没推的工作区；标「证明工作区」的是 `/workspace/aw-xplat-prove`（从 185fc77 新建，只做测量，不推）。
> 依据：review-bot 各轮审查（`/workspace/aw147-*review*.md`、`aw-full-review.md`、`aw-unified-design-review.md`），Test-bot 复测（`/tmp/agentwatch-143/dblock-da57.txt`、`retest-2511990.txt`、`attach-timing-probe.txt`），UI审查 定稿（`/workspace/qa-issues/UI-147-wording.md`），PM 真机结果和 12:12–13:25 的决定。
> 以后 #147 剩下的改动都按这份来做，不再一条一条补。每类都写了：根本原因（对着代码核过，两处「待证」已用数字证实，见 **H 节**）、三个系统统一的规矩、收进来的已报问题、用什么测试来验证、放进哪个提交。
> **PM 13:24：#147 已定的事一条都不砍。** 下面每一条都在 E 节有提交号；没有提交号的只有明确标了「下一包」的。

## 0. 各路现状（14:40，#147 已合进 dev f7ea22f）

| 路 | 提交 / 工作区 | 状态 |
|---|---|---|
| winpipe A（回完话不再断开管道、按长度读） | 4e6b68a，已在 dev | review 有条件通过，看 dev 上的 Windows CI |
| winpipe B（按管道属主核对服务端） | 93a6cfa，已在 dev | 等 review |
| Linux 门控泄漏 | c21dcec，已在 dev（Linux 改走 `unix/hold.rs`，不再用 sh 门控） | 在 dev tip 上 48×300 零泄漏、40 路并发启动 400/400（H3）；剩下三处见 A1「c21dcec 剩下的」 |
| DB 第二、三轮 + 附着修复 | da00935、6a11d6d、36abe45，已在 dev | 附着在 dev tip 上 57–148ms（H3）；行 id 换成（会话, 采样器 `sampler`, seq）、Test-bot 回归项在第 5b 步 |
| 文案（管道核对两句、wording-lint 禁「安全」） | 1efe176，已在 dev | 并进第 8b 步继续 |
| Windows 第三轮 | 345d216，已在 dev | `--no-daemon` 的 Linux/Mac 看门进程是过渡做法（文末说明），第 4 步换掉 |
| Mac 第二轮（95b49ff，review 打回） | 已在 dev | 改法并进 A1，第 4 步做 |
| 统一设计 v2 / v3 | 0aff6cb、ef28f88（feat/cross-platform），本版直接推 dev | — |

---|---|---|
| winpipe A（回完话不再断开管道、按长度读） | 4e6b68a 已推 | review 有条件通过，过关条件是 185fc77 或之后的 Windows CI 绿 |
| Mac 第二轮（fork 后在子进程里挂住） | 95b49ff 已推 | **review 打回**（`aw147-95b49ff-3d95803-review.md`：子进程里分配内存和 unsetenv、放行失败留僵尸、文档顺序写反、兄弟挂住进程继承写端、SIGPIPE 被继承）。改法并进 A1，第 4 步做 |
| Windows 数据目录 ACL + 句柄 | 3d95803 已推 | **review 打回**（数据目录太严 → Mac/Win CI 整片红；子项和联接；检查到使用之间有空档）。放宽规则见 A4 规矩 6，第 0 步做 |
| desktop lock | 185fc77 已推 | desktop CI |
| DB 第二轮 | 8fff164 只在本地（aw-xplat-fix） | 推前检查红（retention storage_full），DB 第三轮在修 |
| CLI 文案第三轮 | aw-xplat-cli 未提交 | 并进第 8b 步，不单独推 |
| winpipe B / C | aw-xplat-winpipe 未提交 | 进行中 |
| 两处「待证」 | 证明工作区 `/workspace/aw-xplat-prove` | **都已证实，数字见 H 节**。Linux 门控的修法和压力测试可以直接拿进第 4 步 |

---

# 第一部分 底层五类

## A1. 启动程序：挂住 → 交出管道和句柄 → 放行 → 谁来收尾

**根本原因**：三个系统各写了一套「哪些 fd/句柄给子程序、子进程在 fork 和 exec 之间能做什么、aw 或后台死了子程序怎么办」，从来没有写成同一条规矩，所以每个系统各漏一处。

- **Linux 门控（已证实，数字见 H1）**：`aw-platform/src/linux/mod.rs:398-431` `spawn_gate` 先 `pipe2(O_CLOEXEC)`，接着在**父进程里**把读端的 CLOEXEC 清掉（403-406），直到 `command.spawn()` 之后的 431 行才 `drop(read_fd)`。这里其实是**两个**毛病，因果链分开写：
  1. **读端泄漏给同时启动的兄弟进程**：48 线程并发时 30.3% 的子程序手里拿着别人的门控读端。读端泄漏**不会**让 EOF 迟到（EOF 只看写端），它违反的是「子程序只拿白名单里的 fd」。
  2. **门控 fd 号 ≥ 10 时目标根本跑不起来**：门控脚本是 `/bin/sh -c 'read -r _ <&{fd} … exec {fd}<&-'`（418-420 行），Ubuntu 的 `/bin/sh` 是 dash，dash 只认一位数的 fd，`<&10` 报 `Bad fd number` 退 2，目标一行都没跑。并发时父进程里同时开着的管道多，fd 号很快过 10，所以 67.8% 的子程序是这样死的；单线程只要 fd 号 ≥ 10 也**必然**失败（`gated_spawn_works_when_the_gate_fd_number_is_ten_or_more` 修前稳定 Exited(2)）。后台本身常驻 fd 多，这一条在真后台里比在测试里更容易踩到。
  - `unix/hold.rs:130-133` 的 `PIPE_LOCK` 只保护 Mac 那条路，Linux 不用它。
  - **c21dcec（已在 dev）已经修掉上面两条**：Linux 的 `spawn_gate`（dev `linux/mod.rs:296-304`）直接调 `crate::unix::hold::spawn`，不再有 sh 门控，所以证明工作区那份「dup2 到 3」的补丁**不再需要**，第 4 步也不再拿它。dev tip 上复测零泄漏（H3）。
  - **c21dcec 剩下的三处**（都在第 4 步改）：
    1. **没有用 `pipe2`**：dev `hold.rs:532-548` `pipe_cloexec` 还是先 `pipe()` 再两次 `fcntl`，中间别的线程 fork 会把管道带走。Linux 上改成 `pipe2(O_CLOEXEC)` 一步建好；Mac 没有 pipe2，照规矩 1 `pipe()` 后马上 FD_CLOEXEC，再由子进程的关 fd 循环兜住。
    2. **附加组用的是连接方报的**：Linux 这边的组来自 `/proc/<pid>/status` 的 `Groups:`（dev `linux/mod.rs:107`、126-144 `peer_groups`，注释自己写着 best-effort），`hold.rs:99-108` 再拿它 `setgroups`。连接方在连上之后可以改自己的组（比如 `newgrp`），读 `/proc` 跟连接时刻也不是同一时刻。改成规矩 4：后台按用户 `getgrouplist` 重新算。
    3. **子进程里还在分配内存**：dev `hold.rs:391`/409 `clear_preload`（`unsetenv`），508/510 两个 `collect()`。照规矩 3 改。
  - CI 上 `command_spawner_*` 偶发失败到底是哪条断言：**CI 日志还没拿到**，按上面两条推断是第 2 条（退 2），要 Test-bot 或 PM 贴一次失败日志确认（I 节列为未完成项）。
- **Mac 挂住（95b49ff，review 打回）**：fork 后不再重新执行自己这一点修好了，但 `aw147-95b49ff-3d95803-review.md` 实测出：
  - 子进程里分配内存：`hold.rs:454-458` `exec()` 里 `collect()` 两个 Vec；`hold.rs:356-364` `clear_preload` 调 `unsetenv`（不在异步信号安全列表里，glibc/macOS 还要拿环境锁，多线程后台可能卡死）。`clear_preload` 本身也没用：execve 传的是另外准备好的环境。
  - 放行前子进程已失败退出时留僵尸、失败码丢失：`hold.rs:190-209` 先 `take()` pid 再写管道，写失败 pid 已经没了，实测 Z 状态，用户只看到英文「Broken pipe」。
  - 挂着的子进程拿着父进程**所有** fd：`child_hold`（331-353）只关了自己那根写端；A、B 同时挂着时中止 A 要等 B 放行（实测 2 秒）。`ffi::pipe_cloexec`（479-502）先 `pipe()` 再分两次 `fcntl`，中间别的线程 fork 会把写端带走。
  - 目标继承了后台「忽略 SIGPIPE」（实测 SigIgn bit 13），Linux 走 Command 会重置，两个系统行为不同。
  - 附加组：Mac 连接方身份 `groups` 永远是 None（`macos/mod.rs:109-124`），`hold.rs:99-102` 遇到 None 就拒，所以 root 后台在 Mac 上替别的用户启动**一定失败**；程序名不解析成绝对路径（`launch_as.rs:446`，execve 不查 PATH）。
  - 文档三处把顺序写成「放行之后再切身份」（`macos.md:128`、`api-and-cli.md:186`、`launch_as.rs:423-428`），代码实际是先切身份再等放行。
  - 自检少查 `getegid` 和「`setgid(0)` 必须失败」（`hold.rs:383-388`）；`caller_preload_is_absent_before_exec`（667-694）是假测试。
- **Windows 放行以后就不再管整棵进程树**：`windows/mod.rs:908-922` 放行前把 `KILL_ON_JOB_CLOSE` 关掉，随后关闭 Job；等待退出用 `WaitForSingleObject(…, u32::MAX)`（973 行）没有上限。缺标准句柄、提前返回泄漏句柄 3d95803 已改（709-732 用 NUL 补，788 行 HANDLE_LIST），没上真机。
- **aw 被强杀后谁来清理，没有设计**：Linux 放行后父子没有任何关联（`linux/mod.rs:416-417` 注释「no daemon-death coupling」）；默认模式 aw 忽略 SIGINT、不转发 SIGTERM（Test-bot E）。`PR_SET_PDEATHSIG` 只管直接子进程，aw 被 SIGKILL 后自己一行代码都跑不了，「再做进程组清理」没人执行；Mac 什么都没有。
- **起程序的不一定是 aw**：App 新建会话时起程序的是**后台**（`watch_routes.rs:371` 起，Linux 走 `launch_as::spawn_as`）。如果统一启动时给所有子进程都设 PDEATHSIG，后台一崩已放行的程序就跟着死，违反「放行以后后台崩了程序照样跑」。
- **`--no-daemon` / Mac `aw run` 让要读终端的程序卡住**：`aw-cli/src/cmd/run.rs:871`、`launch/unix_linux.rs:756`（`process_group(0)`）、`run.rs:1099`（Mac `setpgid`）、Mac 的 `hold.rs:152-161` 加 `run.rs:969/1094`，都把子程序放进新的进程组，但全仓库没有 `tcsetpgrp`，子程序一读终端就收到 SIGTTIN 停住。

**三个系统统一的规矩**（写进 `docs/proposals/cross-platform-os-layer.md` 新增一节「启动契约」，**跟第 4 步同一个提交，或者更早**，见 E 节第 −1 步）：

1. **不继承**：
   - 父进程里新建的 fd 和句柄**一出生就是不可继承的**，整个生命周期都不放开。Linux 用 `pipe2(O_CLOEXEC)`；Mac 没有 pipe2，**`pipe()` 之后马上对两端 `fcntl(F_SETFD, FD_CLOEXEC)`**（PM 13:13）。
   - 只在子进程那一侧按白名单放开，白名单只有 0/1/2 和门控读端：
     - Linux：子进程 fork 之后、切身份之前，`dup2(门控读端, 3)`（dup2 出来的副本自动没有 CLOEXEC；门控 fd 固定为一位数 3，dash 也认），再 `close_range(4, ~0U, 0)`（内核不支持时回退到循环 `close`）。证明工作区已经做了前一半（dup2 到 3、父进程一直 CLOEXEC），压力测试零泄漏，见 H1。
     - **Mac（PM 13:13 决定）**：子进程在 exec 之前，用**最原始的循环 `close`** 关掉除 0/1/2 和自己门控读端以外的所有 fd，不分配内存；上限在**父进程里** fork 之前用 `getrlimit(RLIMIT_NOFILE)` / `getdtablesize()` 算好传进去。**靠的是这个关 fd 循环，不是靠锁。**
     - Windows：`PROC_THREAD_ATTRIBUTE_HANDLE_LIST` 白名单（3d95803 已用）。
   - 门控读端在 exec 目标程序之前关掉（Linux 的 `exec 3<&-`，Mac/Linux 换成 hold.rs 后由子进程直接 close）。
2. **只有一个启动函数 + 禁用 Command（PM 13:23）**：后台和 aw-platform 里起程序一律走 `aw_platform` 的同一个启动函数，它在「建管道 → fork 返回」期间拿一把全局启动锁（`SPAWN_LOCK`，取代只管 Mac 的 `PIPE_LOCK`）。`aw-daemon/clippy.toml` 和 `aw-platform` 加 `disallowed_methods`：`std::process::Command::new`、`libc::fork`、`libc::posix_spawn*`、`nix::unistd::fork`，只有启动模块本身 `#[allow]`。锁是第二道防线，第一道是规矩 1 的子进程关 fd。
   - **明确不覆盖的**（review 会查，这里写死）：
     - **第三方 crate 自己起进程或 fork**（依赖里的 `Command`、`libc::fork`、`system()`）：clippy 只查我们自己的代码，管不到依赖。缓解：我们的 fd 一律 CLOEXEC，所以依赖起的程序拿不到门控管道；依赖自己开的 fd 如果没设 CLOEXEC，会被我们起的子程序继承——这一条由规矩 1 的子进程关 fd 兜住，不靠锁。依赖起的程序的生死不归启动契约管。`cargo deny`/审查清单里列出现在依赖树里会起进程的 crate（第 4 步提交时附清单）。
     - **采集 crate 里直接起系统命令**（dev 上现有四处）：`aw-collector-macos/src/privilege.rs:17` 调 `/usr/bin/id`，`aw-collector-windows/src/privilege.rs:48` 调 `whoami`，`aw-collector-poll/src/host.rs:202` 调 `netstat`，`aw-collector-macos/src/sni.rs:304` 调 `tcpdump`。这些在后台进程里跑，会在启动锁之外 fork。**决定**：采集 crate 也加进 `disallowed_methods`；`id`、`whoami`、`netstat` 三处改成直接调系统接口（`getgroups`/`getgrouplist`、`GetTokenInformation`、读 `/proc/net/*` 或 `sysctl`/`GetExtendedTcpTable`），不再起进程；`tcpdump` 是 Mac 抓 SNI 的唯一办法，改成走统一启动函数（拿启动锁、只给白名单 fd），在源码里 `#[allow]` 并写明原因。`host.rs:373`/409 是测试里重新运行测试二进制，放在 `#[cfg(test)]` 里允许。
     - **依赖里会起进程的代码要扫出来**：clippy 只查我们自己的源码，所以 CI 加一个 `xtask spawn-audit`：对 `cargo vendor` 出来的依赖源码搜 `Command::new`、`fork(`、`posix_spawn`、`system(`、`CreateProcess`，结果跟仓库里的白名单文件 `docs/spawning-deps.txt` 比，多出来就红。另外检查依赖树里的 tokio 没有打开 `process` feature（`cargo tree -e features -i tokio` 里不能出现 `process`；dev 根 `Cargo.toml:60` 现在是 `rt-multi-thread, net, time, macros`，没有），这样 `tokio::process::Command` 进不来。
     - **aw-cli 和桌面 App 自己的进程**：ban 只在 `aw-daemon` 和 `aw-platform`。aw-cli 里 `--no-daemon` / `aw run` 起目标程序那条路**要改走同一个启动函数**（第 4 步），但 aw-cli 其他自己起的进程（如 `daemon install` 调系统服务管理器、打开浏览器）、桌面 App（Tauri）起后台或子窗口，都不在 ban 和启动锁的范围里，也不走门控。
     - **别的进程里的 fork**：锁只在后台/aw 进程内有效，管不到别的进程。
     - **不是我们起的程序**：`attach --pid` 附着的现有进程、它的子孙，启动契约一概不管（它们本来就不是我们起的）。
     - Windows 上依赖用 `CreateProcess` 且 `bInheritHandles=TRUE` 起程序时，会继承我们所有可继承句柄——所以规矩 1 要求我们自己的句柄一律不可继承，只在 HANDLE_LIST 里临时给子进程。
3. **fork 和 exec 之间只做异步信号安全的事**：
   - argv/envp 的指针数组（NULL 结尾）在父进程里准备好，子进程只读，不再 `collect()`；删掉 `clear_preload`；删掉假测试 `caller_preload_is_absent_before_exec`，换成比对**完整集合**的环境测试（见文末「启动程序时的环境变量」）：目标跑 `/usr/bin/env`，后台起的程序输出正好是 HOME、USER、LOGNAME、SHELL、PATH 加请求给的那几项；`aw run` 默认模式和 `--no-daemon` 输出跟 aw 自己的环境（加请求项）完全一样。原来两条「请求只给 `AW_RV=1`，输出正好一行」的老测试是按「环境从零开始、什么都不给」写的，跟 PM 13:44–13:47 的决定冲突，**改成上面这两条**，不再断言只有一行。
   - 子进程里只允许：close/close_range、dup2、fcntl、setpgid、setsid、setgroups、setgid、setuid、get*id、chdir、sigaction、sigprocmask、read、write、execve、_exit、prctl（Linux）。
   - execve 之前把 1..NSIG-1 的信号处理全部 `sigaction` 成 SIG_DFL，`sigprocmask(SIG_SETMASK, 空集)`，目标的 SigIgn / SigBlk 都是 0（修 SIGPIPE 继承，Linux/Mac 一致）。
   - **报错管道**：再建一根 CLOEXEC 的报错管道，子进程哪一步失败（建管道、切身份、自检、chdir、execve）就写「步骤 + errno」再 `_exit`；父进程放行后读到 EOF = exec 成功，读到数据 = 失败原因。121-127 这些码只进日志，不再冒充程序退出码。
   - release 写失败时 pid 不丢：当场 `waitpid`，再按报错管道的内容返回带步骤的错误（「找不到工作目录「路径」」等，A5 表）。
4. **切身份**：顺序 fork → setgroups → setgid → setuid → 自检 → chdir → 堵在门控上等放行 → execve。文档三处按这个顺序改。
   - **附加组一律由后台按用户重新加载**：Linux 和 Mac 都用 `launch_as::login_groups`（`getgrouplist`）在**父进程里**算好传进去，**不用连接方报上来的组**（Linux SO_PEERCRED 本来就拿不到附加组，Mac 永远是 None）。**Mac 照 initgroups 的语义加载**（PM 13:47 已定，不截断也不拒绝）：组列表在 fork 之前用 `getgrouplist` 解析（缓冲区不够就加大重试），子进程里只做系统调用，不做任何查询；macOS 上用带 gmuid 的 `initgroups` 系统调用开启动态成员解析，或者用准备好的列表 `setgroups`。系统仍然只给一部分时记日志、doctor 如实显示。细节见文末「Mac 附加组超过 16 个」。Linux 同样按 `getgrouplist`，不用 `/proc/<pid>/status` 的 `Groups:`（c21dcec 剩下的第 2 处）。
   - 自检：`getuid/geteuid/getgid/getegid` 都对，`setgid(0)` 和 `setuid(0)` 都必须失败，不对就按「切身份失败」退出。
   - **程序名怎么找（PATH，review 挡 2 + PM 定）**：execve 不查 PATH，`execvp` 又不是异步信号安全的，所以分两半做。**挂住启动（`unix/hold.rs`）和 Linux root 后台的 helper（dev `aw-daemon/src/api/launch_as.rs:216` 起的 `spawn_as`，helper 副本里 exec 目标）这两条路调同一个查找函数** `aw_platform::program::candidates(name, cwd, path) -> Vec<CString>`，不各写一份；helper 那条路跑同一组 PATH 测试。
     - **用哪个 PATH**：后台替人起的程序一律用固定的 `DEFAULT_PATH`（dev `launch_as.rs:54-55`）。请求里**不能**给 PATH（PM 定，给了就 400 `env_reserved`，见文末「启动程序时的环境变量」），所以查找永远不受请求影响。aw 自己起的程序（默认模式、`--no-daemon`）用 aw 的 PATH。
     - **工作目录一律是绝对路径**：相对的工作目录由调用方（aw、App）先换成绝对路径再发给后台；后台收到相对路径直接 400 `bad_request`（这是客户端的 bug，不是用户写错），不替它拼。没给工作目录时按目标用户的 HOME。
     - **父进程只拼候选列表，不碰文件系统**（不 `stat`、不 `access`、不 `canonicalize`）：
       - 程序名是绝对路径：只有它自己一个候选；
       - 程序名带 `/` 但不是绝对路径（`./x`、`bin/x`）：候选是「目标的绝对工作目录 + 名字」这一个，不再查 PATH（子进程是先 chdir 再 execve，但这里拼成绝对路径，不依赖 chdir 有没有成功）；
       - 程序名不带 `/`：把 PATH 按 `:` 拆开，**空项、`.`、所有相对目录项一律跳过**（不当成当前目录，防「工作目录里放一个同名程序就被运行」），剩下的绝对目录每项拼上程序名，做成 C 字符串数组在 fork 之前备好；一项都不剩时直接报 `program_not_found`，不 fork。
     - **子进程在切完身份之后挨个 `execve`**：返回 ENOENT/ENOTDIR 就试下一个；EACCES 记下来接着试；全都失败时，报错管道写「找不到程序」（全是 ENOENT/ENOTDIR）或「没有权限」（碰到过 EACCES），父进程回 400 `program_not_found` 或 403 `program_not_permitted`（都是 `daemon_errors.rs` 里已有的码，码名不改；不再静默 127）。`program_not_permitted` 按 UI-147-wording.md 14:30 补拆成程序、工作目录两句（码名不改，按报错管道里失败的那一步选句，见 B1 码表）。
     - **root 后台从不以 root 身份去看调用方的目录**：现在 dev `hold.rs:201-224` `resolve_program` 在父进程里（root 身份）按 PATH 找文件，会让 root 替调用方去看它自己看不了的目录（能用来探测别人目录里有没有某个文件），也会在「找的时候」和「exec 的时候」之间被换掉。改掉后所有判断都在目标用户身份下由内核做。**这一处提前到第 0a 步**，不等第 4 步。
     - **Windows**：同一个查找函数的 Windows 版。程序名没有后缀时按 PATHEXT 补后缀；**后台替人起的程序 PATHEXT 用固定的默认值 `.COM;.EXE;.BAT;.CMD`**，不用请求里给的，也不用后台自己的环境；PATH 同样跳过空项、`.` 和相对项，不先查当前目录（不照 `CreateProcess` 的默认顺序，也不用 `SearchPathW` 的「先当前目录」）。查到的是 `.cmd`/`.bat` 时**必须**走 `cmd.exe /c`，参数按规矩 10 逐个转义；**参数里有 CR 或 LF 就拒绝**（`cmd` 没法安全转义换行，345d216 已经这样做，这里写成规矩）。
     - 测试：
       - （root CI）PATH 里第一项是只有 root 能进的目录（`0700 root`），里面放一个同名程序，第二项是用户自己的目录 → 跑的是第二项那个；PATH 里只有那个 root 目录 → 报「找不到程序」，不是跑了 root 那个；程序名带 `/` 指到只有 root 能读的文件 → 报 `program_not_permitted`；
       - PATH 带空项和 `.`（`:/usr/bin:.`），工作目录里放一个同名的可执行文件 → **不会运行它**（三系统）；
       - `./x` 和 `bin/x` 按目标工作目录解析，跟后台自己的工作目录（`/`）无关；后台收到相对工作目录 → 400；
       - Windows：`foo` 只有 `foo.cmd` 时补出 `.cmd`、走 `cmd /c`；参数里有换行 → 拒绝、没有起任何进程；请求里给了 PATHEXT=`.JS` 也不生效；
       - helper（`launch_as::spawn_as`）那条路跑上面同一组 Unix 测试。
5. **挂住期间**：创建方（aw 或后台）一死，子程序必须退出，而且目标程序一行都没跑过。Unix 靠门控管道读到 EOF 后 `_exit`（规矩 1 保证没有别人拿着写端，所以 EOF 不会被拖），Windows 靠 Job 的 `KILL_ON_JOB_CLOSE`。
6. **放行以后谁来收尾**——**只有起程序的是 aw 时（`aw run` 默认模式和 `--no-daemon`），才把程序跟 aw 绑在一起；起程序的是后台时一律不绑**，后台崩了程序照样跑，会话标成「记录已中断（后台重启）」。
   - 绑定由一个**看门进程**来做，不指望 aw 自己（aw 被 SIGKILL 后一行代码都跑不了）：
     - **Linux（决定，PM 14:04 + review：看门进程就是 subreaper，有没有 cgroup 都一样）**：
       - **进程关系：aw → 看门进程 → 程序**。aw `fork` 后马上 `execve` 自己的二进制进 `aw __no-daemon-watchdog` 子命令（`/proc/self/exe`，管道 fd 用参数传入），所以看门进程是一个全新的单线程进程，可以正常分配内存、读 `/proc`。看门进程**在起程序之前**先 `prctl(PR_SET_CHILD_SUBREAPER, 1)`，然后由它（走 A1 规矩 1–4 的同一个启动函数）起程序。subreaper 只收养**自己的子孙**，所以看门进程必须是程序的祖先，不能像现在这样跟程序做兄弟（见文末 345d216 的说明）。程序和它的所有子孙，不管自己 `setsid`/`setpgid` 了多少次、中间那一层先退出了多少次，变成孤儿时都会被挂到看门进程名下，而不是挂到 init。
       - **看门进程不跟 aw 一起死**：它要比 aw 活得久，才能在 aw 被 SIGKILL 之后做清理。它通过两条线知道 aw 死了：aw 留给它的一根「存活管道」读到 EOF（主要），加上 `PR_SET_PDEATHSIG(SIGUSR1)` 当后备（信号处理函数只置一个标志）。PDEATHSIG 的坑照上面一条处理（fork 看门进程必须在 aw 的主线程里做；设完马上查 `getppid()` 是不是还是 aw）。
       - **看门进程自己在单独的进程组里，不在程序的组里，也不在 aw 的组里**（`setpgid(0, 0)`），并且忽略 SIGINT、SIGQUIT、SIGHUP、SIGTSTP、SIGTTIN、SIGTTOU。这样终端里按 Ctrl+C 只会打到前台组（程序的组），终端挂断和 shell 给作业组发的 SIGHUP 也打不到它。不在终端里时，看门进程直接 `setsid()`，自成一个会话。**在终端里时不能 `setsid`**：`tcsetpgrp` 只能把前台交给同一个会话里的进程组，看门进程要是换了会话，它起的程序就永远拿不到 aw 那个终端的前台。所以在终端里时是「同一个会话，单独的进程组」，这一点已经能满足「Ctrl+C 和组 SIGHUP 杀不到它」。aw 死后看门进程所在的组会变成孤儿进程组；只有组里有被停住的进程时内核才发 SIGHUP+SIGCONT，看门进程不会被停住，而且也忽略 SIGHUP。
       - **退出码**：看门进程 `waitpid(程序, WUNTRACED | WCONTINUED)`，把结果从「状态管道」报给 aw：`exited N`、`signaled N`、`stopped N`、`continued`。aw 照原样退出：`exited N` 时退 N，`signaled N` 时退 128+N（SIGINT → 130，SIGTERM → 143）。启动时看门进程先报一行 `started <pid> <启动时间>`，aw 拿到程序的进程号是为了 `tcsetpgrp` 和显示，**不是为了自己发信号**。
       - **转发信号**：aw 照旧接 SIGINT、SIGTERM、SIGHUP（默认模式和 `--no-daemon` 一样），把信号号写进「控制管道」，由**看门进程**去 `killpg(程序的进程组, 信号)`。看门进程是程序的父进程，程序没被它 `wait` 之前，进程号不会被回收复用，所以这样发信号不会打错进程。aw 自己不直接对程序发信号。
       - **终端前台（tcsetpgrp）**：程序的进程组跟 aw 在同一个会话里，所以 aw 照规矩 7 用 `tcsetpgrp` 把前台交给程序的组（前后都挡住 SIGTTOU）。Ctrl+Z 时，看门进程用 WUNTRACED 看到 `stopped`，报给 aw；aw 把前台拿回给自己的组，再给自己发 SIGTSTP 停下。`fg` 时 shell 给 aw 的组发 SIGCONT，aw 把前台再交给程序的组，并通过控制管道让看门进程 `killpg(SIGCONT)`。看门进程在自己的组里，不会被 Ctrl+Z 停住。aw panic 或因信号退出时照样先还前台（规矩 7）。
       - **看门进程自己意外死了**：aw 也设 `PR_SET_CHILD_SUBREAPER`，所以程序会被挂回 aw 名下。aw 读到状态管道 EOF、又没收到最后的状态时，自己接手：`waitpid` 程序，再按下面同样的循环做清理，同时报「看门进程意外退出」。
       - **清理循环**（程序退出以后、aw 正常退出以后、aw 被杀以后，都会跑一遍，所以 `--no-daemon` 的「aw 一退出，程序和它启动的子程序都会跟着结束」三种情况都成立）：
         1. 扫一遍 `/proc/*/stat`，按 ppid 找出看门进程的所有子孙。因为它是 subreaper，孤儿都已经挂到它名下了，所以这样找不会漏掉 `setsid` 出去的那些；
         2. 先给每一个子孙发 **SIGSTOP**，冻住，让它们没法再 fork。然后重新扫描，新冒出来的接着 SIGSTOP，一直扫到某一轮没有新的为止，所以一直 fork 的子程序也压得住；
         3. 再给所有子孙发 **SIGKILL**，用 `waitpid(-1, WNOHANG)` 把挂到自己名下的都回收掉；
         4. 重新扫描，回到第 1 步，直到 `waitpid` 返回 ECHILD、而且扫描结果为空。有上限：总共 5 秒；到点还有剩下的，把剩下的进程号和命令名写进日志，aw 报「还有 N 个子程序没能结束」，退出码不变。
       - `aw __no-daemon-watchdog` 是隐藏子命令：clap 里 `hide = true`，不出现在 `aw --help`，帮助快照里断言它不出现。
       - 解析 `/proc/<pid>/stat` 时，命令名可能带空格和括号，**从最后一个 `)` 往后切字段**（ppid 是 `)` 后第 2 个字段，启动时间是第 20 个），加单元测试（命令名是 `a) b (c`）。
       - **防进程号复用（发每一个信号之前都核对）**：每个目标记成（pid、ppid、启动时间），启动时间是 `/proc/<pid>/stat` 第 22 列。发信号前重新读一遍，三项有一项对不上就跳过（说明原来那个进程已经没了，号被别人用了）。内核支持（5.3 及以上）时优先用 `pidfd_open` + `pidfd_send_signal`，它本身就不会打到被复用的号上；（pid、ppid、启动时间）这一套是不支持时的退路，也是第 1 步扫描时判断「是不是我的子孙」的依据。
       - **管不到的**：子孙换成了别的用户（比如程序里跑了 `sudo`、setuid 程序）以后，普通用户身份的看门进程发不出信号。这种情况记日志，aw 报「还有 N 个子程序没能结束」，不说成已经清掉了。有可委派的 cgroup v2 时，额外再写一次 `cgroup.kill` 兜底，但**不依赖它**。
     - Mac（watchdog + kqueue，**唯一的例外**）：看门进程用 kqueue `EVFILT_PROC` + `NOTE_EXIT` 盯 aw 的 pid，aw 一死就 `killpg` 整组。macOS 没有 subreaper，清不到自己 `setsid`/改了进程组的孙程序，所以 Mac 的 `--no-daemon` 帮助单独一句（规矩 11）。
     - Windows：靠 Job Object。aw 持有一个带 `KILL_ON_JOB_CLOSE` 的 Job，不允许 breakaway，覆盖整棵树（包括自己另起进程组的）；aw 死了句柄关闭，整棵树结束（接第 6 步；345d216 已经这样做）。
   - PDEATHSIG 的三个坑写进实现注释并各有测试：setuid 会清掉它，所以要在切完身份**之后**再设；设完马上查 `getppid()` 是否已经变了（父进程可能先死）；它跟的是**发起 fork 的那个线程**，fork 看门进程要在活得跟 aw 一样长的线程（主线程）里做。
   - 信号：默认模式下 aw 收到的 SIGINT、SIGTERM、SIGHUP 原样转发给程序的进程组，跟 `--no-daemon` 一样（Linux 经看门进程转发，见上）；aw 的退出码 = 128+信号号（SIGINT → 130）。`ProcessGroupForwarder` 每 10ms 醒一次（`run.rs:1049`）改成阻塞等信号。
   - 能保证的范围：**Linux（有没有 cgroup v2 都一样，靠看门进程当 subreaper）和 Windows（Job）都保证程序和它的所有子孙**跟着结束，包括自己 `setsid`/`setpgid` 出去的、中间那一层先退出留下来的；例外只有两种：子孙换成了别的用户（`sudo` 一类），记日志并如实报「还有 N 个子程序没能结束」。**Mac 是唯一的例外**：只保证直接子程序和留在同一进程组里的孙程序，脱离进程组的孙程序不保证——这是唯一一处「这个系统不支持」。
7. **终端前台**（Linux 和 Mac 的 `aw run` 默认模式、`--no-daemon` 都要覆盖。Linux 默认模式也一样：c21dcec 以后 Linux 默认模式走 `hold.rs`，程序同样在自己的进程组里，`launch/unix_linux.rs:756` 的 `process_group(0)` 也是，所以 Linux 默认模式同样会卡在 SIGTTIN，不能只修 Mac）：
   - 在终端里时，子程序进程组用 `tcsetpgrp` 设成前台；aw 调 `tcsetpgrp` 前后**挡住 SIGTTOU**（否则 aw 自己在后台组时会被停住）。
   - aw 用 `waitpid(…, WUNTRACED)` 看到子程序被 Ctrl+Z 停住时：把终端前台拿回给自己原来的组，再给自己发 SIGTSTP 停下；`fg` 后（SIGCONT）把前台再交给子程序组并 `killpg(SIGCONT)`，不卡住。
   - 正常结束、aw 因信号退出、**aw panic**（panic hook 里）都把前台还给原来的组。
   - **aw 被 SIGKILL 或直接崩掉时，由看门进程还前台**：aw 起程序时把「原来的前台组号」和终端 fd 交给看门进程（Linux 是规矩 6 的 subreaper 看门进程，Mac 是 kqueue 看门进程；两者在终端里时都跟 aw 同一个会话，所以有权 `tcsetpgrp`）。看门进程发现 aw 死了以后，**先**检查终端前台是不是还是程序的组，是的话挡住 SIGTTOU、`tcsetpgrp(终端, 原来的前台组)`，**再**跑清理循环。原来的组已经不存在时（比如 shell 也没了）就不还，只做清理。测试：pty 里起 `sh -c 'read x'`，SIGKILL aw，pty 的前台组变回 shell 的组，shell 能接着读输入。
   - 不在终端里时保持单独的进程组，不调 tcsetpgrp。
8. **出错怎么报**：每一步各有自己的错误码，从报错管道回传，用户看到的是 A5 表里的中文。
9. **等待一律有上限**（Windows 973 行改掉）。超时是出错，用定稿的两句超时错误报，不用「不可得」：等程序结束超时报「等了 {N} 秒，程序还没结束」；等后台回复超时报「后台 {N} 秒没有回应，这次请求没有完成。」（码 `daemon_timeout`，见 B1 码表）。
10. **`.cmd` / `.bat`**：不管是用户直接写的 `x.cmd`，还是规矩 4 按 PATHEXT 补出来的，都走 `cmd.exe /c`，每个参数按 cmd 的规矩逐个转义（`"`、`&`、`%`、`^`、`|`、`<`、`>` 这类）；**参数里有 CR/LF 一律拒绝**，不尝试转义。
11. **`--no-daemon` 帮助**（以 `UI-147-wording.md` 为准）：**Linux 在「孙程序自己 setsid」那条测试（规矩 6 测试第 1 条）在 dev 上通过之前，用 14:17 的临时句**「不经过后台，直接运行程序，不做记录；`aw` 一退出，程序和它启动的子程序会跟着结束。机器上没有可用的 cgroup v2 时，子程序要是自己脱离了进程组，不保证会跟着结束。」；那条测试在 dev 上绿了，**同一个提交**里把 Linux 帮助换成统一那句、更新 Linux 帮助快照。**统一后 Linux 和 Windows 用统一那句**「不经过后台，直接运行程序，不做记录；`aw` 一退出，程序和它启动的子程序都会跟着结束。」——Linux 靠看门进程当 subreaper（有没有 cgroup 都成立），Windows 靠 Job。**Mac 单独一句**（13:51 更正）：「不经过后台，直接运行程序，不做记录；`aw` 一退出，程序和它启动的子程序会跟着结束。子程序要是自己脱离了进程组（比如在后台另起服务），在 Mac 上不保证会跟着结束。」帮助快照按系统分开存，各自断言原文。

**共用测试**（`aw-platform/tests/launch_contract.rs` + 已写好的 `aw-platform/tests/gate_concurrent_spawn.rs`，三个系统的 CI 都跑）：
- **并发泄漏**：48 线程 × 20 轮（CI 默认），`AW_GATE_STRESS_ROUNDS=300` 做压力；每个子程序 `/proc/self/fd`（Mac 用 `lsof -p`/`proc_pidinfo`，Windows 用句柄表）里只有白名单。修前失败率 30.3%（泄漏）+ 67.8%（退 2），修后 0/14400，见 H1；
- **fd 号 ≥ 10 的门控**：`gated_spawn_works_when_the_gate_fd_number_is_ten_or_more`；
- **挂住阶段**的 `/proc/<pid>/fd` 也只有白名单；A、B 同时挂着时只中止 A，A 在 100ms 内退出；
- 挂住时杀掉创建方，目标程序没执行过；
- 目标的 SigIgn、SigBlk 都是 0；目标环境跟规矩 3 那两条完整集合一模一样（后台起的、aw 起的各一条，取代原来「正好一行」的两条老测试）；
- PATH：规矩 4 那三条 root CI 测试；附加组：用户属于 20 个组时，Mac 上目标看到的组跟 `id -G <用户>` 一样（Mac CI 用 `dscl` 建测试用户），Linux 上跟 `getgrouplist` 一样、不跟连接方在连上后 `newgrp` 改出来的组；
- **40 路并发启动零失败（验收项）**：临时 root 后台上 40 个 `aw run -- sh -c 'exit 3'` 同时起、连跑 10 轮，400 次全部退 3，没有一次失败或卡住；dev tip 上已测 400/400（H3），脚本 `/workspace/aw-prove-out/run40.sh` 进 `scripts/perf/`；
- cwd 不存在：release 返回「工作目录」类错误，`/proc/<pid>` 不是 Z；
- 切身份自检：egid 不对、`setgid(0)` 成功都会退出（root CI 跑）；附加组等于 `getgrouplist` 的结果而不是连接方报的；
- **aw 起的程序**：放行后用 SIGHUP / SIGTERM / SIGKILL 杀 aw，直接子程序和**同一进程组里**的孙程序 2 秒内都没了（三个系统都断言）；Linux 和 Windows 上**自己 setsid 出去的孙程序也没了**（Linux 不依赖 cgroup）；Mac 只断言同组的；
- **Linux 看门进程（subreaper）**，`aw-cli/tests/no_daemon_tree.rs`，Linux CI 跑。每个用例结束后，用测试打在环境变量里的标记（`AW_TREE_TAG=<随机值>`）扫 `/proc/*/environ`，断言**一个带这个标记的进程都没有了**：
  - 孙程序自己 `setsid` 出去（`sh -c 'setsid sleep 600 & wait'`），然后 SIGKILL aw → 2 秒内孙程序没了；
  - 子程序一直在 fork（`while :; do sleep 600 & done` 这类，加上进程数上限防止把 CI 压垮）→ aw 退出后 5 秒内全部没了，看门进程自己也退出了；
  - 中间那一层先退出、留下孙程序（`sh -c '(setsid sleep 600 &) ; exit 0'`），然后 SIGKILL aw → 孙程序没了（它已经挂到看门进程名下）；
  - aw 分别以正常退出、SIGINT、SIGTERM、SIGHUP、SIGKILL 结束，每一种都没有子孙留下；
  - 退出码转交：程序 `exit 7` → aw 退 7；程序被 SIGTERM 杀 → aw 退 143；
  - pty 里按 Ctrl+C：程序收到 SIGINT，看门进程没死，最后照样报出程序的退出状态；关掉 pty 主端（终端挂断）→ 没有子孙留下；
  - pty 里 Ctrl+Z 再 `fg`，在 aw → 看门进程 → 程序这种关系下程序照常继续，aw 不卡；`sh -c 'read x'` 能读到输入；
  - SIGKILL 看门进程 → 程序挂回 aw，aw 照样报出退出码，并且做清理；
  - 防复用的单元测试：喂一份假的 `/proc` 表，同一个 pid 但启动时间不同，那一项会被跳过、不发信号。
- **后台起的程序**：后台被 SIGKILL，已放行的程序还在跑，会话标成「记录已中断（后台重启）」；
- pty 里跑 `sh -c 'read x'` 能读到输入（Linux + Mac，两种模式）；pty 里 Ctrl+Z 再 `fg`，程序继续、aw 不卡；aw panic 后终端前台还回来了；
- SIGINT 退出码 130；默认模式信号转发；
- `.cmd` 带特殊字符的参数；
- `--no-daemon` 帮助快照：Linux、Windows 是统一那句，Mac 是 Mac 那句。

| 问题 | 来源 | 状态 | 进哪个提交 |
|---|---|---|---|
| Linux 并发启动门控读端泄漏 + fd≥10 时 dash 退 2（command_spawner_* 偶发失败） | Coding 自查 / PM | **已证实，证明工作区已修**（H1） | 第 4 步（修法 + 压力测试直接拿过去） |
| `command_spawner_*` CI 失败的原始断言 | review 要补 10 | 没拿到 CI 日志 | 第 4 步前由 Test-bot/PM 贴一次 |
| Mac 挂住阶段重新执行自己、ECHILD | review（7569421）/ CI | 95b49ff 已修 | — |
| Mac 子进程里分配内存、unsetenv；假测试 | review（95b49ff 挡 1、收 5） | 没修 | 第 4 步 |
| Mac 放行失败留僵尸、失败码丢失 | review（95b49ff 挡 2） | 没修 | 第 4 步（报错管道） |
| 文档三处顺序写反 | review（95b49ff 挡 3） | 没修 | 第 −1 步（文档先改） |
| 挂着的子进程拿着别人的写端；pipe_cloexec 非原子 | review（95b49ff 收 1）/ PM 13:13 | 没修 | 第 4 步（关 fd 循环 + 马上 FD_CLOEXEC） |
| 目标继承 SIGPIPE 忽略 | review（95b49ff 收 2） | 没修 | 第 4 步 |
| Mac 附加组永远 None、程序名不解析 | review（95b49ff 收 3） | 没修 | 第 4 步 |
| 自检少查 getegid / setgid(0) | review（95b49ff 收 6） | 没修 | 第 4 步 |
| Linux 换 hold.rs 后附加组从哪来 | review 挡-4 | 设计已定（规矩 4） | 第 4 步 |
| Mac root 阶段环境注入 | review | 8addcfe 已修 | — |
| Windows 缺标准句柄、提前返回泄漏句柄 | review（ef6c11d） | 3d95803 已改，没上真机 | 已推 |
| Windows 等待没有上限（973 行） | review | 没修 | 第 6 步 |
| aw 被强杀后孤儿（三个系统），看门进程 | PM 真机 / Test-bot E / review 挡-3 | 设计已定（规矩 6） | 第 4 步（Windows Job 部分第 6 步） |
| 后台起的程序不能绑后台 | review 挡-3 | 设计已定 | 第 4 步（测试） |
| 默认模式不转发 SIGINT/SIGTERM/SIGHUP | Test-bot E | 没修 | 第 4 步 |
| `--no-daemon` / Mac `aw run` 卡住要读终端的程序 | review（2511990 必改 2、95b49ff 收 4） | 设计已定（规矩 7，含 SIGTTOU、WUNTRACED、panic） | 第 4 步 |
| `--no-daemon` 帮助（Linux/Windows 统一句，Mac 单独一句） | UI审查+review 13:25 / 13:51 | 没改 | 第 4 步（帮助快照在第 8b 步） |
| `.cmd` 找不到 / 转义 | PM 真机 | 没修 | 第 6 步 |
| 缺「信号杀掉」「SIGINT」测试、Mac 转发测试 | review | 没写 | 第 4 步 |
| c21dcec 剩下的：没用 pipe2、附加组用连接方报的、子进程里分配 | review（c21dcec） | 没修 | 第 4 步 |
| root 后台以 root 身份按调用方 PATH 找程序（`resolve_program`） | review | 设计已定（规矩 4） | 第 4 步 |
| 采集 crate 直接起 `id`/`whoami`/`netstat`/`tcpdump`；依赖起进程没人查；tokio process feature | review | 设计已定（规矩 2） | 第 4 步 |
| Linux 默认模式也会卡终端；aw 被杀后没人还前台 | review | 设计已定（规矩 7） | 第 4 步 |
| 两条「环境正好一行」老测试跟环境决定冲突 | review | 设计已定（规矩 3） | 第 4 步 |
| 40 路并发启动零失败 | PM | dev tip 400/400（H3） | 第 4 步（进 CI 的缩小版：10 路 × 5 轮） |

## A2. 一问一答：一次请求从开始到结束

**根本原因**：「一次请求什么时候算结束、处理期间能占住什么」从来没定义过。所以有的地方靠对面断开来判断结束，有的地方两头超时各定各的，有的请求在一把全局大锁里等库锁，有的回复写不回去也没人管。
- `aw-daemon/src/api/ipc.rs:681-691` `finish` 把裸句柄交给 `spawn_blocking` 去 flush。外层 `IO_TIMEOUT` 30 秒（487、**577** 行）到点取消时，`pipe` 已经被释放，flush 线程还拿着句柄（可能已关闭，甚至被复用）。客户端连上不读，flush 就一直不返回。`DisconnectNamedPipe` 已在 4e6b68a 去掉。
- 半截回复被当成完整回复：`aw-channel/src/lib.rs:524` `Ok(0) => return Ok(out)`；回复大小没上限；Unix 没有总超时；分帧测试只在 Windows 上跑。
- **Unix 也会被「只连不读 / 慢慢发」卡住**：Unix 服务端每个连接起一个线程，线程数没有上限（`ipc.rs:363-374`）；超时只管单次读写（`ipc.rs:413-414`），没有总时限，对面每 29 秒发一个字节就能一直占着。
- **两头超时不一致**：命令行等 5 秒（`aw-cli/src/client.rs:320`），后台等库锁 8 秒（`aw-store/src/connection.rs:15`）。命令行先放弃，后台照样建出会话、回 201，结果写进 Broken pipe。
- **附着慢（已证实，数字见 H2；原来写的「同步扫整机进程表」是错的，扫描在所有组里都只有 13–120ms）**：慢在库这一侧，是三件事串起来的：
  1. **FTS 写入每行先做一次全表扫描**：`aw-store/src/fts.rs:103-123` `upsert` 在 INSERT 之前先 `delete`（110 行，`DELETE FROM fts_text WHERE src=?1 AND src_id=?2`，127-133 行）。`src_id` 在 fts5 里是 UNINDEXED 列，这条 DELETE 每次都扫整张 `fts_text`。200MB 库里 `fts_text` 约 22.7 万行，每次约 65ms；采样器每写一批进程映像（整机会话一批约 433 行，`sink.rs` `write_images` → `fts::upsert`）就是 433 次全表扫描，一个写事务占住 SQLite 写锁最长测到 **24.8 秒**。**这是唯一随库大小增长的一步。** 新插入的映像根本不可能已有 FTS 行，这次 DELETE 是白做的。
  2. **库写锁**：附着的 `insert_session`（`watch_routes.rs:216-238`）要在 `BEGIN IMMEDIATE`（`sink.rs:419-423`）上等这个写锁，最多 8 秒（`connection.rs:15`），所以 `write_session_row` 测到 5.2–7.2 秒或直接 busy。
  3. **全局大锁**：`ipc.rs:140-150` 每个请求（除导出）都在 `state.lock()` 里处理，包括上面这 8 秒库锁等待。前一个附着在锁里等库，后一个附着就在 `state.lock()` 上排队（测到 2.8–5.7 秒）。
  - 什么时候会踩到：库大（FTS 行多）**并且**有整机会话在采样（`attach --pid 1` 自己就是一个；Test-bot 说的「`sudo attach --pid 1` 留下停不掉的整机会话」会一直跟着抢锁）。Test-bot 的「大库附着单个进程 5 秒」在同样条件下复现了 5/5（H2 的 H 组）。只有大库、没有整机会话在写时，附着单个进程 1.06–1.20 秒（A 组），只有整机会话、库是空的时也正常（J 组）。
  - 已经排除的（计时为证）：开连接 `Store::open_runtime`（`migrate.rs:468-473`）在大库和空库上都是 0.6–2ms（个别 20–50ms 毛刺两边都有），不随库大小增长；`SqliteSink::new` 0.1ms；`MAX(id)` 走主键；扫整机进程表 13–120ms；打开时没有 integrity_check / VACUUM / FTS 重建。
  - 没测、留作候选的：会话列表每行现数 `session_counts`（`aw-store/src/query/mod.rs:487-489`、151-160）也在大锁里做，库越大越慢。这次测量没有同时刷列表，所以没有数字；改法里「读请求不进大锁」会一并消掉它。
- `--duration` 由命令行自己计时（`aw-cli/src/cmd/attach.rs:503-514` `thread::sleep`）。命令行一退出就没人去停这个会话。
- **`timeline --follow` 一行都不出**：`aw-cli/src/cmd/timeline.rs:104-139` 把结果攒在 `collected` 里退出时才打印；Windows 上 `interrupt_flag` 永远不会被置上（183-186）；后台 `/sessions/{sid}/live` 只发 retry 和 keepalive，`routes.rs:327` 注释写明「nothing calls this」。

**统一规矩**（写进接口文档「请求生命周期」一节，**跟第 5 步同一个提交或更早**，见 E 节第 −1 步）：
1. **按长度读完就算结束**。读到 EOF 但长度不够算出错（`DialError::Broken`）；回复上限 16 MiB；三个系统都有总超时。
2. **超时一张表**：客户端超时 = 后台最长处理时间 + 余量。**定为 12 秒**（跟 6a11d6d 已经推的代码一致，dev `aw-cli/src/client.rs:346` 现在是写死的 `Duration::from_secs(12)`；原来这里写的 15 秒作废）：规矩 6 以后一个请求最多只等一次库锁，`BUSY_TIMEOUT` 8 秒 + 4 秒余量够用。写成 `aw-core` 里的常量 `aw_core::timeouts::{BUSY_TIMEOUT, CLIENT_REQUEST_TIMEOUT}`（后者 = 前者 + 4 秒），`aw-store/src/connection.rs`、`aw-cli/src/client.rs`、App 的 IPC 客户端都引用它，不再各写一个数；超时那句里的 {N} 也从这个常量取。第 5b 步改。
3. **对面断了就撤回**：建会话、附着这类会写库的请求，回复写不回去时后台把刚建的会话撤掉或收尾成「附着失败」（`end_reason=attach_failed`），日志记英文原因。
4. **只有「取名字」放到回复之后**：没给名字时的 `attach_target_name_for_pid`（`watch_routes.rs:296-297` 扫整机进程表，314 行调用）挪到回复之后，扫完之前会话显示「正在读取进程…」。**`check_pid_owner`（`watch_routes.rs:164-176`，按 pid 读身份、核对主人）必须照旧在回复之前同步做完，不能一起挪走**（D1）。这条只是顺手优化，不是附着慢的根因。
5. **后台负责计时**：`--duration` 作为请求字段交给后台，到点由后台收尾。
6. **处理请求时不拿全局大锁去等库**：`ApiState` 的大锁只保护内存里的状态，持锁期间不做任何 SQLite 读写和进程表扫描；读请求（列表、show、timeline、stats）不进大锁；写库走自己的连接，锁等待上限 = 规矩 2 的 `BUSY_TIMEOUT`。
7. **写库不做全表扫描**：FTS 写入改成——新插入的行（`ON CONFLICT DO NOTHING` 之后 `changes()==1`）直接 INSERT，不先 DELETE；确实要更新或删除 FTS 行时按 rowid 删（加一张 `fts_map(src, src_id) → rowid` 带索引的映射表，或把 fts 的 rowid 定成由 `(src, src_id)` 确定的值），不再按 UNINDEXED 列 DELETE。证明工作区只做了前一半（新行直接 INSERT），已经足够把附着拉回 1.1 秒（H2）；后一半给改名、retention 删除用。另外每个采样写事务的时长写进日志，超过 1 秒记 warn。
8. **候选（第 5 步按测量决定做不做）**：后台常驻一个写连接、所有写入排一个队列，别再每 250ms（`sample.rs:50`、647-649）新开连接；列表计数改成按需算或预先算好。
9. **服务端每个连接都有读写期限和总时限**，三个系统都一样：单次读写有超时，**整次请求有总时限**（读完请求 ≤ 10 秒，防慢慢发）；同时在途的连接数有上限（建议 64），超了直接拒绝新连接；Unix 改成固定大小的线程池或 tokio，不再每连接一个无上限线程。Windows 上 flush 不再拿裸句柄，句柄生命周期由 `NamedPipeServer` 自己管（winpipe C）。
10. **`--follow` 改成轮询**：按游标定期查库里的时间线，每批立刻打印，会话结束就退出，Windows 上也能用。不写成「本版本未接入」，实时推送留到接管道那一包。

**测试**：
- Unix 和 Windows 都跑：半截回复报错、超大回复报错；**16 个只连不读的客户端、加 16 个每 29 秒发一个字节的客户端时，其他请求照样 200**（Unix 和 Windows 都跑）；连接数到上限时新连接被拒，旧连接不受影响；
- 命令行在请求中途被杀，带 `--duration` 的会话照样按时结束；
- **附着验收（按 review 挡-1 改过）**：同一个 200MB 库、同时有 2–3 个整机会话在采样时，`attach --duration 1s`（单进程和 `--pid 1` 各一组，各 5 次）总时间 ≤ 1.5 秒，`POST /sessions` 本身 ≤ 0.3 秒，跟空库一样；改前在同样条件下 5/5 超时（H2 的 H、B 组）。测试脚本 `/workspace/aw-prove-out/attach-timing2.sh` + `matrix*.sh` 进仓库 `scripts/perf/`；CI 里放一个缩小版（生成 5 万行 FTS 的库 + 1 个整机会话，断言 POST ≤ 0.3 秒、单个采样写事务 ≤ 1 秒）；
- 单元测试：`write_images` 写 N 行新映像时 FTS 不出现 `DELETE`（用 `sqlite3_trace` / `EXPLAIN QUERY PLAN` 断言没有对 `fts_text` 的全表扫描）；
- `check_pid_owner` 在回复之前：附着别人的 pid 仍然在 201 之前就拒；
- 回复写不回去时，库里没有一直开着的会话；
- `--follow` 每秒都有输出，会话结束后 2 秒内退出（Linux + Windows）。

| 问题 | 来源 | 状态 | 进哪个提交 |
|---|---|---|---|
| DisconnectNamedPipe 后客户端报断开 | review（624bb19） | 4e6b68a 已修，等 185fc77 的 Win CI | winpipe A |
| 句柄交给别的线程、30 秒取消后句柄失效 | review | 没修 | 第 7 步（winpipe C） |
| 只连不读 / 慢慢发 / 连接数没上限（**Unix 和 Windows**） | review / review 要补 7 | 没修 | 第 7 步（三个系统一起） |
| 半截回复当完整、没有大小上限、Unix 没有总超时、分帧测试只在 Windows 跑 | review（4e6b68a 第 7 条） | 没修 | 第 7 步（aw-channel 共用代码，三个系统一起） |
| 命令行 5 秒 < 后台锁等待 8 秒 | Test-bot（da57） | 没修 | 第 5 步 |
| 回复写不回去留下没人管的会话 | Test-bot / PM | 没修 | 第 5 步 |
| 附着 5–9 秒 / 超时：FTS 全表扫描 DELETE + 库写锁 + 全局大锁 | Test-bot / review 挡-1 | **已证实**（H2），证明工作区已验证修法 | 第 5 步（规矩 6、7） |
| 扫整机进程表只为取名字 | review | 已核实（只占 13–120ms） | 第 5 步（规矩 4，只挪取名字） |
| `--duration` 由命令行计时 | Test-bot / PM | 没修 | 第 5 步 |
| `daemon_timeout: read: operation would block` 英文漏给用户 | UI审查 | 没修 | 第 5 步（说法见 A5） |
| `timeline --follow` 不出东西、不退出、Windows 不能用 | review（2511990 必改 3）/ Test-bot C | 没修 | 第 9 步（按游标轮询） |

## A3. 数据要靠得住：每次写入都能安全重写，会话由后台收尾

**根本原因**：会话的结束和写入是不是完整，靠的是「这一次没出错」，不是靠规矩保证。
- `aw-store/src/sink.rs:53` 把每次事务限成 500 行，419-434 行逐块提交。中间某一块失败时，前面的块已经提交了，跟后面的重试会重复或者缺一截。da579f1 就是这样破坏了原子性。
- `aw-daemon/src/watch.rs:288-297` 的 `end()` 和 115-121 行的 `recover()` 都用 `let _ = conn.execute(...)` 把错误吞掉，结束状态写不进去也没人知道，会话就一直停在「录制中」。
- `--duration` 由命令行计时（见 A2）。
- 压力测试下 224 个会话里有 148 个一条进程记录都没有、187 个没记下根进程身份：大多是 `adopt_timeout`（`watch.rs:145`）。H2 已证实写锁会被一个采样写事务占住 16–25 秒，接管在这段时间里超时是同一个原因；要在第 5 步修完 FTS 以后用同一个压力脚本计数确认比例降下来。
- **FTS 写入不能安全重写**：`fts::upsert`（`fts.rs:103-123`）先按 UNINDEXED 的 `src_id` DELETE 再 INSERT，既慢（全表扫描，H2）又让「同一批写两遍」依赖一次全表扫描。改法见 A2 规矩 7（新行直接 INSERT、改/删按 rowid）。

**统一规矩**：
1. **行 id =（会话 id, 采样器, seq）**（PM 13:44 定，取代按内容哈希的做法；3.3 按 review 挡 4 改）。**新列叫 `sampler`，不叫 `source`**：`source TEXT NOT NULL` 这一列 dev 上已经有了（`0001_init.sql:58/77/112/142` 的 processes、process_images、net_flows、dns，还有 file_access、http、agent_events、agent_instances、ipc_channels、agent_rpc、agent_links），意思是「哪一类采集器给的」，原样不动。**每张表的 `id INTEGER PRIMARY KEY`（也就是 rowid）保留不改**，FTS 删除触发器靠它，SQLite 也改不了主键；行 id 用一个唯一索引 `UNIQUE(session_id, sampler, seq)` 表达，不重建大表。按表分三类（第 5b 步）：
   - **事件表（只追加）**：`process_images`、`dns`、`gaps`、`http`。加 `sampler`、`seq` 两列和上面的唯一索引，写入 `ON CONFLICT(session_id, sampler, seq) DO NOTHING`。整批重写时带的是同一批 seq，所以不会重复；内容完全相同的两个事件 seq 不同，照样是两行。
   - **实体表（同一个东西会被反复更新）**：`sessions`（`id`）、`processes`（`session_id, proc_uid`）、`net_flows`（`id`）、`file_access`（`id`）。冲突键还是现在的自然键；每行多两列：`sampler`（**这一行归哪个采样器更新**）和 `last_seq`（那个采样器最后一次更新它用的 seq）。合并**按列写**，不用整条语句的 `WHERE`：
     - **会变的列**（最后看到的时间、计数、状态）：`CASE WHEN excluded.last_seq > 表.last_seq THEN excluded.列 ELSE 表.列 END`。**相等就不更新**（严格大于），同一批写两遍结果一样；
     - **只写一次的列**（退出码、结束时间、可执行文件、父进程、SNI 这类）：**不管 seq 大小**一律 `COALESCE(表.列, excluded.列)`。这样 A 批（seq 100，带退出码）写失败、B 批（seq 200）先写进去以后，A 批重写时退出码照样能补上；
     - **不同采样器的 seq 永远不互相比**：每张实体表写清楚哪组列归哪个采样器。`sessions` 的行由后台（`daemon`）写，采样器只通过事件表报东西，不改 sessions 的列；`processes`、`net_flows`、`file_access` 的会变列只归这一行的 `sampler`（第一次写它的那个），别的采样器给同一行的数据只能走 `COALESCE` 补空列，不能改会变列；`excluded.sampler <> 表.sampler` 时 `last_seq` 不动。以后真要多个采样器改同一列，就按（采样器, last_seq）分开记，不在这一轮做。
   - **累计表**：`net_flow_buckets`（`flow_id, bucket_ns`）。现在 dev `sink.rs:851-856` 是 `bytes_up = 表.bytes_up + excluded.bytes_up`，同一批写两遍就加两遍。改成**采集端写这个桶到目前为止的总数**，库里一律 `bytes_* = MAX(表.bytes_*, excluded.bytes_*)`。同一个桶里的字节数只会涨，所以不管顺序、写几遍、**后台重启以后采集端从 0 重新累计**，库里的值都不会变小；不靠 `last_seq`。（同样的道理用在 `file_access` 的 opens/reads/bytes_* 上：dev `file_access.rs:199-215` 在 `partial = 1` 时做 `+=`，改成总数 + MAX。）
   - **其余 8 张表**（review 挡 4 漏洞 4）：
     - `http`：走分批写入（dev `sink.rs:576` `write_http`），归**事件表**，同上；
     - `file_access`：走分批写入（`sink.rs:565`），归**实体表**（计数列用 MAX，见上）；
     - `findings`：`upsert_finding`（`findings.rs:78-105`）不在 `write_all` 里，dev 上后台没有调用方（只有 `api/findings.rs:156` 直接 UPDATE 用户标记）。**不走分批写入，这一轮不受影响**；它的 `count = count + 1` 不能重写，等规则引擎接进来那一包，按实体表处理（引擎算总数后 MAX）。
     - `agent_events`：`store_agent_event`（`api/query.rs:1266`）一个请求一行、一个事务，**不走分批写入，不受影响**；
     - `agent_instances`、`ipc_channels`、`agent_rpc`、`agent_links`、`watch_groups`：`inter_agent.rs` 的 `store_*` 都是单行单事务，dev 上后台没有调用方，**不走分批写入，不受影响**。
   - **seq 怎么分（PM 14:31 + review 挡 4 漏洞 1）**：seq **在事件产生的那一刻**分配，写进事件本身，然后才进批；批不管重写多少次，带的都是事件里已经有的那个 seq。**写库那一层绝不分配 seq**：要是在写入时从计数表取号，重写的批会拿到一批新号，`ON CONFLICT` 挡不住，正好造成重复。
     - **计数器归后台，不归采样器实例**：后台内存里一张表 `HashMap<(会话 id, 采样器名), AtomicU64>`，采样器实例取号时按名字去这张表里拿。实例被重新建出来（attach 往已有会话里加进程、采样器出错后被重新拉起），后台没重启，计数器照样留着，接着往下数，老实例手里还挂着没写成功的批（号比库里的 MAX 大）也不会撞号。
     - **后台启动时**：每个（会话, 采样器）从 `max(seq_next.next, 各事件表 MAX(seq) + 1)` 接着数，两者不一致记 warn。后台重启以后，内存里没写完的批本来就丢了，库里没有那些号，再用到不会撞。
     - `seq_next(session_id, sampler, next)` 这张表**只是持久化的高水位**：跟这一批数据在同一个事务里推进到「这批最大的 seq + 1」，只用来让启动时不必扫各事件表求 MAX，**永远不是任何一行（包括重写的那一行）seq 的来源**。
   - **跟现有 `process_images.seq` 撞名**：这一列现在的意思是「同一个进程第几次 exec」（`UNIQUE(session_id, proc_uid, seq)`），跟行 id 的 seq 不是一回事。**迁移里改名为 `exec_seq`**（`ALTER TABLE … RENAME COLUMN`，唯一约束跟着改名），查询、导出、API 的 JSON 字段同步改成 `exec_seq`；API 里旧名 `seq` 再保留一个版本当别名，在接口文档里标「将删除」。行 id 那一列在所有事件表里统一叫 `seq`。
   - **迁移（0012）**，一个事务里做完：
     - `process_images.seq` → `exec_seq`；
     - 事件表加 `sampler TEXT NOT NULL DEFAULT 'legacy'`、`seq INTEGER`，按 `ROW_NUMBER() OVER (PARTITION BY session_id, sampler ORDER BY 时间列, id)` 补 seq（时间列：`process_images.ts_ns`、`dns.ts_ns`、`http.ts_ns`、`gaps.from_ns`），再建 `UNIQUE(session_id, sampler, seq)`；
     - 实体表加 `sampler TEXT NOT NULL DEFAULT 'legacy'`、`last_seq INTEGER NOT NULL DEFAULT 0`；按现有数据填好 `seq_next`；
     - FTS 重建一次，rowid 由 `(src, src_id)` 推出来（见下面 FTS 那条），三个删除触发器换成按 rowid 删；
     - `DROP TABLE replay_writes`。
     - 老会话的采样器一律 `legacy`，新事件不会再用这个名字。中途失败整个回滚，库还是 0011；
     - **实测**（207MB 库的副本，process_images 22.7 万行、processes 24.2 万行、fts_text 22.7 万行；探针 SQL `/tmp/aw-prove/mig0012-probe.sql`，sqlite3 3.46，跟后台同一台机器）：**整个事务 3.6 秒**，其中 FTS 重建 1.5 秒、提交 1.2 秒、补 process_images 的 seq 0.5 秒，其余都在 0.15 秒以内；`integrity_check` ok。超过 2 秒，所以**迁移时后台先不开接口**，CLI 和 App 连上来看到的是「正在升级」的状态，迁移完才开接口。这句话 wording 文件里还没有，**请 UI审查 定**。
     - 测试：拿一份 0011 的库迁到 0012，行数不变、`exec_seq` 等于原来的 `seq`、`replay_writes` 没了；迁移中途注入失败，库还是 0011 的样子，老版本程序照常打开；老版本程序打开 0012 的库时走「只读打开新版库」（`db_read_only_newer`）。
   - **`replay_writes` 去掉**（da00935 / 迁移 0011 加的按内容哈希的「已写过」表，dev `replay.rs`）：上面三类规矩各自保证重写不重复以后，它就多余了，而且它本身有毛病：内容相同的两个正常事件会被当成重复丢掉（跟「相同事件写成两行」冲突），每写一行多写一行，表只涨不缩，64 位 FNV 有碰撞的可能。删掉 `replay.rs` 和 `sink.rs` 里的 `replay::claim` 调用。
   - **FTS 搜索行跟主表一起写、一起删**（review 挡 4 漏洞 6）：
     - 主表这一行真插进去了才写搜索行（36abe45 已做）；
     - **fts 的 rowid 由 `(src, src_id)` 推出来**：`rowid = 来源编号 × 2^48 + src_id`（`process_images` = 1、`file_access` = 2、`http` = 3），写搜索行时显式给 rowid，删的时候 `DELETE FROM fts_text WHERE rowid = …`，走主键，不再按 UNINDEXED 的 `src_id` 扫全表。不另建映射表（省一次写）；
     - **0012 给 `http` 补删除触发器**（dev `http.rs:7-8` 自己写着 0005 没装），`file_access`、`process_images` 那两个（`0005_fts.sql:37-47`）换成按 rowid 删；
     - 实测（同一份 207MB 库）：**改前删 200 行 process_images 要 9.4 秒**（每行一次 fts 全表扫描，照这个速度删 1 万行约 8 分钟，一直占着写锁）；**改后删 1 万行 0.26 秒**，搜索行同步少了 1 万行。
     - 测试：删会话以后，按网址、按路径、按命令行都搜不到了；在 200MB 库上删 1 万行 ≤ 2 秒。
   - **测试**：
     - **同一批重写一遍（以及分块写到一半失败后整批重写），每一行的 seq 跟第一次完全一样，新增行数为 0**（断言两次写完后每张事件表的行数和 `(sampler, seq)` 集合都不变）；写库层没有任何分配 seq 的代码路径（构造一批不带 seq 的事件直接写，报错而不是补号）；
     - 内容相同的两个事件写成两行；
     - **采样器重建**：会话里第 1 个采样器实例有一批写失败、还挂着；建出第 2 个实例写一批；再把第 1 批重写一遍 → 两批的行都在，没有撞号；
     - **只写一次的列**：带退出码的那批晚于后面一批到达，退出码还在；同一批写两遍，会变列不变；
     - 不同采样器写同一行：后一个采样器的大 seq 不会覆盖前一个的会变列；
     - **流量**：同一批写两遍字节数不翻倍；后台重启以后还在同一个桶里，字节数不会变小；
     - 后台重启后 seq 从 `max(seq_next, MAX+1)` 接着数，不撞号。
2. **会话只由后台收尾**：结束写失败要记 error 并重试，下次启动时把留下的「录制中」统一标成「记录已中断（后台重启）」。
3. 旧库：只读打开比自己新的库（`db_read_only_newer`）；不是 WAL 的旧库先尝试转换，失败给中文提示；`db_busy` 按实际等待秒数映射。

**测试**：
- 分块写到第 2 块时注入失败，再重放整批，按 id 和按内容都没有重复，也没有缺；
- `end()` 注入写失败，重启后会话标成「记录已中断」；
- Test-bot 的 `dbintegrity.py` 压力脚本跑通，`adopt_timeout` 比例 < 5%；
- `retention::age_then_size_keeps_pinned_and_active` 变绿（6a11d6d 已修）。
- **Test-bot 对 6a11d6d 的回归项**（都进第 5b 步，每条一个测试）：
  1. **读不拿写锁**：列表、show、timeline、stats、导出只开读事务（`BEGIN DEFERRED`，不 `BEGIN IMMEDIATE`），有一个采样写事务占着写锁时，读请求照样 ≤ 0.3 秒返回；
  2. **小批写不排在大事务后面**：一次只写几行的（会话行、结束状态、缺口）不跟采样大批共用一个事务，单个采样写事务时长 ≤ 1 秒（超过记 warn）；
  3. **`Watches::end` 写失败要重试**：注入一次 busy，结束状态最终写进去了，不是吞掉；重试用尽时记 error，下次启动标「记录已中断（后台重启）」；
  4. **busy 报的秒数是真等了多久**：`db_busy` 里的 {N} 取 `waited_seconds`（实际等待），不是写死的 8；
  5. **只读打开新版库那句中文**：库比程序新时只读打开，CLI 和 App 显示 wording 文件里那一句（B1 码表的 `db_read_only_newer`），断言原文；
  6. **到时结束、出错结束的原因用中文**：结束原因 `duration`（`--duration` 到点）显示「到了设定的时长，已自动结束」，`error`（结束时写库失败）显示「记录已中断（写入失败）」（UI-147-wording.md 14:17 补）；两句都进 B1 码表，命令行和 App 用同一句，不露 `duration`、`error` 这种英文原因码，也不落到「不可得」或「已停止」；
  7. **`--duration` 从会话建好那一刻开始计**：不是从命令行发请求时、也不是从第一次采样时；测试：`attach --duration 2s`，`ended_at - created_at` 在 2±0.3 秒以内。

| 问题 | 来源 | 状态 | 进哪个提交 |
|---|---|---|---|
| 500 行分块破坏原子性 | review（da579f1） | 8fff164 本地已改，没推 | 第 5 步 |
| 会话结束写失败被吞掉 | review | 8fff164 本地已改 | 第 5 步 |
| `--duration` 由命令行计时 | Test-bot | 没修 | 第 5 步 |
| 148/224 个会话没有进程记录 | Test-bot | 待查 | 第 5 步 |
| 只读打开新版库 / 非 WAL 旧库 / db_busy 映射 | review | 8fff164 本地 | 第 5 步 |
| retention 测试 storage_full | Coding 推前检查 | 正在修 | 第 5 步 |
| PATCH 回复 pinned=null 时显示「没采」 | Test-bot B | 老问题 | DB 轮（PATCH 回复带上真实的 pinned 值） |
| FTS 写入每行全表扫描 DELETE（附着慢的根因） | Test-bot / review 挡-1 / H2 | **已证实**，证明工作区验证了一半修法 | 第 5 步 |
| `database_busy_tests::lock_past_busy_timeout…` Mac 失败（watch_routes.rs:932） | review（95b49ff CI） | 没修 | 第 5 步 |
| 行 id 只说了「会话, 来源, seq」，没分实体表 / 累计表；桶 `+=` 不能重写；`process_images.seq` 撞名；没有迁移方案 | review | 设计已定（规矩 1） | 第 5b 步 |
| 新列跟已有的 `source` 撞名；主键不能改 | review 挡 4 | 定了：新列叫 `sampler`，保留 `id`，加唯一索引 | 第 5b 步 |
| 采样器重建后撞号；整行比 `last_seq` 丢退出码；不同采样器的 seq 互比；重启后流量总数变小 | review 挡 4 | 定了：计数器归后台、按列合并、采样器各管各的列、MAX | 第 5b 步 |
| 其余 8 张表没归类 | review 挡 4 | 已归类 | 第 5b 步 |
| 0012 迁移占锁多久 | review 挡 4 | 实测 3.6 秒（207MB），迁移时先不开接口 | 第 5b 步（「正在升级」那句待 UI审查） |
| `http` 没有 FTS 删除触发器，删掉的网址还搜得到；另两个触发器按 UNINDEXED 列删、删 200 行 9.4 秒 | review 挡 4 | 定了：rowid 由 (src, src_id) 推出，三个触发器按 rowid；实测删 1 万行 0.26 秒 | 第 5b 步 |
| `replay_writes` 留不留 | review | 定了：去掉 | 第 5b 步 |
| Test-bot 6a11d6d 回归 7 条 | Test-bot | 设计已定（上面测试 1–7） | 第 5b 步 |
| 客户端超时 12 秒（代码）跟 15 秒（文档）不一致 | review | 定为 12 秒，进 aw-core 常量 | 第 5b 步 |

## A4. 安全和权限：先确认对方是谁，再给权限

**根本原因**：「确认对方是谁」和「这个目录可不可信」散在各个入口里，有的入口压根没确认，有的直接信了命令行、环境变量或路径字符串。
- `aw hook` 自己打开管道：`aw-cli/src/cmd/hook.rs:127` `OpenOptions::new().write(true).open(path)`，没设 SQOS，也不查对面是不是后台。std 默认不设 SQOS，对面可以完全冒充自己；`aw-channel/src/lib.rs:636-641` 的注释说「默认匿名」，是错的。
- 客户端反查后台：`windows/mod.rs:1082-1122` `verify_pipe_server` 打开服务端**进程**的令牌去比对。后台以 SYSTEM 运行时普通用户很可能打不开（要真机确认），进程号也可能被复用。
- `--owner`：后台用的是认出来的身份（`routes.rs:1602-1606`），这一点对。不对的几处：
  - **stop**：CLI 会带上 `owner`（`attach.rs:418-424`），后台也读（`routes.rs:2138`），但**会话属于调用者自己时后台根本不看 `--owner` 填了谁**，所以 `@last --owner alice` 会静默地停掉自己的会话；
  - 主人自己带 `--owner=自己` 反而被拒（`routes.rs:1643-1644`，`mutation_owner` 在 1632 行）；
  - 只认数字 uid，不认用户名；不存在的用户不报错；「用户」列显示 uid；
  - 管理员往别人的会话里加附着进程不用写 `--owner`（`watch_routes.rs:757`）；
  - 管理员按会话名找会话时会把所有人的会话都算进来（`attach.rs:325`）。
- **内存会话分支**：没配数据库时 `routes.rs:172-184` 用内存里的会话列表（`POST /sessions` 回假 201），PATCH 和 stop 的内存分支（`routes.rs:1603-1611`、2138-2142）各自判断 owner，写法跟 `mutation_owner` 不一样。正式版如果能走到这里，就是一条没被统一的权限路径。
- `daemon uninstall --purge --data-dir <任意目录>`：`daemon.rs:436` 带 `--data-dir` 时不用管理员，`daemon.rs:137-138` 调 `remove_test_data_dir`（159 行）直接删整个目录；`tree.rs:403-406` 公开写在帮助里。`test-hold-delay` 只在 `aw-platform/Cargo.toml:10` 定义，**CI 里没有任何检查 release 版里没有它**。
- **数据目录（3d95803，review 打回 + PM 要放宽）**：
  - 太严：`validate_directory_path`（`macos/mod.rs:63-87`、`linux/mod.rs:73-97`）路径上任何一段是符号链接就拒，Mac 的 `/var`、`/tmp` 本来就是系统链接，Mac e2e 全部起不来；Windows 提权管理员建的目录主人是 BA 不是用户，`--data-dir` 一定被拒（`mod.rs:1319-1321`）。
  - 能绕：「是不是正式目录」靠环境变量 `ProgramData`（`windows/mod.rs:1325-1331`），按字符串不分大小写比（106-110），斜杠反过来、末尾多 `\`、8.3 短名（`PROGRA~2`）、`\\?\` 前缀都能绕开。
  - 先建后查：普通用户后台走到正式目录那一支时先 `create_dir_all` 再查主人（`mod.rs:278-285`），目录被抢先建好，系统服务以后每次启动都被拒（占位）。
  - 只看最外层：目录里已有的子项和联接一概不管（`secure_data_dir_with_policy` 261-292），`AgentWatch\db` 预建成联接就能让 SYSTEM 写到任意位置；检查和设 DACL 之间没有把目录钉在句柄上（`SetNamedSecurityInfoW` 会 follow）。
  - Unix：主人要求是「后台自己的 uid」（`linux/mod.rs:28-38`），但只查最后一级；库是每次请求按路径重新打开的，`restrict_unix` 也会跟着链接去 chmod。
  - 报错把英文 detail 拼进中文（`runtime.rs:91`），跟定稿 `UI-147-wording.md:14-15` 对不上（`paths.rs:61`）。

**统一规矩**：
1. **所有进后台的连接都走 `aw-channel` 里同一个带保护的打开函数**：设 SQOS 识别级，发任何字节之前先确认对面是后台。`aw-cli` / App 里不许直接 `OpenOptions` 打开管道，用 clippy `disallowed_methods` 守住（跟 `aw-daemon/clippy.toml:2` 禁 `current_user` 一样）。
2. **反查后台查的是管道本身归谁**：`GetSecurityInfo`。服务模式下管道主人是 SYSTEM，开发模式下是当前用户。「查不了」和「查到了但不是后台」分开报。
   - **装了服务就只认 LocalSystem**：客户端自己查服务控制管理器（`OpenSCManager` + `OpenService`，能打开就算装了）来判断是不是开发模式，**不读环境变量、不看命令行参数**（这两样都能被普通用户随手改）。装了的话，管道主人必须是 LocalSystem（`S-1-5-18`），不是就报 `daemon_untrusted_server`，**绝不回退**到「主人是当前用户也行」的开发模式规则——否则普通用户进程抢先建一个同名管道就能冒充后台。只有没装服务时才按开发模式认当前用户。查服务状态本身失败时按「装了」处理（不放宽）。
   - Windows 管道服务端不是 `agentwatchd`（主人对、但进程不是后台）也算「连上的不是后台」，**沿用已有那句**「连上的不是 AgentWatch 后台，可能有别的程序占用了这个通信口。为防内容被它拿到，这次没有发送任何内容。」（码 `daemon_untrusted_server`），不另写新句。
   - 测试（Windows CI）：装了服务时，以当前用户身份先建同名管道 → 客户端报 `daemon_untrusted_server`、一个字节都没发；没装服务时开发模式照常能连。
3. **权限一律由后台按认出来的身份判断**。所有写操作（delete、rename、pin、**stop**、**attach 加进程**）都走同一个 `mutation_owner`：
   - 会话主人带不带 `--owner=自己` 都放行；
   - **会话是自己的、但 `--owner` 填了别人 → 拒绝**，不再静默执行，专门修 `@last --owner alice` 这个组合。`@last` 时报「`@last` 只指你自己最近的会话，不能跟 `--owner` 一起用。要操作别人的会话，请写会话号。」；写会话号时报「会话「{号}」的主人不是「{填的用户}」，没有做任何改动。」（码名沿用 `daemon_errors.rs` 已有的，没有就在第 8a 步按表加，不改已有码名）；
   - 管理员改别人的会话必须写 `--owner`；`--owner` 可以填用户名或 uid，**由后台解析**（Unix `getpwnam_r`，Windows `LookupAccountName` → SID）。用户不存在报「找不到用户「{名}」，没有做任何改动。」（码 `owner_user_not_found`，退出码 2，跟「找不到会话」的 6 分开，见 B1 码表）；查询本身失败（不是「不存在」）报「查不到用户「{名}」对应的账户，没有做任何改动。」，并且**不放行**。这两处都**不写「没有这个」+「用户」那句，也不用「不可得」**（UI-147-wording.md:71/76，那句在禁用词表里）；
   - 管理员按会话名找会话时，没写 `--owner` 只在自己的会话里找；写了 `--owner` 才在那个用户的会话里找（修 `attach.rs:325`）；
   - `@last` 永远只指调用者自己的会话，`@last` + `--owner=别人` 一律拒绝；
   - 「用户」列由后台填用户名（查不到时显示数字 uid）；
   - 管理员改别人的会话被拒：码名 `owner_action_forbidden`（UI审查 13:10，不用 `permission_denied`），中文只写「只有会话主人能操作」，前面不加「认证失败：」；认不出用户才用「后台认不出你是哪个用户……」那句，两种不混用。**码名一个都不改**，以 `daemon_errors.rs` 为准。
4. **内存会话分支（必须做，并进第 2 步）**：`routes.rs:172-184`、`1603-1611`、`2138-2142` 放到 `#[cfg(test)]` 后面；正式版没有库时后台**不启动 API**（报中文「数据库打不开」并退出），加测试证明 release 构建里走不到内存分支。
5. **测试开关只编进测试版，CI 用行为来验，不用 strings**：
   - `aw-cli` 加 feature `test-data-dir`，`--data-dir`（uninstall/purge 和其他子命令）只在这个 feature 下存在；
   - CI 编 release 版，跑 `aw daemon uninstall --help` 断言没有 `--data-dir`，再跑 `aw daemon uninstall --purge --data-dir /tmp/x` 断言是参数错误（退出码 2）、`/tmp/x` 还在；**不用 `strings` 搜**（二进制里本来就有 `data_dir` 这个配置名，会误报）；
   - `test-hold-delay` 补同样的行为检查（release 版的环境变量/参数不生效）；
   - 提前通知 Test-bot：他的脚本用的 `--purge --data-dir` 以后要用测试版二进制跑。
6. **数据目录（3d95803 放宽，PM 要求；review 四点照写）**：
   - **「后台是不是管理员」只看后台自己的令牌**：Unix 有效 uid==0；Windows 令牌是 SYSTEM 或提权管理员（跟 doctor `host.privileged` 同一来源）。不读环境变量、命令行、配置文件、调用方传的任何值。`storage.data_dir` 和命令行参数都不能改变「谁是管理员」「哪个是正式目录」这两个判断。
   - **「是不是正式目录」先规范化再比**：Windows 用 `SHGetKnownFolderPath(FOLDERID_ProgramData)` 取，不读环境变量；比较前对两边都 `GetFinalPathNameByHandle`（消掉 8.3、斜杠、`\\?\`、末尾分隔符），或者直接比文件 ID（卷序号 + FileId）。Mac/Linux 用 `canonicalize`（`/var → /private/var` 这类系统链接要先消掉再比）。
   - **非管理员后台碰到正式目录，在建目录之前就拒绝**，不碰它（修占位）。
   - **管理员后台指到非正式目录**仍按「普通用户目录」规则：主人必须是后台账户（Windows 提权时 BA 也算可信主人），权限只给自己（Unix 0700，Windows 受保护 DACL 只含自己的 SID，或 SY + 自己）。
   - **路径上的链接**：每一级（含上级）如果是符号链接/联接，只接受「主人是 root/SYSTEM、组和其他人都不能写」的系统链接（如 Mac 的 `/var`）；最后一级是链接一律拒绝；不能因为上级是可信链接就放过最后一级。root 后台用的目录，**上面每一级都必须是 root 的，而且组和其他人不能写**（或是带粘滞位的 `/tmp` 这类），否则拒绝。
   - **查完到用之间没有空档**：Windows 用 `CreateFileW(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)` 打开目录拿句柄，之后的主人检查、DACL 都对着句柄做（`SetSecurityInfo`，不用 `SetNamedSecurityInfoW`）；新建时 `CreateDirectory` 直接带安全描述符，或「临时名 → 设好 DACL → 原子 rename」。Unix 用 `open(O_DIRECTORY|O_NOFOLLOW)` + `fchmod`/`fchown`。建完再 canonicalize 核对一次。
   - **子项一起管**：目录已存在时遍历直接子项（不 follow），发现联接/符号链接、主人不对 → 拒绝；子目录和文件设同样的受保护 ACL 或 0600/0700。
   - **别人能写就纠正，纠正不了就拒绝**，报定稿中文（`UI-147-wording.md:14-15`：「数据目录「{路径}」不归管理员所有，可能被别人改过。为防万一，后台没有启动。请删掉这个目录后再启动后台。」；「路径含链接 / 纠正失败 / 普通用户目录别人能写」另外三句请 UI审查 补定稿，不许用带「安全」的说法，走 `secure_data_dir_error` 统一出口），`RuntimeError::DataDir` 不再把英文 `source` 拼进用户那一行。
7. 后台不能用后台自己的身份启动程序（`IdentifiedCaller::current_user` 已禁用）；以调用方身份启动前，先核对身份和权限；附加组按用户重新加载（A1 规矩 4）。
8. `config set` 保留文件原来的主人，这一条不改（D 节）。

**测试**：
- 反向测试：用匿名级别连上来的客户端被拒；对面不是后台时客户端一个字节都不发；`aw hook` 也一样；
- **`mutation_owner` 一张参数化表**，delete / rename / pin / stop / attach 加进程五种操作 × 下面每种组合都跑：普通用户带 `--owner` 改别人的 → 403；主人带 `--owner=自己` → 200；主人的会话 + `--owner alice` → 拒绝（专门覆盖 `@last --owner alice` 停自己会话）；管理员不写 `--owner` 改别人的 → 拒绝；管理员 `--owner 用户名` → 200；`--owner 1001` → 200；`--owner nosuchuser` → 中文「找不到用户「nosuchuser」，没有做任何改动。」，退出码跟找不到会话不同；用户名查询失败（注入）→「查不到用户「x」对应的账户，没有做任何改动。」且没改动；管理员按会话名找，没写 `--owner` 只找到自己的；
- 原来断言「主人带 `--owner=自己` 会被拒」的测试在第 2 步同一个提交里改掉；
- release 构建：`uninstall --help` 没有 `--data-dir`、传了报参数错误、目录还在；`test-hold-delay` 同样检查；release 构建里走不到内存会话分支；
- **数据目录矩阵**（review 3d95803 挡 1 的表全部照搬，每格一条测试）：普通用户 + 自己的临时目录 → 接受并收紧权限（Mac/Win CI 的 `ensure_data_dir_creates_a_temp_tree` 和 e2e 变绿）；普通用户 + 别人预建的 → 拒；普通用户 + 正式目录 → 拒且**目录没被建出来**；管理员 + 正式目录（不存在 / 普通用户预建）→ 新建 / 纠正或拒；管理员 + 自己的非正式目录 → 按普通用户规则接受；管理员 + 别人的非正式目录 → 拒；最后一级是恶意链接 → 拒；Mac `/var/folders/...` → 接受；ProgramData 的 5 种写法（反斜杠、末尾 `\`、8.3、`\\?\`、大小写）都被认成正式目录；预建 `data\evil` 联接 → 拒；预建 `data\secret.txt` 主人是普通用户 → 被纠正或拒；查完到用之间换成联接 → 第二次核对抓到；Windows CI 真建 junction 和 symlink；DACL 断言改成「去重后只有 SY 和 BA 两个 SID、有一条带 OI|CI」。

| 问题 | 来源 | 状态 | 进哪个提交 |
|---|---|---|---|
| `aw hook` 没加保护（hook.rs:127），注释写错（lib.rs:636-641） | review（624bb19） | 没修 | 第 3 步（winpipe B） |
| 反查改成查管道归谁，「查不了 / 不是后台」分开报 | review / UI审查 | 没修 | 第 3 步 |
| 匿名级别 / 对面不是后台的反向测试 | review | 没写 | 第 3 步 |
| `uninstall --purge --data-dir` 删任意目录；CI 没有 release 检查 | review（2511990 必改 1）/ review 要补 9 | 没修 | 第 2 步 |
| stop：自己的会话时不看 `--owner`（`@last --owner alice` 静默停自己的） | review / Test-bot B | 没修 | 第 2 步 |
| 主人带 `--owner=自己` 被拒；不认用户名；不存在的用户不报错；用户列显示 uid | review / Test-bot B / PM 12:57 | 没修 | 第 2 步 |
| 管理员加附着进程不用写 `--owner`（watch_routes.rs:757） | review | 没修 | 第 2 步 |
| 管理员按会话名找会话时跨所有用户（attach.rs:325） | review | 没修 | 第 2 步 |
| 内存会话分支各自判断 owner | review 要补 5 | 没修 | **第 2 步（必须）** |
| 「认证失败：」前缀不对 / 码不对 | review / Test-bot H1 | 没修 | 第 2 步 + 第 8b 步 |
| 数据目录太严（Mac/Win CI 整片红） | review（3d95803 挡 1） | 没修 | **第 0 步** |
| 数据目录能被路径写法绕开、先建后查、子项和联接、检查到使用有空档、上级目录可写 | review（3d95803 挡 2/3）/ review 要补 1 | 没修 | 第 0 步（Unix 部分）+ 第 6 步（Windows 句柄化部分） |
| 数据目录报错英文 detail、跟定稿不一致 | review（3d95803 收 1） | 没修 | 第 0 步 |
| Windows 数据目录 DACL 测试预期写错（4 条 vs 2 条） | review（3d95803） | 没修 | 第 0 步 |
| 后台日志 0644 | review 整体 F-f | 没修 | 下一包（先在文档里写「日志不记会话内容」，并加测试守住） |

## A5. 文字：一处定稿，CLI / App / 检查都从那里读

**根本原因**：文字写死在好几处（Rust 字符串、`ui/src/i18n/zh.json`、`ui/src/api/errors.ts`、`aw-cli/src/daemon_errors.rs`），定稿只是一份 md，靠人对照，所以同一批文字两次漏改。检查也分成两套、各有盲区：
- CI 里已有 `cargo xtask wording-lint`（`ci.yml:117-128`，`xtask/src/wording_lint.rs`）：只查 `ui/src/i18n/**/*.json` 每行、`crates/aw-cli/src/**/*.rs` 的**字符串字面量**、`aw-pipeline/rules/*.toml`；**不查 `///` 注释**，而命令行帮助正是从 `///` 生成的。
- `/workspace/qa-issues/check-147-wording.sh` 有 #147 的禁用词和必须出现的句子，但不在 CI 里，而且它主动跳过 `//`、`///` 开头的行（第 9 行的 `grep -vP`），所以 `findings` 的「查看发现」、`attach --help` 这类帮助文字它也查不出来。
- `daemon_errors.rs` 已有一张 47 行的「码 → 中文」表和测试 `every_daemon_error_code_has_a_chinese_sentence`（扫后台源码里 `error_response` 的字面量），但它的中文跟 `UI-147-wording.md` 有几处不一致（例：`daemon_errors.rs:91` 的 Windows 新建会话那句）。

**统一规矩和机制**（UI审查 + review 13:25 定，以下是决定）：
1. **码名以 `daemon_errors.rs` 为准，一个都不改名**；**中文以 `/workspace/qa-issues/UI-147-wording.md` 为准**（入库后放 `docs/03-wording/UI-147-wording.md`），两边不一致时**照 wording 文件改** `daemon_errors.rs` 和其他地方，不反过来改 wording 文件。
2. 机器可读的单一来源是 **`crates/aw-core/wording/zh.toml`**：每条一个稳定 key（错误码的 key 就是码名）、中文原文、可选英文。它是 wording 文件的逐条转写，**源码扫描测试**（`aw-core` 的 `wording_file_matches_toml`）逐条断言 toml 里的中文跟 wording 文件里那一句一字不差，wording 文件改了 toml 没跟上就红。
3. Rust 端：`aw-core/build.rs` 把 toml 生成 `const` 表（`aw_core::wording::Key → &'static str`），CLI 和后台只能通过 key 取文字；`daemon_errors.rs` 的表改成从这里取（第 8b 步）。
4. App 端：构建时生成 `ui/src/i18n/generated/wording.zh.json`，`zh.json` 里同名的 key 不许手写（lint 检查）；`errors.ts` 的 CODE_TEXT 从 `error-codes.json` 生成（B1）。
5. **`check-147-wording.sh` 并进 `xtask wording-lint`，CI 里只有这一个文案检查**：
   - 禁用词全部搬进去（规则写在 `zh.toml` 的 `[lint.forbid]` 里）：`将删除 N 个会话`、`用法: `（半角冒号）、`[OPTIONS]`、`<COMMAND>`、`planned:`、`executed=false`、`证据 S`、`不会读取 ca.key`、`查看发现`、`无法确认当前用户"`、`"platform I/O error`、`channel_broken: `、`operation would block`、`token len`、`` 找不到会话 ` ``、`找不到这个程序或工作目录`、`per-user db stats`、`认证失败：只有会话主人`、**`没有这个用户`**、**`录制中`**、`此构建不支持`、`当前运行模式不支持`、**`原因码 `**、**`为了安全`**、**`没法安全传递`**；
   - 必须出现的句子也搬进去（`[lint.require]`）：`已取消，没有删除任何会话`、`用法：`、`记录中`、`（已隐藏）`、`正在读取进程`、`只有会话主人能操作`、`你还没有会话`、`本版本未接入`；另加「`zh.toml` 里每个 key 至少被引用一次」；
   - 扫描范围扩到 `crates/**/*.rs` 的字符串字面量 **和 `///`、`//!` 文档注释**（CLI 帮助），`ui/src/**`；排除测试、快照、`tracing::` 日志行、`docs/`（文档里会引用禁用词当例子）；豁免标记沿用 `// wording-lint: allow <理由>`；
   - 原来 evidence-model §7 的规则（`安全` 打包票等）保留在同一个 lint 里。
6. **帮助快照测试**：`aw --help` 和每个子命令的 `--help` 用 insta 存快照，三个系统各存一份，CI 跑；`attach --help` 错行、`findings` 说明、`--no-daemon` 统一那句（A1 规矩 11）都由快照抓。
7. 用户看到的文字里，名字一律用「」括，不用反引号（Test-bot H2）；英文和错误码只进日志和 `--json`。
8. 门禁：第 8b 步之前，推前本地跑 `cargo xtask wording-lint`，只允许违例数比基线少（靠自觉，不算 CI 门禁）；**从第 8b 步起改由 CI 卡**，违例清零和打开 CI 检查在同一个提交里。

| 问题 | 来源 | 状态 | 进哪个提交 |
|---|---|---|---|
| 漏改 4 处 + `planned:` / `executed=false` + 6 句新句子不合定稿 | UI审查（2511990） | 正在改 | 第 8b 步（CLI 文案第三轮并进来） |
| `findings` 说明「查看发现」（两个检查都查不到 `///`） | UI审查 | 正在改 | 第 8b 步 + 帮助快照 |
| `attach --help` 选项说明错行 | Test-bot（da57） | 没修 | 第 8b 步 + 帮助快照 |
| 退出码对不上表：连不上后台时 list/export/timeline 返回 1（应为 3）；export 找不到会话返回 1（应为 6）；普通用户 db stats 返回 1 且是英文（应为 4 + 中文）；取消没有自己的码 | review 必改 5 / Test-bot F | 没修 | 第 9 步（**按表改代码，不改表**） |
| 「连不上后台」那句带英文 | review | 没修 | 第 8b 步 |
| 「找不到会话 `x`」用了反引号 | Test-bot H2 | 没修 | 第 8b 步 |
| 「找不到程序「{名字}」，请检查名字或路径」；工作目录另报「找不到工作目录「{路径}」」 | Test-bot H3 / UI审查 | 没修 | 第 8b 步（报错管道在第 4 步） |
| `daemon_errors.rs` 中文跟 wording 文件不一致 | review（3d95803 收 2）/ 13:25 | 没修 | 第 8b 步（照 wording 文件改） |
| 两套文案检查、`///` 不查、检查不进 CI | PM / UI审查 / review 要补 3 | 没做 | 第 8b 步（并进 xtask wording-lint） |
| `--no-daemon` 帮助（Linux/Windows 统一句，Mac 单独一句） | UI审查+review 13:25 / 13:51 | 没改 | 第 4 步改文字，第 8b 步快照 |

**定稿句子的落点表**（UI审查 0aff6cb 第 5 条；每条写第几步、改哪个文件。行号按 0aff6cb）：

| 定稿 | 第几步 | 文件 | 做什么 |
|---|---|---|---|
| Windows App 新建会话那句 + 单独的码 `launch_not_in_this_build` | 8b（文字）、10（界面） | `crates/aw-daemon/src/api/watch_routes.rs:390-398`、`crates/aw-cli/src/daemon_errors.rs:91`、`ui/src/i18n/zh.json:497` | 三处换成定稿原文；码名不变；HTTP 503 → 退出码按码表改成 5 |
| 新建按钮旁同一句灰字提示（不等点了才报） | 10 | `ui/src/features/sessions/NewSessionPage.tsx`、`ui/src/features/sessions/SessionsPage.tsx`（新建按钮） | 按 `/capabilities` 里的「Windows App 新建会话 = 本版本未接入」直接显示灰字，按钮变灰；jsdom 测试 |
| `doctor` 能力表表头改中文 | 8b | `crates/aw-cli/src/cmd/doctor.rs` | 345d216 已经把表头改成中文；第 8b 步按 wording 文件核对三个系统一致，加进帮助/输出快照 |
| 启动到一半出错，按步骤的句子 | 4（报错管道带步骤）、8b（句子） | `crates/aw-platform/src/unix/hold.rs`、`crates/aw-platform/src/windows/mod.rs`、`crates/aw-cli/src/daemon_errors.rs` | 总句「程序启动到一半出错，已经结束，没有运行：{原因}」；{原因}按步骤分：进工作目录 → 用 `cwd_not_found` 那句；执行 → `program_not_found` 那句；建管道、切身份、自检、放行四步的{原因}中文**请 UI审查 补进 wording 文件**，补之前用总句加「（第 N 步）」，不出现英文 |
| 打码的参数显示「（已隐藏）」 | 8b | `crates/aw-cli/src/cmd/render.rs`（会话命令行、参数显示）、`ui/src/lib/redact-preview.ts`、`ui/src/i18n/zh.json` | 人看的输出把打码标记换成「（已隐藏）」，原标记只留在 `--json` 和导出；`aw run --help` 补定稿那段隐藏说明（`crates/aw-cli/src/cmd/tree.rs` 的 `///`）；e2e 实际跑出「（已隐藏）」 |
| 管理员看别人的会话：停止 / 删除 / 改名变灰，旁注「只有会话主人能操作」 | 2 | `ui/src/features/sessions/SessionsPage.tsx:365-366`（现在只有改名、置顶两个按钮带 `title`）、会话详情页的停止按钮 | 停止、删除也变灰；「只有会话主人能操作」作为看得见的旁注文字，不只放在 `title` 里；jsdom 测试 |
| 库比程序新：App 顶部提示、按钮变灰，命令行报同一句 | 5 | `ui/src/api/errors.ts`、`ui/src/features/shell/`（顶部提示）、`crates/aw-daemon/src/api/routes.rs:1893`（文字已对） | 读接口回带只读标记（或 `/capabilities` 带上），App 顶部常驻提示，新建 / 停止 / 删除 / 改名变灰；命令行写操作报同一句 |
| App 里管道被占住的顶部提示 | 7 | `ui/src/lib/auth.tsx:35-36`、`ui/src/features/shell/SignIn.tsx:40`、`ui/src/api/errors.ts:51` | `daemon_untrusted_server` 用「连上的不是 AgentWatch 后台……」那句，做成顶部提示，不只在登录页显示 |
| 新建页命令框下方的环境变量灰字提示（13:41） | 10 | `ui/src/features/sessions/NewSessionPage.tsx`、`ui/src/i18n/zh.json` | 命令框下面常驻灰字，原文照 wording 文件；jsdom 测试 |

---

# 第二部分 对外五件统一的事

## B1. 错误码和说法：一张表 —— **进 #147**（第 8a 步）

- **根本原因（按 review 重数）**：
  - 后台 `error_response(状态码, "代码", "英文")` 在 185fc77 上去重后 **41 种**，全在正式代码里；
  - 还有不经过 `error_response`、直接用 `json!` 拼的 **5 种**：`db_busy`（`routes.rs:1874`、1918）、`unauthorized`（`routes.rs:1837`、2662）、`misdirected`（`routes.rs:2669`）、`wording_lint`（`export/markdown.rs:1043`）、`not_implemented`（`routes.rs:159-167`，**格式也不一样**：`"error"` 是字符串，不是 `{code, message}`）；
  - 所以后台实际**至少 46 种**，没有枚举；
  - 已经存在两张中文表：`aw-cli/src/daemon_errors.rs`（47 行 + 扫字面量的测试）和 `ui/src/api/errors.ts` 的 CODE_TEXT（16 项；其中 `write_failed` 后台根本不发，`caller_unknown` 跟别的码共用一句），其余码在 App 里走 76-79 行直接显示英文。CLI 另有 `DialError` + `exit.rs`。
- **统一改法**：
  - `aw-core::error::ErrorCode` 枚举，**第一版从 `daemon_errors.rs` 的 47 行表生成**（码名原样，一个不改，老测试断言和 App 都不用跟着改），补上表里没有的那几种；每个码带稳定英文名、HTTP 状态、CLI 退出码、wording key（中文在 `zh.toml`，以 wording 文件为准，见 A5）；
  - 后台 `error_response` 只接受 `ErrorCode`（老签名删掉）；`not_implemented` 改成统一的 `{code, message}` 格式；
  - **CI 检查**：xtask 里加 `error-lint`，禁止 aw-daemon 里出现 `error_response(` 带字面量状态码，**也禁止用 `json!` 拼带 `"error"` 键的回复**（只 grep `error_response` 抓不到那 5 种）；
  - `daemon_errors.rs` 里扫字面量的测试改完以后会**扫不到东西、空着就过**，同一个提交里换成「`ErrorCode` 每个值都有中文、每个值都有退出码」；
  - 导出 `error-codes.json` 给 UI，`errors.ts` 从它生成；`write_failed` 删掉（后台不发）；`caller_unknown` 按表单独配句子；
  - `api-and-cli.md` 加一节错误码表（由枚举生成）。
  - 「还不支持」只用四种说法（C1）。
- **收拢的问题**：review F5、U4、U5；UI审查 的 `unidentified_peer` 中文；`daemon_timeout` 英文；Test-bot H1/H4；`doctor`「当前不可用」不在四种说法里；review 要补 2。
- **测试**：`ErrorCode` 每个值都有中文和退出码（单元测试）；`xtask error-lint` 在 CI 里结果为 0；App 端 errors.ts 快照；老的码名断言全部原样通过。
- **拆成两个提交**（review 建议 5）：**8a** 只放 `ErrorCode` 枚举、生成代码、`error-lint`（码名不变，没有测试会变红）；**8b** 放文字表 `zh.toml`、wording 文件对照测试、「没采」替换、`daemon_errors.rs` 中文照 wording 文件改、帮助快照、`check-147-wording.sh` 并进 xtask，8b 一合进去 CI 检查就打开。

### B1 附：码表（UI审查 0aff6cb 第 1 条）

规则：码名以 `aw-cli/src/daemon_errors.rs` 为准，已有的一个不改；中文以 `UI-147-wording.md` 为准。退出码按 `aw-cli/src/exit.rs`：0 成功、1 一般错误、2 参数错、3 连不上后台、4 没权限、5 本版本未接入、6 找不到；**新加 7 = 用户取消**（取消删除用，`exit.rs` 第 9 步加常量）。「新码」那一列标「新」的，是第 8a 步要新加进枚举的码，名字以这张表为准。HTTP 状态和退出码跟现在代码不一样的，按这张表改代码（不改表）。

| 码 | 新 | 谁报 | HTTP | 退出码 | 中文（原文照 UI-147-wording.md） |
|---|---|---|---|---|---|
| `launch_not_in_this_build` | | 后台（Windows App 新建会话） | 503 | 5 | Windows 上暂时还不能在 App 里新建会话（本版本未接入）。可以先在命令行里用 `aw run -- 程序` 记录。 |
| `option_not_wired` | 新 | 后台 | 400 | 5 | 「{选项名}」本版本未接入，这次没有新建会话。请去掉这个选项再试。 |
| `db_read_only_newer` | | 后台 | 409 | 1 | 这份记录是更新版本的 AgentWatch 写的，现在只能查看，不能新建或修改。请升级 AgentWatch。 |
| `program_not_found` | | 后台 / CLI | 400 | 6 | 找不到程序「{名}」，请检查名字或路径 |
| `program_not_permitted` | | 后台 / CLI（报错管道，失败在 execve） | 403 | 4 | 程序「{路径}」没有执行权限，请检查文件权限后再试。 |
| `program_not_permitted` | | 后台 / CLI（报错管道，失败在 chdir） | 403 | 4 | 没有权限进入工作目录「{路径}」，请换一个目录或检查权限。 |
| `env_reserved` | 新 | 后台（替人起程序时，请求带了基础变量） | 400 | 2 | 环境变量「{名}」由系统按你的账户来填，不能在请求里改。请去掉这个变量再试。 |
| `cwd_not_found` | 新 | 后台 / CLI（报错管道，A1 规矩 3） | 400 | 6 | 找不到工作目录「{路径}」 |
| `owner_user_not_found` | 新 | 后台 | 400 | 2 | 找不到用户「{名}」，没有做任何改动。 |
| `owner_lookup_failed` | 新 | 后台 | 503 | 1 | 查不到用户「{名}」对应的账户，没有做任何改动。 |
| `owner_mismatch` | 新 | 后台 | 403 | 4 | 会话「{号}」的主人不是「{填的用户}」，没有做任何改动。 |
| `last_with_owner` | 新 | CLI（发请求前就拒） | — | 2 | `@last` 只指你自己最近的会话，不能跟 `--owner` 一起用。要操作别人的会话，请写会话号。 |
| `owner_action_forbidden` | | 后台 | 403 | 4 | 只有会话主人能操作 |
| `delete_cancelled` | 新 | CLI（终端里答「否」） | — | 7 | 已取消，没有删除任何会话 |
| `data_dir_untrusted_owner` | 新 | 后台启动时（`agentwatchd` 退出码 1，`aw daemon start` 退 1） | — | 1 | 数据目录「{路径}」不归管理员所有，可能被别人改过。为防万一，后台没有启动。请删掉这个目录后再启动后台。 |
| `data_dir_link` | 新 | 同上 | — | 1 | 数据目录「{出问题的那一级路径}」是一个链接，后台不会顺着链接写数据，所以没有启动。请换成普通目录后再启动后台。 |
| `data_dir_fix_failed` | 新 | 同上 | — | 1 | 数据目录「{路径}」的权限改不过来，后台没有启动。原因：{中文原因}。请删掉这个目录后再启动后台。 |
| `data_dir_others_writable` | 新 | 同上 | — | 1 | 数据目录「{路径}」别的用户也能写，后台没有启动。请把权限改成只有你自己能写，或者换一个目录。 |
| `data_dir_machine_needs_admin` | 新 | 同上 | — | 1 | 正式数据目录「{路径}」只能由管理员运行的后台使用。请用管理员运行后台，或者换一个自己的目录。 |
| `daemon_timeout` | | 客户端（aw-channel） | — | 1 | 后台 {N} 秒没有回应，这次请求没有完成。（附着 / 新建会话再加：「后台不会留下这个会话。」撤掉成功才写；收尾成附着失败写「这个会话已记为附着失败」） |
| `channel_broken` | | 客户端（aw-channel） | — | 1 | 跟后台的连接断了，请再试一次。 |
| `daemon_server_unverified` | | 客户端（Windows 反查后台） | — | 4 | 没法确认连上的是不是 AgentWatch 后台，为防连到冒充的程序，这次没有发送任何内容。请重启后台后再试。 |
| `daemon_untrusted_server` | | 客户端（Windows 反查后台） | — | 4 | 连上的不是 AgentWatch 后台，可能有别的程序占用了这个通信口。为防内容被它拿到，这次没有发送任何内容。 |
| `unidentified_peer` | | 后台 | 403 | 4 | 后台认不出你是哪个用户，已拒绝这次请求。请确认 `aw` 和后台是同一个版本，还不行就重启后台。 |
| 结束原因 `duration` | | 会话结束原因（不是错误，CLI 和 App 显示） | — | — | 到了设定的时长，已自动结束 |
| 结束原因 `error` | | 会话结束原因（结束时写库失败） | — | — | 记录已中断（写入失败） |
| `db_busy` | | 后台 | 503 | 1 | 会话数据库正忙（后台在写入），等了 N 秒还是没轮到，请稍后再试。 |

- 数据目录那 5 个码不走 HTTP：后台启动时就失败，写进 `agentwatchd` 的标准错误和日志（日志里另带英文原因），`aw daemon start` 照原文转给用户。
- `launch_not_in_this_build` 现在是 503 → 退出码 1，按表改成 5；`daemon_errors.rs:91` 的中文照 wording 文件改（第 8b 步）。
- `program_not_found` 现在的中文「找不到这个程序或工作目录」在禁用词里，拆成 `program_not_found` + `cwd_not_found` 两个码（第 4 步的报错管道能分出是哪一步）。
- 表里没列的老码（`daemon_errors.rs` 里其余那些）第 8a 步原样搬进枚举，中文照 wording 文件逐条核对。

## B2. 筛选语法：一套 —— **进 #147**（第 11 步）

- **根本原因**：有两个解析器。`aw-core/src/filter/registry.rs` 是完整字段表（`exe` 在 112 行，`path` 在 127 行）；`aw-store/src/query/filter.rs:1-6` 是另写的「子集」，只认 kind/proc/pid/domain/ip/port/evidence/time，`path` 能解析但会报不支持。`ast.rs:8` 写着「等 aw_core 的好了再接过来」，一直没接。`kind:` 的值不校验（`filter.rs:755` 只认出这个字段名，值原样转成 SQL 的 `cat` 匹配，`sql.rs:101`），所以 `kind:flie` 不报错，只是安静地返回空。
- **统一改法**：只留 `aw-core::filter` 一套，CLI、App、后台都用它解析，`aw-store` 只负责把它的 AST 翻成 SQL。
  - `kind:` 的值不认识就报错 `bad_filter`，带中文「不认识的类别「flie」，可选：proc、file、net…」；
  - `exe`：进程本来就有 exe 字段，**接上**，按 `exe` 筛进程要能用（review 建议 3，不能把能用的说成没有）；
  - 真没采的字段（`path` 等文件字段）报「这个版本还不能按「path」筛选（本版本未接入）」；
  - README 第 56 行（review 当时写的是 50 行）和时间线输入框的占位文字，换成现在真能用的例子 `kind:proc pid:1234`。等文件采集接上以后，`kind:file path:~/.ssh/**` 自然就能用。
- **收拢的问题**：review F3、U5（`37-filter-typo.png`）。
- **测试**：`exe:node` 能筛出进程；同一组输入，CLI 和后台解析出来的 AST 一样（共用的测试表）；`kind:flie` 报错；README 里每个示例都在测试里实际跑一遍（doc 测试）。

## B3. 能力和状态：后台报一次，其他地方都读它 —— **进 #147**（第 10 步）

- **根本原因**：App 新建会话页把 `proxy`、`self_report`、`follow_children` 发给后台（`NewSessionPage.tsx:150-152`，勾选框在 195 行起），后台 `create_inner`（`watch_routes.rs:351` 起）根本不读这几个字段，**悄悄忽略**；命令行那边对应的参数是明确拒绝的。能力现在已经有**两套**：`doctor_capabilities`（`collector_state.rs:81`，全局），和每个会话存下来的采集器能力（`routes.rs:1735-1750`，UI 的 `lib/capabilities.ts` 按它判断「采了 / 没采 / 不知道」）。
- **统一改法**：
  - **分清两种东西**：
    - **全局能力**（这一版、这个系统现在能做什么）：新加 `GET /capabilities`，复用 `aw-platform::Capability`，每项只有四种结果（C1）；它**替掉** `doctor_capabilities`，doctor、设置页、新建页、`--help` 的「（本版本未接入）」都从它渲染，不变成第三套。
    - **会话当时的能力**（那次记录时采了什么）：照旧跟着会话存、跟着会话读，老会话是老版本记的，**不能拿现在这一版的能力去套**。
  - 未接入的选项在界面上变灰并写「本版本未接入」；
  - **后台对请求里出现的未接入字段返回 400 `option_not_wired`**，带中文（按 wording 文件定句），不再悄悄忽略。
  - **安全**（review 要补 4）：`/capabilities` 只报这一版、这个系统、全局的能力，加上**调用者自己**能做什么（由后台按认出来的身份算，不读请求里的字段），**不报其他用户的会话、路径、进程**；它走跟其他接口一样的认人和 token，不开放给不认人的回环端口；App 不能拿 capabilities 当权限依据，后台照样对未接入字段回 400；Windows 上先确认对面真是后台（winpipe B，第 3 步）再相信它报的能力。
- **收拢的问题**：review G1、U3/U4 的一部分；附着时「包含已有子进程」取消勾选被忽略；`doctor`「认出连接方」没真测（真测归第 7 步）。
- **测试**：后台对 `proxy:true`、`self_report:"auto"`、`follow_children:false` 都回 400；新建页按 capabilities mock 把选项变灰（jsdom）；doctor 输出和 `/capabilities` 一致；老会话（用老版本能力记的 fixture）照它自己存的能力显示，不被新版本覆盖；普通用户调 `/capabilities` 拿不到别人的任何东西；不认人的连接调 `/capabilities` 被拒。

## B4. 界面信息结构 —— **下一包**（只做文档）；例外进 #147 第 12 步

页头一行显示命令、时长、退出码、结束原因；整列都是「没采」的列折叠；窄窗口 960px 能用；行内操作收进「⋯」菜单；加载时保留外框；出错写中文。这些属于 review U2、U3、U6、U8、U11，先记在这里，下一包整体返工。

**例外，进 #147**：
- **会话列表能一眼看出失败**：结束原因列写「程序已退出（退出码 7）」，非 0 用红色，但不能只靠颜色，**文字里也要写出退出码**（PM 12:52 决定）。数据库里已经有 `exit_code`，不用新采。测试：jsdom 断言非 0 时文字里有「退出码 7」；被信号结束写「程序被信号结束（信号 {N}）」，同样标红、有字（UI-147-wording.md:80）；CLI 的 `sessions list` 同步改。
- **出错写中文**：已经被 B1 覆盖。

## B5. 派生数据在查询时再算 —— **进 #147**（第 12 步）

- **根本原因**：`aw-daemon/src/sample.rs:1039-1076` 写库时用 `depths_by_pid(&drafts)` 算层级，`walk_pid` 只在**这一批**里往上找父进程，父进程是前几轮写进去的，孩子就被当成根。界面按库里的 `depth` 缩进（`ProcessesPage.tsx:131`），CLI 的 `procs --tree` 按 `parent_uid` 自己画，两边不一样。**而且 `parent_uid` 本身常常是空的**：`sample.rs:1039` 注释原文「`parent_uid` is often missing on a poll snapshot」，`sample.rs:541-542` 拿不到父进程时直接标成拿不到，`sample.rs:1015`、1476 直接写 None。所以原来写的「查询时按 `parent_uid` 现算」修不好（review 挡-2），CLI 的树也一样会画错。
- **统一改法（选 (b) 为主，(a) 补新数据）**：
  - **(b) 查询时修（主）**：API 和 CLI 共用 `aw-store` 里同一个 `process_tree(session)` 函数。先用 `parent_uid`；`parent_uid` 为空时，在**同一会话**里按 `ppid` 找父进程，条件是「父的 pid == 孩子的 ppid、父的启动时间 ≤ 孩子的启动时间、孩子启动时父进程还没退出（父的结束时间为空或 ≥ 孩子启动时间）」，多个候选取启动时间最晚的那个。这样老会话也能修好，还能避开 pid 被复用。
  - **(a) 采样时补（辅）**：后台按会话记一张跨轮的「(pid, 启动时间) → proc_uid」表，写库时把 `parent_uid` 补全，新数据以后不再依赖 (b) 的推断。
  - 层级、孩子数、进程数（同时在跑 / 累计）这类派生数据**写库时不算**，API 返回嵌套结构时顺带给层级；界面缩进改用嵌套深度；CLI `procs --tree` 改用同一个函数。库里的 `depth` 列以后不读，只为兼容保留。
- **收拢的问题**：review F4、U1（`12-build-processes.png`、`26-all-processes.png`）、review 挡-2。
- **测试**：父进程第 1 轮写入、孩子第 3 轮才出现、**孩子的 `parent_uid` 写成 NULL**，API 和 CLI 返回的层级都是 1；pid 被复用（老父进程已退出、新进程用了同一个 pid、孩子在新进程启动前就启动了）不挂错爹；同一会话 CLI 树和 API 树结构一致；(a) 打开后新写的行 `parent_uid` 不为空。

## B6. 其他进 #147 的对外项

| 项 | 根本原因（已核实） | 改法 | 测试 |
|---|---|---|---|
| CLI 导出的 Markdown 用 UTC | `aw-daemon/src/export/markdown.rs:47-49` 时区靠请求参数 `tz`，没有就用 UTC；`aw-cli/src` 里没有任何地方传 `tz` | CLI 导出时按本机时区带上 `tz`（分钟数），第 9 步 | `TZ=Asia/Taipei aw export --format md` 里写的是 UTC+08:00 |
| 架构文档过时 | architecture.md 写的是 HTTP/axum，实际是内部通道 + 手写路由（`aw-daemon/Cargo.toml` 里没有 axum）；crate 表缺 aw-platform、aw-channel；「谁启动程序」写反了 | 按接口文档 A/B/C 节重写 §2 图、§3 表、§4、§5.1；ADR-0005 标「部分被取代」；**第 −1 步先推** | 文档检查：crate 表跟 `cargo metadata` 对照（脚本） |
| 会话列表显示退出码 | 见 B4 例外 | — | — |

---

# 第三部分 C. 说法和状态（决定）

## C1. 能力状态：只有四种说法

| 说法 | 什么时候用 | 例子 |
|---|---|---|
| 可用 | 做了，这次也拿到了 | Linux 进程采样 |
| 本版本未接入 | 功能还没做，或者做了还没接上 | 文件、网络、代理、自报告、Windows App 新建会话 |
| 这个系统不支持 | 这个系统本身做不到 | macOS 上**脱离进程组**的孙程序不保证跟着 aw 结束（macOS 没有 subreaper，A1 规矩 6）。Linux（有没有 cgroup 都一样）和 Windows 都保证 |
| 不可得 | 做了，但这次拿不到（权限、进程已退出、读失败） | 普通用户读不到别人的进程；进程退出太快 |

**「没采」不是第五种说法，全部替换**（在 185fc77 上 grep 代码和 UI，测试文件和快照跟着改）：

| 位置 | 现在的写法 | 改成 |
|---|---|---|
| `ui/src/i18n/zh.json:443` `coverage.notCollected` | 没采：本版本不采集{kind} | 本版本未接入：{kind}（这里没有数据，不代表没有发生） |
| `zh.json:441` `coverage.notCollectedShort`（`OverviewPage.tsx:153/164`、`NotCollected.tsx:10` 用它表示「这一版没采这类数据」）、`zh.json:526` `settings.capNo` | 没采 | 本版本未接入 |
| `ProcessesPage.tsx:226` 退出码列（现在借用 `coverage.notCollectedShort`） | 没采 | **拆出新 key `procs.exitUnavailable` =「不可得」**，退出码列只用它；还在跑的进程写「还在运行」（C2）。`ProcessesPage.exit.test.tsx:46` 跟着改 |
| `zh.json:449` `overview.notCollected` | 没采：{kinds}（本版本只有进程采样） | 本版本未接入：{kinds}（这一版只采进程） |
| `zh.json:508` `new.capNotCollected` | 没采：{kinds}（{reason}） | 按原因选「本版本未接入 / 这个系统不支持 / 不可得」（权限不够、读失败这类用「不可得」） |
| `zh.json:166` `new.procNotCollected`；`aw-cli/src/cmd/ps.rs:206` | 没采：进程表（原因） | 这个平台上没有进程表时用「这个系统不支持」；后台没接上时用「本版本未接入」；读失败用「不可得」 |
| `aw-cli/src/cmd/render.rs:254/437`、`aw-daemon/src/export/markdown.rs:723`、`ProcessesPage.tsx:215`：退出码缺失（Mac/Windows 根进程的退出码，非子进程） | 没采 | **不可得**（功能做了，这次拿不到） |
| `render.rs:145`、`query.rs:87`、`http_source.rs:516`：pinned 缺失 | 没采 | 这是 bug，PATCH/show 要带上真实值（A3）；还没修好前写「不可得」 |
| `aw-cli/src/cmd/run.rs:915` cgroup 退化 | 没采：cgroup 会话范围… | 「不可得：这台机器没法把程序整组跟踪（没有可用的 cgroup v2），改为按父子关系跟踪；离开父子关系的程序可能漏记。」（UI-147-wording.md:82） |
| `run.rs:1622` | 退出太快没采到 | 不可得（进程退出太快） |
| `aw-cli/src/cmd/doctor.rs:92`（`Unprobed`，这一版本来就不检查） | 没采 | 本版本未接入（这一版没有检查采集功能） |
| `doctor.rs:180`（后台 doctor 没列出采集器）、`doctor.rs:266`（后台回复里没带 status） | 没采 | **不可得**（做了，这次没拿到） |
| `OverviewPage.tsx:49`、`NewSessionPage.tsx:73/322`、`ComparePage.tsx:212`（注释）；`docs/01-architecture/ui.md:63/93/139/189`、`api-and-cli.md:71/185/191`、`storage.md:458-459` | 没采 | 按上面同样的规则改，文档一起改 |

**四种说法只用来说能力**：出错用错误句子（B1 码表），过程和结果用状态句子（C2），不拿「不可得」「本版本未接入」去报错或标状态。比如超时要报「等了 {N} 秒，程序还没结束」或「后台 {N} 秒没有回应，这次请求没有完成。」，进程还在跑写「还在运行」。

**其他「还不支持」说法的替换表**（UI审查 0aff6cb 第 3 条；行号按 0aff6cb）：

| 位置 | 现在的写法 | 改成 | 第几步 |
|---|---|---|---|
| `ui/src/i18n/zh.json:40` `na.collector_unavailable` | 当前运行模式不支持采集此信息（详见 aw doctor） | 按原因选：「{类别}本版本未接入」或「这个系统不支持{类别}」 | 8b |
| `zh.json:285` `gaps.unavailable` | 本平台不可得的能力 | 这个系统不支持 | 8b |
| `aw-cli/src/cmd/doctor.rs:507` `CapabilityStatus::Unavailable` | 当前不可用 | 不可得 | 8b |
| `aw-cli/src/cmd/run.rs:1199` | 后台记录会话时不支持 --no-follow-children（轮询采样器总是跟随子进程）；请移除此参数或使用 --no-daemon | `--no-follow-children` 本版本未接入。请去掉这个参数，或者用 `--no-daemon` | 8b |
| `aw-cli/src/cmd/attach.rs:573` | 此构建的 attach 不支持 --name；请用 `aw ps` 找到进程后传入 --pid | `--name` 本版本未接入，请用 `aw ps` 找到进程号后写 `--pid` | 8b |
| `attach.rs:633` | 此构建的 attach 不支持 {name}；后台轮询采样器没有这个参数 | `{参数}` 本版本未接入 | 8b |
| `run.rs:1437` | 子进程启动尚未接入，本次只给出注入计划，没有设置系统代理，没有改证书库 | 代理模式本版本未接入。这次没有设置系统代理，也没有改证书库。 | 8b |
| `run.rs:1654` | [aw] 摘要不可用 · 本构建没有会话存储，不能用 0 表示未知 | [aw] 摘要本版本未接入（这一版没有会话存储） | 8b |
| `run.rs:1661`、`run.rs:1731`（JSON `reason`） | [aw] 摘要不可用 · {detail} | [aw] 摘要不可得：{中文原因}（读失败时）；JSON 里的 `reason` 照样改中文，英文原因只进日志 | 8b |
| `zh.json:76` `session.recording`、`zh.json:447` `overview.noRecordedGapsYet` | 录制中 / 录制中，到目前没有记录到采集缺口 | 记录中 / 记录中，到目前没有记录到采集缺口 | 8b |
| 注释：`ui/src/features/sessions/SessionsPage.tsx:387`、`ui/src/lib/live-session.ts:8`（UI审查 列的 `aw-cli/src/cmd/sessions.rs:362`、`docs/04-plan/pack2-checklist.md:13` 在 0aff6cb 上已经没有「录制中」，第 8b 步再 grep 一遍） | 录制中 | 记录中（注释和文档一起改，免得 lint 豁免越来越多） | 8b |

**内部码和术语的替换表**（UI审查 0aff6cb 第 6 条；这些词同时进 `zh.toml` 的 `[lint.forbid]`，但不能只靠 lint，每一处都写清改成什么）：

| 位置 | 现在的写法 | 改成 | 第几步 |
|---|---|---|---|
| `aw-cli/src/cmd/ps.rs:207` | 原因码 {code}，这个版本还不认识 | 不可得：进程表（后台给了这个版本不认识的原因，请升级 aw）。原因码只进 `--json` | 8b |
| `aw-cli/src/launch/unix_linux.rs:64` `V1_DOCTOR_HINT`（`aw-collector-linux/src/scope.rs:79` 里同一句也改） | 检测到 cgroup v1：启动模式不可用，已退化为 scope_pids 进程树跟踪。cgroup v2 才能把进程关在会话目录里。 | 不可得：这台机器没法把程序整组跟踪（没有可用的 cgroup v2），改为按父子关系跟踪；离开父子关系的程序可能漏记。 | 8b（`unix_linux.rs:1248` 的断言跟着改） |
| `run.rs:915` | 没采：cgroup 会话范围（…），已退化为按进程树跟踪（scope_pids）；… | 同上一行那句 | 8b |
| `run.rs:1199`、`attach.rs:633` 的「轮询采样器」 | 见上表 | 见上表（句子里不出现「轮询采样器」） | 8b |
| `run.rs:754` | 中断转发不可用；Windows 启动器未创建控制台进程组 | Windows 上没法把 Ctrl+C 转给程序（不可得） | 4 |

`[lint.forbid]` 加：`原因码`、`scope_pids`、`轮询采样器`、`注入计划`、`摘要不可用`、`本平台不可得`、`当前不可用`、`此构建`、`探测采集器`。代码注释里提到 `scope_pids`（eBPF map 的名字）不算用户可见，lint 只扫字符串和 `///`，不扫 `//`。

## C2. 会话和页面状态（跟能力状态是两张表，不混用）

| 状态 | 什么时候显示 | 现在代码里的写法 |
|---|---|---|
| 记录中 | 会话还没结束 | UI 是「录制中」（`zh.json:76`），**改成定稿的「记录中」** |
| 正在读取进程… | 已经回了 201，进程扫描还没做完（A2 规矩 4） | 新增 |
| 程序已退出（退出码 N） | 程序自己退出了，N≠0 时红色，文字里写出码 | `zh.json:78`「程序已退出」，补上退出码 |
| 程序被信号结束（信号 N） | 程序被信号杀掉，跟非 0 退出码一样标红、有字 | 新增（UI-147-wording.md:80） |
| 还在运行（进程）/ 记录中（会话） | 退出码为空且程序还在跑；**不写「不可得」** | UI-147-wording.md:81 |
| 正在停止记录… | 用户按了停止，后台还在收尾 | `zh.json:85` `session.stopping`，留着 |
| 已停止记录 | 用户按了停止 | `zh.json:81`；会话列表里的「○ 已停止」（`zh.json:77` `session.stopped`）**并进「已停止记录」**，不再用单独的「已停止」 |
| 记录已中断（后台重启） | `daemon_restart` / `daemon_shutdown` | `zh.json:82-83` |
| 附着失败 | 附着失败，或者回复写不回去被撤回 | `zh.json:79` |
| 接管超时 | `adopt_timeout`（`watch.rs:145`） | 定稿里有，UI 里要补 |
| 已停止（采集器） | 设置页里的采集器状态 | `zh.json:522`，留着，只用在采集器上，不用在会话上 |

这两张表都进 `zh.toml`（A5），中文以 `UI-147-wording.md` 为准。

---

# 第四部分 D. 跟 #147 已定的安全规矩不冲突（逐条确认）

1. **先认人**：所有改法都不放松「认不出就拒绝、码 4」。winpipe B 是在原来的基础上**加**确认对面是后台、`aw hook` 也纳入；A2 只把**取名字**挪到回复之后，认人和 `check_pid_owner`（按 pid 核对主人）仍在回复之前同步完成，中间没有 `await`。
2. **管理员和 `--owner`**：始终由后台按认出来的身份判断，CLI 传来的 `owner` 只当作「想操作谁的会话」，不当作权限；用户名到 uid 的解析在后台做；普通用户带 `--owner=别人` 一律拒绝（带 `--owner=自己` 照常执行）；`@last` 永远只指自己的会话。这次只是把 stop、attach 也拉进同一个 `mutation_owner`，比现在更严，没有放松。
3. **降权**：启动契约要求先切身份（setgroups/setgid/setuid 并自检），再 chdir、等放行、exec。附加组**一律由后台按用户重新加载**（`getgrouplist`），不用连接方报上来的组（review 挡-4，原来这里有冲突，已改）；自检补 getegid 和 `setgid(0)` 必须失败；后台禁止用 `current_user`（`aw-daemon/clippy.toml:2`），这条不变。
3a. **挂住时后台崩了程序结束，放行以后照样跑**：PDEATHSIG/看门进程**只用在 aw 起的程序上**，后台起的程序一律不绑（review 挡-3，原来这里有冲突风险，已改）；挂住阶段子进程关掉白名单以外的所有 fd，EOF 不会被别的挂住进程拖住。
3b. **`--no-daemon` 时 aw 一死程序跟着结束**：由看门进程保证，aw 被 SIGKILL 也成立。Linux 上看门进程是 aw 和程序之间那一层、并且是 subreaper，以 aw 的用户身份运行，只给自己的子孙发信号，每次发信号前按（pid、ppid、启动时间）核对，不会打到别人的进程；Mac 例外见 A1 规矩 6。
4. **数据目录**：放宽只放宽「普通用户后台用自己的目录」这一种；「是不是管理员」只看后台自己的令牌，「是不是正式目录」规范化后比，非管理员后台在建目录之前就拒绝正式目录，root 后台的目录上面每一级都必须是 root 且不可被别人写（A4 规矩 6）。测试用的 `--data-dir` 从 release 里拿掉，CI 按行为检查，只会更严。
5. **B3 拒绝未接入字段**只会让后台更严，不会给出新权限；`/capabilities` 只报全局能力和调用者自己能做什么，走同样的认人和 token，App 不拿它当权限依据。**B5 查询时算层级**只读本人有权看的会话，复用现在的 `owner_for_viewer`（query.rs:496）。
6. **filter 统一**：用户写的文字仍然只做参数绑定，不拼进 SQL（`filter.rs:5-6` 的规矩搬到 aw-core 里继续用）。
7. **`config set` 保留原来的主人**：这次不改。
8. **内存会话分支**进 `#[cfg(test)]`，正式版只剩 `mutation_owner` 一条权限路径（第 2 步）。

---

# 第五部分 E. #147 提交计划（顺序、每一步 CI 都是绿的）

**#147 已经合进 dev（f7ea22f），下面每一步都单独推到 `dev`，不再攒成一个 PR**：每一步先 rebase 到最新的 `origin/dev`，**绝不 force push**。**推 dev 不会自动跑 CI**：`ci.yml` 和 `desktop.yml` 只有 `pull_request`、推 `main` 和 `workflow_dispatch`（674bdef 加的手动触发），dev 的自动触发等用户决定、这里不加。所以**每推一次 dev，推的人手动跑三系统检查**（`gh workflow run ci.yml --ref dev`、`gh workflow run desktop.yml --ref dev`，Linux / Mac / Windows 三套都在里面），等跑完把结果和链接贴到群里，三套都绿了才算这一步完成；某一步推上去以后 CI 红了，下一次推的就是修它的提交，不回滚别人的提交。表里「已推」的是已经在 dev 上的提交。

当时的现状：**185fc77 这一版 CI 还没全绿**。Mac 一整片红（`ensure_data_dir_creates_a_temp_tree`、`secure_data_dir_*`、`e2e_macos::daemon_samples_long_running_program`、`second_instance_*` 等，报错全是「data directory path contains a symlink」，根子在 3d95803 的数据目录检查太严），另有 `database_busy_tests::lock_past_busy_timeout…`（`watch_routes.rs:932`）属 DB 那一路。所以第 0 步先让 tip 变绿。后面每个提交都要求三系统 `cargo test --workspace --no-fail-fast` + clippy（Linux/Win/Mac）+ desktop 全绿才推；第 8b 步之前推前本地跑 `cargo xtask wording-lint` 只允许违例数比基线少，**第 8b 步起由 CI 卡**。

**PM 13:24：已定进 #147 的一条不砍。** 下表每一行都要做完，#147 的事才算完（#147 本身已合，剩下的都按下表一条一条推到 dev）。

| # | 提交（路） | 内容 | 为什么这时 CI 能绿 | 用什么验证 |
|---|---|---|---|---|
| −1 | **文档先行**（只改文档，单独推；本文 0aff6cb / ef28f88 / 本版） | architecture.md 按实际重写（内部通道 + 手写路由、crate 表补 aw-platform/aw-channel、「谁启动程序」改对）；ADR-0005 标「部分被取代」；接口文档加「启动契约」（A1 规矩）、「请求生命周期」（A2 规矩）两节；Mac 三处顺序写反的改掉（`macos.md:128`、`api-and-cli.md:186`，`launch_as.rs:423-428` 注释在第 4 步一起改） | 只改文档，CI 不受影响；规矩先落文档，后面的代码对着它写（review 要补 8） | crate 表跟 `cargo metadata` 对照脚本 |
| 0a | **安全快修**（排在最前面，比第 0 步还早；每条一个反向测试） | ① `spawn_as_self`（dev `watch_routes.rs:539-555`）只调了 `envs(...)`、没有 `env_clear()`，后台用自己身份起程序时把**后台自己的整套环境**交给了程序 → 先 `env_clear()`，再放 5 个基础变量和请求给的变量；② `hold.rs:201-224` `resolve_program` 以 root 身份按 PATH 找程序 → 改成父进程只拼候选、子进程切身份后 execve（A1 规矩 4，先在 hold.rs 里改，不等第 4 步的统一启动函数；PATH 跳过空项、`.`、相对项）；③ Windows 数据目录能绕开 → 正式目录用 `SHGetKnownFolderPath(FOLDERID_ProgramData)`，不读 `%ProgramData%` 这类环境变量，非管理员后台在**建目录之前**就拒绝（原第 0、6 步里这一小块提前）；④ 请求里给 HOME/USER/LOGNAME/SHELL/PATH 就 400 `env_reserved`（`launch_as.rs:186-194` `base_env` 现在让请求覆盖）。`--data-dir` 只在测试 feature 里那一条仍在第 2 步，第 2 步紧跟着推 | 都是小改，不碰启动契约和看门进程，跟后面的步骤不冲突 | 反向测试：① 后台环境里放 `AW_SECRET=1`，起的程序的环境里没有它，并且跟完整集合一模一样；② root CI 上 A1 规矩 4 那三条 + 「PATH 带空项和 `.`」那条；③ 设了 `ProgramData=C:\Users\x\evil` 时后台照样用真正的 ProgramData，非管理员时目录根本没建出来；④ 5 个变量各一条，都是 400，都没有起任何进程 |
| 0 | **tip 变绿**：Mac 收尾 + 数据目录放宽（aw-xplat-macfix / aw-xplat-win） | A4 规矩 6 的 Unix 部分和规则判断（是不是管理员只看自己令牌、正式目录规范化后比、非管理员不碰正式目录、上级目录检查、系统链接放行、子项检查）；Windows 用 `SHGetKnownFolderPath`、建前拒绝；DACL 测试预期改对；数据目录报错中文按 wording 文件 | 修的就是现在红的那一片 | Mac/Win/Linux CI 全绿；A4 的数据目录矩阵（Windows 句柄化部分在第 6 步补完） |
| 1 | winpipe A 的过关 | 不改代码，看第 0 步之后的 Windows CI | — | Win CI 绿 + PM 开发模式真机连跑 5 条命令都成功 |
| 2 | **CLI 安全修**（`--data-dir`、`--owner`；CLI 路，紧跟第 0a 步推） | `--data-dir` 只在 `test-data-dir` feature 里；CI 加 release 行为检查（`--help` 没有、传了报参数错、目录还在；`test-hold-delay` 同样）；`--owner` 统一走 `mutation_owner`（stop / attach 加进程也是），主人的会话 + `--owner 别人` 拒绝，主人带 `--owner=自己` 放行，后台解析用户名，「找不到用户」「查不到…对应的账户」两句，用户列显示用户名，管理员按会话名只找自己的；**内存会话分支放进 `#[cfg(test)]`**；改掉原来断言「主人带 `--owner=自己` 被拒」的测试；通知 Test-bot 改用测试版跑 `--purge --data-dir` | 后台和 CLI 一起改、测试一起加，不碰平台层 | A4 的参数化表；release 检查；release 走不到内存分支 |
| 3 | winpipe B（**已推 93a6cfa**） | 查管道归谁（GetSecurityInfo）；`aw hook` 走带保护的打开函数；改注释；反向测试；clippy 禁止直接打开管道 | 只动 Windows 和 aw-channel | 匿名级别被拒、对面不是后台时一个字节都不发 |
| 4 | **启动契约**（aw-xplat-macfix；Linux 门控泄漏**已推 c21dcec**，改走 hold.rs、压力测试 `crates/aw-platform/tests/gate_concurrent_spawn.rs` 已在 dev，所以证明工作区的 dash/dup2-到-3 补丁**不再拿**） | A1 规矩 1–11：c21dcec 剩下的三处（Linux `pipe2`、附加组按 `getgrouplist`、子进程里不分配）；PATH 父进程拼候选、子进程切身份后挨个 execve；采集 crate 禁 Command + `xtask spawn-audit` + tokio 不开 process；Mac `pipe()` 后马上 FD_CLOEXEC + 子进程原始循环关 fd；唯一启动函数 + `SPAWN_LOCK` + clippy 禁 `Command::new`/`fork`；子进程里不分配、删 `clear_preload`、信号复位、报错管道、release 失败不丢 pid；附加组按 `getgrouplist`；自检补两项；程序名解析；看门进程（Linux：aw → 看门进程 → 程序，subreaper、SIGSTOP 再 SIGKILL 循环、pid+ppid+启动时间；Mac kqueue），替换 345d216 的 sh 看门进程；只绑 aw 起的程序；默认模式信号转发；tcsetpgrp（Linux/Mac 的默认模式和 `--no-daemon`、SIGTTOU、WUNTRACED、panic、aw 被杀后看门进程还前台）；`--no-daemon` 帮助（Linux/Windows 统一句，Mac 单独一句）；环境测试按完整集合；依赖里会起进程的 crate 清单 | 第 0 步之后 Mac 已绿；Linux/Mac 共用 hold.rs；Windows Job 部分如果没法在同一提交里绿，拆到第 6 步 | `gate_concurrent_spawn` 48×20 零泄漏（压力 48×300 零泄漏，dev tip 已是 0/14400）、40 路并发启动零失败、A1 共用测试全部 |
| 5 | DB 第二+三轮 + 附着修复（**已推 da00935、6a11d6d、36abe45**；剩下的进 5b） | 8fff164 + retention 修复 + `lock_past_busy_timeout` 修复；A2 规矩 2–7：超时一张表、撤回、只把取名字挪到回复之后（`check_pid_owner` 留在前面）、后台计时 `--duration`、**大锁里不碰库**、**FTS 新行不先 DELETE、改/删按 rowid**；「正在读取进程…」状态；按测量决定规矩 8（常驻写连接、列表计数） | 8fff164 的 retention 失败修完才推；A2 的 CLI 部分跟后台同一个提交，不会出现两头不一致的中间版本 | **同一个 200MB 库 + 2–3 个整机会话在采样，attach 单进程和 `--pid 1` 各 5 次都 ≤ 1.5 秒、POST ≤ 0.3 秒**；CI 缩小版；命令行被杀后会话照样按时结束；dbintegrity 压力测试 |
| 5b | **DB 第四轮：行 id 按三类表 + 回归项**（aw-xplat-fix） | A3 规矩 1：事件表加 `sampler` + `seq` + 唯一索引（保留 `id` 主键）、实体表按列合并（会变列比 `last_seq`、只写一次的列 COALESCE、不同采样器不互比）、桶和 file_access 计数写总数取 MAX；计数器归后台；`seq_next` 只当高水位；FTS rowid 由 (src, src_id) 推出、`http` 补删除触发器；`process_images.seq` → `exec_seq`；迁移 0012；去掉 `replay_writes`；FTS 改/删按 rowid；Test-bot 6a11d6d 回归 7 条；超时常量 12 秒进 aw-core；A2 规矩 6 剩下的（读请求不进大锁） | 迁移和写入同一个提交，没有「新代码 + 老表」的中间版本；API 的 `seq` 别名保留，UI 不跟着红 | A3 测试全部；0011 → 0012 迁移测试（含 207MB 库上迁移 ≤ 5 秒）；附着验收（H3 的 D/I 组）和 40 路并发启动（H3）都不回退 |
| 6 | Windows 第三轮（aw-xplat-win，**部分已推 345d216**） | `.cmd` 转义、整棵进程树 Job（接第 4 步）、等待有上限、PPID 复用；数据目录句柄化（`OPEN_REPARSE_POINT` + `SetSecurityInfo`、带安全描述符建目录、子项）+ 真建 junction/symlink 的测试 | 只动 Windows | Win CI + 真机清单 + 数据目录矩阵 Windows 那几格 |
| 7 | winpipe C + 三系统连接上限（aw-xplat-winpipe） | 句柄生命周期、doctor 真测、App `unidentified_peer`；**aw-channel 分帧三系统修复**（半截回复、16 MiB 上限、总超时）；**Unix 服务端连接数上限、每请求总时限、线程池**（review 要补 7） | aw-channel 改动影响 Unix，所以放在第 5 步之后、超时常量已经定下来再做 | 16 个不读 + 16 个慢慢发的客户端时其他请求照样 200（Unix + Win）；半截回复报错（Unix + Win） |
| 8a | **错误码枚举**（B1） | `ErrorCode` 从 `daemon_errors.rs` 生成，码名不改；`error_response` 只收枚举；`json!` 拼的 5 种收进来，`not_implemented` 统一格式；`xtask error-lint`；`error-codes.json` 和 errors.ts 生成；扫字面量的测试换成「每个值都有中文」 | 码名不变，没有断言会变红 | 每个码有中文和退出码；error-lint 为 0 |
| 8b | **文字表**（A5，CLI 文案第三轮并进来；**一部分已推 1efe176**） | `zh.toml` + wording 文件对照测试；`daemon_errors.rs` 中文照 wording 文件改；`check-147-wording.sh` 全部禁用词/必须句并进 `xtask wording-lint`，扫 `///`；帮助快照（三系统）；四种说法；「没采」全部替换；C2 状态表 | 违例清零和打开 CI 检查在同一个提交 | wording-lint 在 CI 里为 0；帮助快照 |
| 9 | CLI 退出码 + `--follow` 轮询 + 导出时区（CLI 路） | 按表改代码（3/6/4/取消）；`--follow` 按游标轮询，Windows 也能用；导出带 tz | 依赖第 8b 步的 key | 退出码表逐条测试；follow 每秒有输出、会话结束就退出；`TZ=Asia/Taipei` 导出是 UTC+08:00 |
| 10 | **能力报一次 + 拒绝未接入字段**（B3，提到 B2 前面） | `/capabilities` 替掉 doctor 那套，会话能力照旧跟会话存；新建页变灰；后台 400；只报全局和调用者自己的 | 依赖第 8b 步的说法 | 后台 400 测试；jsdom；老会话 fixture；不泄漏别人的东西 |
| 11 | filter 统一（B2） | aw-store 改用 aw-core 的 AST；`kind` 值校验；`exe` 接上；README 和占位例子 | 解析器替换一次性，老的子集测试迁到 aw-core | 共用测试表；README 示例 doc 测试 |
| 12 | 进程树查询时算 + 列表退出码（B5 + B4 例外） | `process_tree` 共用函数（parent_uid 为空按 ppid + 启动时间找）、采样时补 parent_uid；UI 用嵌套深度；列表写「程序已退出（退出码 N）」「程序被信号结束（信号 N）」 | 只动查询和 UI | 孩子 parent_uid 为 NULL 时层级仍为 1；pid 复用不挂错爹；jsdom |
| 13 | 收尾文档 | 由枚举生成的错误码表进 `api-and-cli.md`；`/capabilities` 接口文档 | 只改文档 | 生成结果跟提交的文件一致（CI diff） |

**顺序上的几条说明**：
- 文档先行（第 −1 步）：规矩本身先进文档，代码按它写；architecture.md 已经知道是错的，按「文档错了先改文档」放最前面。
- 第 0 步把数据目录放宽提前，因为它就是 Mac CI 整片红的原因；第 0 步不绿，后面每一步的「CI 绿」都无从谈起。
- CLI 文案第三轮不单独推，并进第 8b 步，否则同一批文字要改两次。
- A2 的后台部分（超时、撤回、后台计时、附着修复）跟 DB 轮放在同一个提交（第 5 步），否则中间会有一个两头超时不一致的版本。
- 第 0a 步（review 3.1 挡 3）：四个已知的洞（后台环境泄漏、root 按 PATH 找程序、Windows 数据目录能绕开、请求能改基础变量）都很小，不等第 4 步这个最大的一步，放在最前面先堵上；第 2 步紧跟着推。
- 第 2 步是挡合并项里最小、最独立的，放在前面。

## F. 风险

1. **Linux 改用 hold.rs**：重写 Linux 的启动路，会影响已经过了 Test-bot 307 条测试的那一路。缓解：第 4 步可以先只上证明工作区那个最小修法（父进程一直 CLOEXEC + 子进程 dup2 到 3），压力测试零泄漏后再换 hold.rs；推上来后 Test-bot 把 RETEST-CLI / STEP3 / ALLCLI 全部重跑。
2. **Windows 都没上过真机**：3d95803、4e6b68a、winpipe B/C 都只在 CI 上跑过。服务模式和普通用户两项要等用户开管理员窗口。
3. **附着修复只做了一半**：证明工作区只验证了「新行不先 DELETE」。改名和 retention 删除时的 FTS 删除仍然是全表扫描，要按 rowid 删（A2 规矩 7）才算完；第 5 步 CI 缩小版要盖住 retention 删除的耗时。另外 FTS 改 rowid 方案涉及迁移，老库要回填映射表（大库上一次性耗时要测）。
4. **看门进程**是新加的进程：它**必须比 aw 活得久**（不能被绑在 aw 上一起死，否则 aw 被 SIGKILL 后没人清理）；清理完成后自己退出，5 秒上限防止卡住；它自己意外死了，程序挂回 aw（aw 也是 subreaper），由 aw 接手。aw → 看门进程 → 程序这层关系改了退出码、信号和终端前台的走法，第 4 步的 pty 测试必须盖住（A1 测试）。
5. **wording 表一次性动的地方很多**（Rust、UI、文档、快照）。冲突风险高，第 8b 步期间其他路尽量不改用户可见的文字。
6. **`--owner` 用户名解析**在 Windows 上要查 SID 对应账户，可能慢或失败；失败时报「查不到用户「{名}」对应的账户，没有做任何改动。」且不放行。
7. **Mac `setgroups` 超过 16 个**：A1 规矩 4 选了截断 + 日志，待 PM 确认。
8. 时间：第 −1～5 步是挡合并的，第 8a–13 步工作量不小。**PM 13:24 定一条不砍**，排期紧时只调顺序不删：B1 > B3 > B5 > B2（review 建议 4，B3 提到 B2 前面）。

## G. 未归类（不在五类里，记下来）

- 内存会话分支：已从「建议」改成**必须**，挪进 A4 规矩 4、第 2 步。
- `cfg(target_os)` 搬家：`aw-daemon` 96 处、`aw-cli` 94 处，`aw-platform` 反过来依赖采集器 crate。属于下一包，但第 4 步会顺带把 `run.rs` 里启动相关的分支搬走。
- 接 Linux 文件和网络采集、真浏览器 UI 冒烟测试、资源优化（进程数无限涨 G6、全机采样会话 G7）：下一包。G7 跟附着慢有关（整机会话越多，写锁越抢），第 5 步的 FTS 修复先把单批写入从秒级降到百毫秒级，写入频率的优化留到下一包。
- `sudo attach --pid 1` 留下停不掉的整机会话（Test-bot）：第 5 步后台计时 `--duration` 会收掉有时长的；没写时长的整机会话怎么停，第 9 步在 CLI 里补提示。
- e2e 测试只在 Linux 上编译（`crates/aw-daemon/tests/e2e_cli.rs:10`）：第 6 步让 e2e 在 Win/Mac CI 上跑。
- STOP-DAEMON.sh 用 `pgrep -x` 判断会误判（Test-bot）：测试脚本，跟第 5 步一起改成按我们自己的进程号判断。
- `MacHeld`/`MacReleased` 改名（现在是 Unix 通用代码）；`MacReleased` 没有 Drop 会留僵尸、`Drop for MacHeld` 在 tokio 线程上阻塞 waitpid：第 4 步顺手改（review 95b49ff 建议）。
- Mac「root 切到别的用户」还没人在 Mac 上跑过，【待验证】标记保留。

---

# H. 两处「待证」：数字和结论（PM 13:04 / review 13:10、要补 10）

都在证明工作区 `/workspace/aw-xplat-prove`（从 `origin/feat/cross-platform` 185fc77 新建，`CARGO_BUILD_JOBS=4`，没推、没碰 root 后台 pid 607359 和其他路的工作区）里做，Linux 盒子上测。原始输出都在 `/workspace/aw-prove-out/`。

## H1. Linux 并发启动门控泄漏 —— **已证实**（而且比原来推断的多一个毛病）

- 测试：`crates/aw-platform/tests/gate_concurrent_spawn.rs`（副本 `/workspace/aw-prove-out/gate_concurrent_spawn.rs`）。每轮 48 个线程用 Barrier 同时走门控启动，放行后每个目标把自己的 `/proc/$$/fd/*` 列出来；超出基线（同一测试进程普通 spawn 继承到的 fd）的就是泄漏，`pipe:[…]` 是别人的门控读端。CI 默认 48×20，`AW_GATE_STRESS_ROUNDS=300` 做压力。另一条 `gated_spawn_works_when_the_gate_fd_number_is_ten_or_more` 单线程、先把 fd 号顶到 ≥ 10 再启动。
- **修前**（185fc77 原样，48 线程 × 300 轮 = 14400 个子程序）：
  - 拿到别人门控读端的子程序 **4363 个（30.3%）**，泄漏 fd 23927 个，全是 `pipe:[…]`，**300/300 轮都有**；
  - 另有 **9768 个（67.8%）** 目标根本没跑起来，`Exited(2)`：dash 不认两位数 fd，`<&10` 报 `Bad fd number`；
  - fd≥10 单线程测试：稳定 `Exited(2)`（`gate-highfd-before.txt`）。
- **因果链**（回答 review 要补 10）：读端泄漏**不会**让 EOF 迟到（EOF 只看写端），它违反的是 fd 白名单；真正让目标「没跑起来」的是第二个毛病（fd 号 ≥ 10 → dash 退 2），并发只是让 fd 号更容易过 10。CI 上 `command_spawner_*` 偶发失败对应的是哪一条，**还要一份 CI 失败日志才能对上**（没拿到，列为未完成）。
- **A/B 只改一处**（review 指定的那一处，不是整个换成 hold.rs）：父进程里两端一直 CLOEXEC（删掉 403-406 的清 CLOEXEC），子进程在 `pre_exec` 里 `dup2(读端, 3)`，门控脚本固定用 fd 3。补丁 `/workspace/aw-prove-out/linux-gate-fix.patch`。
- **修后**（同样 48 × 300 = 14400）：泄漏 **0**，退 2 **0**，其他失败 **0**（`gate-after.txt`）；fd≥10 测试通过。
- 次数够不够：修前每个子程序的失败率 p ≈ 0.98（30.3% + 67.8%），按 review 的 3/p 规则只要几次；按每轮算 p = 1（300/300 轮都有泄漏）。修后 14400 次零失败，远超 3/p。
- 回归：`cargo test -p aw-platform` 全过（19 + 2 + 3 条）、`cargo test -p aw-cli command_spawner` 全过（`gate-regress.txt`）。
- 结论：根本原因是「父进程里清掉 CLOEXEC 留出继承窗口」+「门控 fd 号不固定、dash 只认一位数」。修法写进 A1 规矩 1，第 4 步直接拿补丁和测试；hold.rs 的子进程关 fd（close_range）是在这个基础上再加的一道。

## H2. 附着 6 秒 —— **已证实，原来写的根因（同步扫整机进程表）已否定**

- 方法：证明工作区里给后台加了计时探针（`/workspace/aw-prove-out/attach-timing-probe.patch`，`AWT` 行），拆成：等全局大锁 `state_lock_wait`、`check_pid_owner`、扫进程表 `host_process_table_scan`、`Store::open_runtime`、`SqliteSink::new`、`write_session_row`（含等库写锁）、`insert_session` 合计、`total_serve`，另记采样器每次 `write_batch` 超过 50ms 的耗时。临时后台、临时数据目录、临时 socket；大库是 `/tmp/agentwatch-143` 那份的拷贝（207MB，`fts_text` 约 22.7 万行），每组前重新拷一份干净的。每组 `attach --duration 1s` 跑 5 次，**墙钟时间里含那 1 秒**。加了一个只在探针里的开关 `AW_PROBE_NO_HOST_SAMPLE` 关掉后台自带的整机采样，用来做「库大但没有在采样的会话」那组对照。
- 修前（185fc77 原样）：

| 组 | 库 | 在采样的整机会话 | 附着目标 | 成功 | 墙钟 | 等大锁 | 写会话行 | 采样器单次写最长 |
|---|---|---|---|---|---|---|---|---|
| A | 207MB | 无（探针关掉） | 单进程 | 5/5 | 1.06–1.20 秒 | 0 | 1.7–28ms | 84ms |
| C | 207MB | 后台自带 1 个 | 单进程 | 5/5 | 1.06–1.23 秒 | 0 | 1.0–138ms | 974ms |
| B | 207MB | 无（探针关掉），但附着的就是 `--pid 1` | 整机 | **0/5** | 5.1–9.2 秒（客户端 5 秒超时） | 2.87–3.06 秒 | 最长 7.24 秒 | **16.0 秒** |
| H | 207MB | 后台自带 + 2 个 `--pid 1` | 单进程 | **0/5** | 5.07–5.23 秒（超时） | 最长 5.70 秒 | 最长 5.25 秒 / busy | **24.8 秒** |
| G | 空库 | 后台自带 1 个 | 整机 | 5/5 | 1.13–1.16 秒 | 0 | 3–23ms | 393ms |
| J | 空库 | 后台自带 + 2 个 `--pid 1` | 单进程 | 5/5 | 1.13–1.58 秒 | ≤ 72ms | 2–99ms | 147ms |

- 每一步的耗时，各组对比：
  - **扫整机进程表 13–120ms**，空库和大库一样，**跟慢无关**（否定原来 A2 第 4 条）；
  - **开连接 `Store::open_runtime` 0.6–2ms**（个别 14–51ms 毛刺出在空库上），`SqliteSink::new` 0.1–13ms，**都不随库大小增长**；打开时没有 integrity_check/VACUUM/FTS 重建；
  - **随库大小增长的只有一步：写入时 FTS 的 `DELETE … WHERE src_id=?`**。`src_id` 在 fts5 里是 UNINDEXED，每次全表扫描，大库上约 65ms 一次；整机会话每批约 433 个映像就是 433 次，单个写事务占住写锁 16–25 秒；
  - 附着的 `insert_session` 在 `BEGIN IMMEDIATE` 上等这个写锁（最多 8 秒），**同时还在全局大锁里**，后面的请求在大锁上排队 2.9–5.7 秒；客户端 5 秒先放弃。
  - 结论：慢 = 「库大（FTS 行多）」×「有整机会话在写映像」。只有其一都不慢（A、C、G、J 组）；两者都有就 5/5 超时（B、H 组），H 组就是 Test-bot 报的「大库附着单个进程 5 秒、多数超时」的复现。
- 修后（只改一处：`write_images` 对新插入的映像直接 `INSERT INTO fts_text`，不先 DELETE；补丁 `/workspace/aw-prove-out/fts-insert-probe.patch`）：

| 组 | 库 | 在采样的整机会话 | 附着目标 | 成功 | 墙钟 | POST 本身（serve） | 等大锁 | 采样器单次写最长 |
|---|---|---|---|---|---|---|---|---|
| D | 207MB | 后台自带 + 3 个 `--pid 1` | 整机 | 5/5 | 1.09–1.15 秒 | 30–84ms | ≤ 63ms | 76ms |
| I | 207MB | 后台自带 + 2 个 `--pid 1` | 单进程 | 5/5 | 1.07–1.12 秒 | 21–61ms | ≤ 37ms | 99ms |
| E | 207MB | 后台自带 1 个 | 单进程 | 5/5 | 1.17–1.22 秒 | 26–122ms | 0 | 78ms |
| F | 空库 | 后台自带 1 个 | 整机 | 5/5 | 1.11–1.14 秒 | 47–83ms | 0 | 115ms |

- **按 review 挡-1 的验收标准**（同一个 200MB 库、同样数量的在采样会话，`attach --duration 1s` 总共 ≤ 1.5 秒、POST ≤ 0.3 秒）：修后 D、I 两组全部达标（≤ 1.15 秒，POST ≤ 84ms），跟空库（F、G）一样。
- 推荐修法（写进 A2 规矩 6、7，第 5 步）：① FTS 新行直接 INSERT，改/删按 rowid（映射表或确定性 rowid），不再按 UNINDEXED 列 DELETE；② 全局大锁里不碰库，读请求不进大锁；③ 采样写事务时长进日志；④ 两头超时一张表。扫进程表挪到回复之后只是顺手优化（只挪取名字，`check_pid_owner` 留在前面）。
- 没测的：会话列表每行现数 `session_counts` 在大锁里的耗时（这次没同时刷列表）；Mac / Windows 上的同样测量。

## H3. 在 dev tip（f7ea22f，含 c21dcec / 6a11d6d / 36abe45）上复测（14:20–14:35）

同一台机器、`CARGO_BUILD_JOBS=4`、release 构建、临时 root 后台 + 临时数据目录 + 临时 socket，没碰 root 后台 pid 607359。

| 项目 | 做法 | 结果 |
|---|---|---|
| 门控泄漏（现在 Linux 走 hold.rs） | `AW_GATE_STRESS_ROUNDS=300 cargo test --release -p aw-platform --test gate_concurrent_spawn`，48 线程 × 300 轮 | spawned=14400，leaking_children=0，leaked_fds=0，other_failures=0，50.9 秒；fd≥10 那条也过（输出 `/workspace/aw-prove-out/gate-36abe45.txt`） |
| 40 路并发启动（经后台） | `/workspace/aw-prove-out/run40.sh 10 40`：40 个 `aw run -- sh -c 'exit 3'` 同时起，10 轮 | **400/400 都退 3，0 失败**，共 25.7 秒（`run40-36abe45.txt`） |
| 附着 D 组 | 207MB 库 + 后台自带 + 3 个 `--pid 1` 在采样，`attach --pid 1 --duration 1s` × 5 | 5/5，墙钟 **57–111ms** |
| 附着 I 组 | 207MB 库 + 后台自带 + 2 个 `--pid 1` 在采样，附着单个进程 × 5 | 5/5，墙钟 **65–148ms** |

- 墙钟比 H2 的「修后」少了约 1 秒，是因为 6a11d6d 把 `--duration` 交给后台计时，命令行建好会话就返回（输出「监控已附着；后台会在 --duration 到时…」），墙钟里不再含那 1 秒。远低于验收线（≤ 1.5 秒、POST ≤ 0.3 秒）。
- 这一版构建里没有计时探针，所以没有每一步的分解数字，也没有「采样器单次写最长」；要分解数字得把探针补丁再打到 dev 上。
- Mac 这一步的 CI 结果：本机拿不到，请 PM / Test-bot 看 dev 上 f7ea22f 之后那次 Mac CI。

---

# I. 本版对照 review 13:40 打回意见（逐条）

| review 意见 | 本版怎么改的 | 在哪 |
|---|---|---|
| 挡-1 附着慢根因写错、验收定错 | 用 10 组对照计时证实是 FTS 全表扫描 DELETE + 库写锁 + 全局大锁；扫描已否定；验收改成「同库同采样会话 ≤ 1.5 秒 / POST ≤ 0.3 秒」，修后达标 | A2、H2、E 第 5 步 |
| 挡-2 进程树按 parent_uid 现算修不好 | 改成 (b) 查询时 parent_uid 为空按 ppid + 启动时间找（主）+ (a) 采样时补；测试改成孩子 parent_uid 为 NULL、pid 复用 | B5、E 第 12 步 |
| 挡-3 aw 被强杀谁来清理、Mac 写反、PDEATHSIG 不能用在后台起的程序 | 只绑 aw 起的程序；看门进程（Linux：看门进程是 subreaper、夹在 aw 和程序之间，SIGSTOP 再 SIGKILL 循环清理；Mac kqueue NOTE_EXIT；Windows Job）；PDEATHSIG 三个坑；Mac 写成「脱离进程组的孙程序不保证」；测试加「后台被杀程序还在跑」 | A1 规矩 6、C1 |
| 挡-4 hold.rs 附加组来源、异步信号安全、挂住时拿着所有 fd | 附加组一律 `getgrouplist`；父进程准备指针数组、删 `clear_preload`；子进程关 fd（Linux close_range，Mac 原始循环 close，PM 13:13）；测试加挂住阶段白名单、A/B 中止 | A1 规矩 1、3、4 |
| 要补 1 数据目录放宽 | A4 规矩 6 + 测试矩阵，第 0 步（Windows 句柄化第 6 步） | A4、E |
| 要补 2 错误码 46+ 种、两张已有表 | B1 重写：41 + 5，`not_implemented` 格式、`json!` 禁用、从 daemon_errors.rs 生成、码名不改、`write_failed` 删 | B1、E 第 8a 步 |
| 要补 3 跟 xtask wording-lint 怎么合 | check-147-wording.sh 并进 xtask，CI 只一个检查，扫 `///` | A5 规矩 5 |
| 要补 4 能力分两种、安全三点 | B3 重写 | B3 |
| 要补 5 内存会话分支 | 必须做，进第 2 步 | A4 规矩 4 |
| 要补 6 check_pid_owner 不能挪 | 写明只挪取名字 | A2 规矩 4、D1 |
| 要补 7 Unix 只连不读 / 连接上限 / 总时限 | 三个系统一起，测试 Unix 也跑 | A2 规矩 9、E 第 7 步 |
| 要补 8 文档顺序 | 加第 −1 步「文档先行」 | E |
| 要补 9 release 里没有 `--data-dir` 怎么验 | feature + 行为检查，不用 strings；`test-hold-delay` 同样补；通知 Test-bot | A4 规矩 5、E 第 2 步 |
| 要补 10 两处待证的验证方法 | 已做，数字见 H；Linux 那条只改一处做 A/B，次数远超 3/p；CI 失败原始断言还没拿到 | H1、H2 |
| 要补 11 tcsetpgrp 三件事 | SIGTTOU、WUNTRACED + Ctrl+Z/fg、panic 还前台；Mac 两种模式 | A1 规矩 7 |
| 建议 1 行号 | run.rs 871/1099/1049、ipc.rs 577 已改；stop 那条按 review 写准 | A1、A2、A4 |
| 建议 2 C1 例子 | 改成「脱离进程组的孙程序不保证」 | C1 |
| 建议 3 `exe` 别说成没有 | 改成 `exe` 接上（进程已有这个字段），只有 `path` 等文件字段是「本版本未接入」 | B2 |
| 建议 4 B3 提到 B2 前面 | 第 10 步 B3、第 11 步 B2 | E |
| 建议 5 第 8 步拆两个 | 8a / 8b | B1、E |
| 安全对照：config set 保留原主人 | D 节补一条「不改」 | D |

**同时写进来的其他决定**：PM 13:13（Mac 原始循环关 fd + `pipe()` 后马上 FD_CLOEXEC）→ A1 规矩 1；PM 13:23（唯一启动函数 + 全局启动锁 + clippy 禁 Command）→ A1 规矩 2，并写明**不覆盖**的范围；UI审查+review 13:25（码名以 daemon_errors.rs 为准、中文以 wording 文件为准；check-147-wording.sh 并进 xtask 并扫 `///`；`--no-daemon` 帮助三系统统一）→ A5、A1 规矩 11；`aw147-95b49ff-3d95803-review.md` 的挡合并和合并前要收各条 → A1、A4 的问题表。

**还没完成、需要别人给的**：`command_spawner_*` 在 CI 上失败的原始日志（Test-bot / PM）；数据目录另外三种失败的中文（UI审查）；`option_not_wired` 的中文（UI审查）。


## 补充决定（PM 13:44–13:51，提交前加入）

### 启动程序时的环境变量
- **后台起的程序**（App 新建会话、以 root 起再切到用户）：环境变量从零构造，只有 HOME、USER、LOGNAME、SHELL（来自目标用户的账户，fork 前用 `getpwuid_r` 取好）和固定的 PATH，再加上请求里给的变量；绝不继承后台自己的环境，也不是「先复制再删」。**请求里给了 HOME、USER、LOGNAME、SHELL、PATH 中的任何一个就拒绝**（PM 14:30 定），回 400 `env_reserved`，一个程序都不起：「环境变量「{名}」由系统按你的账户来填，不能在请求里改。请去掉这个变量再试。」（现在 dev `launch_as.rs:186-194` `base_env` 是让请求覆盖，第 0a 步改；测试：5 个变量各一条，请求带上就 400 `env_reserved`、没有起任何进程）。查找程序用的 PATH 因此永远是固定的 `DEFAULT_PATH`（A1 规矩 4）。只对后台替人起的程序生效；`aw run` 默认模式和 `--no-daemon` 用的是用户自己的环境，不受这条限制。测试比对完整集合，不只是「没有密钥」。
- **`aw run` 默认模式和 `--no-daemon`**：aw 本来就以当前用户运行、自己起程序，原样传当前用户的环境，不经过后台（PM 13:47 定）；加测试确认用户环境原样传到程序。
- 环境里不是 UTF-8 的变量：跳过并记日志，不 panic。

### Mac 附加组超过 16 个（PM 13:47）
- 不截断也不拒绝，按用户加载（跟登录一样，initgroups 语义）。libc 的 `initgroups()` 不是异步信号安全的，所以组列表在 fork **之前**解析（`getgrouplist`，缓冲区给大，溢出就加大重试）；子进程里只做系统调用（macOS 的 `initgroups(ngroups, gidset, gmuid)` 系统调用通过 gmuid 开启动态成员解析，或者用准备好的列表 `setgroups`），fork 后不做任何查询。系统仍然只给一部分时：记日志，并在 doctor 里如实显示，绝不悄悄丢掉。

### `--no-daemon` 时 aw 退出，子程序怎样跟着结束（13:51 更正）
- Linux（看门进程设 `PR_SET_CHILD_SUBREAPER`，进程关系 aw → 看门进程 → 程序，有没有 cgroup 都一样）和 Windows（Job Object `KILL_ON_JOB_CLOSE`）能清到孙程序，包括自己另起进程组的。细节（退出码转交、信号经看门进程转发、tcsetpgrp、SIGSTOP 再 SIGKILL 的清理循环、按 pid+ppid+启动时间防复用、看门进程自己单独一个进程组）见 A1 规矩 6（PM 14:04 定）。
- Mac：看门进程 + kqueue 会 `killpg` 整个进程组，但清不到自己 `setsid`/改了进程组的孙程序（macOS 没有 subreaper）。所以只有 Mac 的 `--no-daemon` 帮助单独一句（见 UI-147-wording.md），Linux 跟 Windows 用统一那句，Mac 的 doctor「aw 退出时清理子程序」一项也不写单纯的「可用」，带同样的说明。帮助快照按系统分开存。

### UI审查 13:50 新增文字（数据目录其余失败、option_not_wired）
- 路径含链接：「数据目录「{出问题的那一级路径}」是一个链接，后台不会顺着链接写数据，所以没有启动。请换成普通目录后再启动后台。」
- 纠正失败：「数据目录「{路径}」的权限改不过来，后台没有启动。原因：{中文原因}。请删掉这个目录后再启动后台。」
- 普通用户后台用的目录别人能写：「数据目录「{路径}」别的用户也能写，后台没有启动。请把权限改成只有你自己能写，或者换一个目录。」
- 普通用户后台用正式目录：「正式数据目录「{路径}」只能由管理员运行的后台使用。请用管理员运行后台，或者换一个自己的目录。」
- option_not_wired：「「{选项名}」本版本未接入，这次没有新建会话。请去掉这个选项再试。」
- 以上以 `/workspace/qa-issues/UI-147-wording.md` 为准，两边不一致时照那份文件。

### 345d216（Windows 第三轮）里的 `--no-daemon` 整树清理跟上面差在哪（14:05 核对）
- 345d216 在 Linux/Mac 上用的是 `NoDaemonTreeWatchdog`（`crates/aw-cli/src/cmd/run.rs`，约 1046-1112 行）：aw 用 `std::process::Command` 起一个 `/bin/sh`，它读 aw 留下的管道，读到 EOF 就 `kill -KILL -<程序的进程组>`；aw 正常退出前先写一行 `done`，避免打到被复用的进程组号。**它没有用 `PR_SET_CHILD_SUBREAPER`**，代码注释自己也写着「自己 `setsid`/换了进程组的程序能逃掉，Linux 上更强的是 cgroup」。
- 跟上面的决定比，差了这几处：看门进程是 aw 的**子进程、程序的兄弟**，不是程序的祖先，就算设了 subreaper 也收养不到程序的子孙；只按进程组 `killpg`，没有 SIGSTOP 再 SIGKILL 的扫描循环；不按（pid、ppid、启动时间）核对；而且这个 sh 跟 aw 在**同一个进程组**里（Command 默认不另起组）。按代码推断（没实测）：终端里按 Ctrl+C 或者终端挂断时，SIGINT/SIGHUP 会把这个 sh 一起打死，之后 aw 再死就没人清理了。
- 结论：345d216 的 Windows Job 部分符合上面的决定；Linux/Mac 的 watchdog 是过渡做法，第 4 步换成上面的设计（Linux 用 subreaper 看门进程，Mac 改成 kqueue 看门进程），并加 A1 那组测试。
