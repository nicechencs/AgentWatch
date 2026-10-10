# AgentWatch 第二包：#144 下一包清单

#144（squash 为 `dev` 上的 d55b59f）之后的下一包。勾选状态以 PR 正文为准，本文件只记录范围。

## 后台与 CLI

- adopt 前不放行 exec 做扎实：Windows 用 CREATE_SUSPENDED 起进程、adopt 后 ResumeThread；macOS、Windows 也提前写根进程行
- adopt 比对 real/effective/saved 三个 uid，并锁定进程启动时间；启动时间存 ns（/proc stat ticks 或平台 API），不再是秒级
- `/exit` 与 `record_root_exit` 按 proc_uid（会话、pid、启动时间）找根进程行，重用的 pid 拿不到别人的退出码
- 闸门管道用 pipe2(O_CLOEXEC)，读端不泄漏进目标进程
- `/exit` 没更新到行时记日志；`/adopt` 写库失败记日志
- e2e 断言根进程行的退出码（不是会话的），回退修复时必须失败
- `aw sessions show`：缺 pinned 显示「没采」而不是未置顶；打印退出码
- API 错误中英文措辞统一；主组为 0 的正当用户不再被拒
- CI：ubuntu 上用 sudo 跑 ignored 的 root 测试
- `aw export` 经后台导出自己的会话
- `aw procs <别人的会话>` 报错里显示会话 id，不再是空反引号
- 清理过时注释

## 界面

由另一位 worker 在同一分支完成。
