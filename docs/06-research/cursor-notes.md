# Cursor 适配笔记（P5-AGENT-06）

> 状态：未在真机验证
> 最后更新：2026-10-09
> 关联：[P5-AGENT-06](../04-plan/tasks/P5-agent-adapters.md)、[SPIKE-04](SPIKE-04-proxy-trust-injection.md)、[SPIKE-07](SPIKE-07-agent-hooks.md)、[network-attribution §5.2](../01-architecture/network-attribution.md)、[process-tracking §6](../01-architecture/process-tracking.md)
>
> 本文不是 SPIKE 结论。SPIKE-04 与 SPIKE-07 在 [索引](README.md) 里仍是「未开始」。下面只记录本卡实现了什么、哪些数字还没有。

## 1. 实测状态

未在真机验证。

- 没有启动 Cursor，没有枚举本机进程，没有进程树截图。
- 没有跑 `aw run --agent auto --proxy -- cursor`，因此没有 `aw http` / `aw flows` 的记录。
- 没有代理覆盖率数字。不写占比，也不写“经过代理 / 直连”的计数。
- 没有核对 Cursor 或 Electron 的安装版本。

人工验收（任务卡两条）标为未执行。

## 2. 本卡代码做了什么

纯函数，在 `crates/aw-agent-adapters/src/agents/cursor/`：

| 函数 | 行为 | 不做的事 |
|---|---|---|
| profile `cursor` | 用可执行文件名识别主进程（`Cursor` / `cursor`，含 `.exe`） | 不把 `node` 或 `Cursor Helper` 当成 Agent 根 |
| `classify_role` | 按 argv 标子进程角色：`renderer`、`utility`、`extension-host`、`terminal-shell`，以及已有的 `mcp_server` 形态 | 不读进程表；角色是 argv 标注，不是已证实的职责 |
| `plan_launch` | 调用方传入“已有实例”时，返回“请退出后重启，或改用附着模式”；调用方传入“用户坚持启动”时带上 `attribution_break` | 不自己判断本机有没有 Cursor |
| `plan_proxy` | `--proxy` 时给出追加 `--proxy-server=<endpoint>` 的参数 | 不设置 CA 环境变量，不安装证书，不改 Cursor 安装目录或用户设置 |

`profiles/cursor.toml` 的 `self_report = []`。本卡不接入 E3。

## 3. 待验证

这些项在代码注释和 `plan_proxy` 的说明里保持【待验证】，本文不给是或否。

1. **Electron 是否认 `NODE_EXTRA_CA_CERTS`。** SPIKE-04 表格把 Electron / Chromium 的 CA 写成“用系统证书库”，并预期代理覆盖不到、标为直连。同一格没有在真机上填过结果。本卡不声称认，也不声称不认。
2. **Chromium 网络栈是否只认系统证书库。** 同上。需要系统证书库时，只能提示用户自行执行 `aw proxy trust --user` 并阅读风险说明；本工具不代为安装。
3. **`--proxy-server=` 是否被当前 Cursor 版本转给 Chromium。** 参数计划按 network-attribution §5.2 与任务卡写出。未对二进制确认。
4. **第二次启动是否把工作交给已有实例。** 任务卡把它当作归属中断的典型情况。`plan_launch` 只在调用方声明已有实例且用户坚持时打上 `attribution_break`。没有录到一次真实的二次启动。
5. **终端命令由哪个进程执行。** SPIKE-07 §5.3 写明文档没有给出 OS 进程名。`terminal-shell` 只匹配常见 shell 文件名（`bash`、`zsh`、`fish`、`sh`、`pwsh`、`powershell`、`cmd`）。命中不等于“这就是 Cursor 的终端宿主”。
6. **公开 hooks 能否在不改用户配置的情况下接入。** SPIKE-07 正文 §5.3（查阅日期 2026-10-07）写有 hooks 页，同时写明没有一次性启动参数的记载。索引状态仍是未开始，任务卡要求未确认则 `self_report = []`。本卡按任务卡留空，不复用 P5-AGENT-02 的通道。
7. **主进程可执行文件名。** profile 里的 `Cursor` / `cursor` 来自产品名，不是一次录制。SPIKE-07 §5.3 将 exe 名标为【待验证】。

## 4. 直连标注（未计数）

代理计划说明：未经过会话代理的流量按直连标注，URL 记 `NA(direct_bypass_proxy)`。这是字段原因，不是一条已观测的流量。覆盖率留空，等真机验收后再填，并且只填当时测到的会话，不外推。

## 5. 人工验收（未执行）

- [ ] 无已有实例时：`aw run --agent auto --proxy -- cursor`，让 Agent 执行一条终端命令。核对终端子进程是否归到会话。把该次 `aw http @last` 与 `aw flows @last` 里经过代理和直连的计数写进本文第 4 节。记录 Cursor 版本与平台。
- [ ] 已有实例时：CLI 出现“请退出后重启，或改用附着模式”。用户坚持启动后，时间线上出现归属中断标注。记录版本与平台。

两条都还没做。
