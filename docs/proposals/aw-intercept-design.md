# AgentWatch 拦截与改写方案（第一版）

> 状态：草案
> 最后更新：2026-10-21
> 关联：REQ-09、REQ-10、REQ-12（本方案新增）、ADR-0006、ADR-0008、ADR-0009、ADR-0012、ADR-0014（本方案新增，提议）、SPIKE-07、SPIKE-09
> 代码基线：`origin/dev` = `5d23e14`（下文 file:line 都按这个提交核对）
> 官方文档查询日期：2026-10-21（下文「官方文档」一节逐条给出链接）

## 0. 一句话结论

可以做，而且**大部分能力 agent 自己已经开放了**。由 `aw run` 启动 agent，最大的好处是能在启动前把「关卡」装好，不用改用户自己的配置文件。

- **拦截（拒绝）**：四层都能做，越往下越硬，越往下越难。
- **内容替换（改写）**：只有上面三层能做（agent 自带关卡、工具转接层、网络代理）。系统层只能「准 / 不准」，不能改内容。
- **改写的范围**：
  - Claude Code：能改「工具要执行的参数」（执行前）和「工具结果给模型看的内容」（执行后）；**不能改用户输入的提示词**，只能拒绝或附加说明。
  - Codex：能改「工具要执行的参数」（执行前）；执行后只能把结果整体换成一段说明，不能精细改；也不能改提示词。
  - 工具转接层（MCP）：请求和结果两个方向都能改，但只对 aw 包起来的本机 MCP 服务有效。
  - 网络代理：技术上能改请求和响应，但第一步只做「按规则拒绝」，不做改写（理由见 §4.3）。

## 1. 目标与非目标

### 1.1 目标

1. 通过 `aw run` 启动的 agent（第一步：Claude Code、Codex），在它**动手之前**按规则决定：放行、拒绝、改写、问用户。
2. 三个系统（Linux、macOS、Windows）用**同一套规则文件**、同一套动作。
3. 每一次拒绝、改写、问用户，都留**审计记录**：命中哪条规则、原来是什么（脱敏摘要 + 哈希）、改成了什么（脱敏摘要 + 哈希）、谁做的决定。
4. 规则**默认关闭**。不写规则、不打开开关时，行为和现在完全一样（只审计）。

### 1.2 非目标

- 不对抗有管理员权限、或者刻意绕开 aw 的 agent（见 §6）。
- 不改用户自己的 `~/.claude/`、`~/.codex/` 配置文件；只在本次启动生效。
- 第一步不改模型的 API 流量（不改 Anthropic / OpenAI 的请求和回复）。
- 第一步不做系统层（Landlock / ES / 驱动）拦截，放到第二步。
- 不保存文件内容、HTTP body、提示词原文（沿用 ADR-0012）。审计里的「原文」只存脱敏、截断后的摘要和哈希。

## 2. 现状核对（代码，基线 5d23e14）

| 部件 | 真实状态 | 依据 |
|---|---|---|
| `aw hook` | 永远以 0 退出、stdout/stderr 永远为空，**从不返回 deny**。文件头写明这是故意的 | `crates/aw-cli/src/cmd/hook.rs:3-5`、`:144-176`、`:178-184` |
| `aw hook` 发给后台 | 默认地址是 Unix socket / 命名管道（`endpoint.rs:209-222`），但 `write_frame` 发的是「4 字节长度 + JSON」（`hook.rs:126-142`），而后台的 socket 和管道说的是 HTTP（`crates/aw-daemon/src/api/ipc.rs:1-8`）。Unix 上用 `File` 打开 socket 本身就会失败（`hook.rs:122` 注释自己写了）。**按代码推断：不加 `--http` 时，hook 报告到不了后台**，只会被记成丢弃。【待验证】需要真机确认一次 | 同左 |
| 后台 hook 接收 | 只有回环 HTTP 的 `POST /api/v1/agent/hook`，不要票据，写 `agent_events` | `crates/aw-daemon/src/api/routes.rs:745-750`、`:853-880` |
| Claude Code 注入计划 | `plan_temp_settings` 能生成临时 `--settings` 文件内容（PreToolUse / PostToolUse / SessionStart / SessionEnd 都指向 `aw hook claude-code`），但**没有任何地方调用它**，`aw run` 不会注入 | `crates/aw-agent-adapters/src/agents/claude_code/mod.rs:99-144`；全仓 grep `plan_temp_settings` 只在适配器 crate 内 |
| Codex 适配 | 只有识别和 OTEL 映射，没有 hook 注入 | `crates/aw-agent-adapters/src/agents/codex/` |
| `aw run --self-report` | 直接拒绝，提示「本版本未接入」 | `crates/aw-cli/src/cmd/run.rs:1682-1700` |
| `aw run --mcp-tap` | 直接拒绝，不改 MCP 配置、不启动 | `run.rs:1686-1688` |
| `aw mcp-tap -- <cmd>` | 手动包装一个 stdio MCP 服务，双向**原样转发**字节，按行解析出标签打到 stderr；**不发给后台**（没有接收路由） | `crates/aw-cli/src/cmd/mcp_tap.rs:1-15`、`:76-174`、`:207` |
| 网络代理 | `MitmProxy`（hudsucker）能真的终止 TLS，handler 记录元数据后**原样转发**；请求和响应 body 被整个读进内存再转发（流式 SSE 会被攒完才发） | `crates/aw-proxy/src/server/mitm.rs:76`、`:280-311`、`:313-351`、`:353-361` |
| 代理有没有被用上 | **没有**。`aw run --proxy` 只打印注入计划然后退出，不监听端口（后台没有 tokio 运行时） | `run.rs:16-23`、`:1335-1364`；`MitmProxy` 在 aw-proxy 之外无人引用 |
| 证书被拒 | 已有 `--proxy-on-reject fail|tunnel` 两种处理 | `crates/aw-proxy/src/inject.rs:23-28` |
| 采集器 | 后台只接了轮询采样；三平台采集器只是「链接进来证明依赖存在」，没有启动 | `crates/aw-daemon/src/collectors.rs:5-26`、`crates/aw-daemon/src/runtime.rs:637-640` |
| 产品决定 | 需求和愿景都写着「不做拦截」；P5-AGENT-02 任务卡的「限制」也写着 hook 不能返回 deny | `docs/00-overview/requirements.md:96`、`docs/00-overview/vision.md:37`、`docs/04-plan/tasks/P5-agent-adapters.md` P5-AGENT-02「限制」 |

结论：**拦截需要的「接口」大部分在，但从「启动」到「判定」中间是断的**：hook 不会被自动装上、装上了报告也可能到不了后台、代理没跑起来、MCP 包装不会自动套上。第一步要先把这条链接通。

## 3. 官方文档核实结果（2026-10-21 查询）

只写查到的。没查到的写「未确认」。

### 3.1 Claude Code

来源：<https://code.claude.com/docs/en/hooks>、<https://code.claude.com/docs/en/cli-reference>、<https://code.claude.com/docs/en/sandboxing>（页面无版本号；本机 `claude --version` 为 2.1.304）。

| 事件 | 能拦吗 | 能改吗 | 原文要点 |
|---|---|---|---|
| `PreToolUse` | 能。`permissionDecision` 取 `allow` / `deny` / `ask` / `defer`；退出码 2 也是拦 | **能改工具参数**：`updatedInput` 替换整个参数对象，要带上没改的字段；改后的参数还会再过一遍权限规则。配 `allow` 直接执行，配 `ask` 把改后的参数给用户看 | 多个 hook 冲突时 `deny > defer > ask > allow`。`defer` 只在 `-p` 非交互模式有效 |
| `PermissionRequest` | 能，`decision.behavior` = `allow` / `deny` | 能，`allow` 时可带 `updatedInput` | 只在要弹权限框时触发 |
| `PostToolUse` | 不能撤销（工具已经跑完） | **能改模型看到的结果**：`updatedToolOutput`，必须符合该工具的输出格式，否则被忽略、用原结果；MCP 工具不校验格式 | 官方警告：只改模型看到的；文件已写、命令已跑；OTEL 遥测记的还是原结果 |
| `UserPromptSubmit` | 能，`decision: "block"` 或退出码 2 | **不能替换提示词**，只能用 `additionalContext` 附加说明 | 原文：“can't replace the prompt” |
| `MessageDisplay` | — | `displayContent` 只改屏幕显示，记录和模型看到的不变 | 对拦截没用 |

失败时的行为（对「后台挂了怎么办」很关键）：

- 默认：hook 超时、起不来、退出码不是 0 或 2，对 `PreToolUse` **都算放行**（走正常权限流程）。
- `onFailure: "block"`（command / http hook 可设，要求 v2.1.295 及以上）：失败等于拦截。
- hook 有 `http` 类型，可以直接 POST 到本机地址。
- 启动时注入：`--settings <文件或 JSON>` 只对本次会话生效；hook 在各层之间是**合并**而不是覆盖；项目里的 `disableAllHooks` 压不过 `--settings`。
- 会让我们的 hook 失效的情况：管理员策略 `allowManagedHooksOnly`、`--bare`、`--safe-mode`。
- Claude Code 自带沙箱：macOS 用 Seatbelt，Linux/WSL2 用 bubblewrap + socat；**原生 Windows 不沙箱**。
- `if` 字段的命令匹配是「尽力而为」，官方建议硬性规则用权限系统而不是 hook。

### 3.2 Codex CLI

来源：<https://developers.openai.com/codex/hooks>、<https://developers.openai.com/codex/agent-approvals-security>、<https://developers.openai.com/codex/rules>、<https://developers.openai.com/codex/cli/reference>（这些地址会显示为 learn.chatgpt.com 的页面；页面无版本号）。

| 事件 | 能拦吗 | 能改吗 | 原文要点 |
|---|---|---|---|
| `PreToolUse` | 能。`permissionDecision: "deny"`，或旧格式 `decision: "block"`，或退出码 2 | **能改工具参数**：`permissionDecision: "allow"` + `updatedInput`。Bash / `apply_patch` 必须带字符串 `command`；MCP 和其他本地工具是整个参数对象 | **`ask` 不支持**：返回 `ask` 会被当作 hook 失败、工具**照常执行** |
| `PermissionRequest` | 能，`allow` / `deny`，任一 `deny` 胜出 | 不能（`updatedInput` 是保留字段，现在会失败并拒绝） | 只在 Codex 本来就要问用户时触发 |
| `PostToolUse` | 不能撤销 | 只能用 `decision: "block"` 或 `continue: false` 把结果**整个换成一段说明**；`updatedMCPToolOutput` 已解析但不支持 | — |
| `UserPromptSubmit` | 能，`decision: "block"` 或退出码 2 | 不能改提示词，只能附加说明 | — |

其他要点：

- 覆盖范围：Shell、`exec_command`、`apply_patch`、MCP、其他本地函数工具都走 hook；**托管工具（如 WebSearch）不走 hook**。官方原话：hook 是“useful guardrail, not a complete enforcement boundary”。
- 失败时：文档写明 `PreToolUse` 回调出错、超时、格式不对，**可能不拦**（偏放行）。没有查到类似 Claude Code `onFailure` 的开关：**未确认**。
- 信任：非托管 hook 必须先被用户审阅信任；`--dangerously-bypass-hook-trust` 可在单次运行跳过信任（给已自行审核 hook 的自动化用）。
- 注入：`-c key=value` 能覆盖配置，hook 也能写在 `config.toml` 的 `[hooks]` 里；但**用 `-c` 临时注入 hook 是否生效：未确认**。`--profile` 叠加 `$CODEX_HOME/<名>.config.toml`，能否带 hook：未确认。
- 审批：`--ask-for-approval on-request|never`；沙箱 `--sandbox read-only|workspace-write|danger-full-access`。系统沙箱：macOS Seatbelt（`sandbox-exec`），Linux `bwrap` + `seccomp`，Windows MXC（旧的 elevated / unelevated 兜底）。
- 网络：`workspace-write` 默认不联网；`features.network_proxy` 可按域名放行/拒绝，但**不管** web search、MCP 连接、模型请求。
- exec policy（`.rules`，实验性）：`prefix_rule` 的 `allow` / `prompt` / `forbidden`，控制的是「**沙箱外**能跑哪些命令」；`codex exec --ignore-rules` 可以不加载。aw 能否只在本次启动塞一个 rules 文件：未确认。

### 3.3 系统层（公开资料）

- Linux Landlock：普通用户就能用，限制文件访问；从 ABI v4 起能限制 TCP 端口（v10 起 UDP）。只能「不准」，不能改内容。来源 <https://docs.kernel.org/userspace-api/landlock.html>。
- Linux seccomp 用户态通知：man 页明确写着不能拿它做安全决策（检查和使用之间有竞争窗口，参数可被改写）。所以 seccomp 只用来「直接拒绝某些系统调用」，不用来「问一下再放行」。来源 <https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html>。
- macOS Endpoint Security 的 AUTH 事件能「准 / 不准」，要苹果批的 `com.apple.developer.endpoint-security.client` 授权和 root；本仓库目前只用 NOTIFY（`docs/02-platforms/macos.md:77`），授权申请见 SPIKE-08（未开始）。
- Windows：文件和网络的硬拦截要 minifilter / WFP callout 驱动，需要 EV 签名和微软认证；ADR-0008 已决定 1.0 不做驱动。

## 4. 四层：能拦什么、能改什么

### 4.1 总表

| 层 | 能拦什么 | 能改什么 | Linux | macOS | Windows | 硬不硬 |
|---|---|---|---|---|---|---|
| ① agent 自带关卡（hook） | 每一次工具调用（命令、读写文件、MCP、子 agent）；提示词可整条拒绝 | Claude：工具参数、工具结果；Codex：工具参数 | 同 | 同 | 同（Claude 在 Windows 上 hook 默认走 Git Bash，没装时走 PowerShell；我们用 exec 形式绕开 shell） | 软：agent 自己的机制，配置可能被关掉；看得最懂 |
| ② 工具转接层（`aw mcp-tap`） | 某个 MCP 工具调用（按方法名、工具名、参数） | 请求参数、返回结果，两个方向都能改 | 同 | 同 | 同 | 中：只管被 aw 包起来的 stdio MCP；远程 HTTP MCP 走 ③ |
| ③ 网络代理（会话 CA） | 连哪个域名、哪个 URL、哪个方法 | 技术上能改请求和响应；第一步不做 | 同 | 同 | 同 | 中：只管听代理环境变量、信任会话 CA 的流量；`curl --noproxy` 之类能绕过 |
| ④ 系统层 | 文件路径、网络端口、某些系统调用 | **不能改内容** | Landlock + seccomp，普通用户可用 | Seatbelt（普通用户可用；Codex、Claude Code 文档都写明在用）；ES AUTH 要苹果授权 | 要驱动（ADR-0008 不做）；用户态只能 Job / 受限令牌，粒度粗 | 硬：绕不过，但看不懂语义 |

### 4.2 第 ① 层细节

- 启动注入：
  - Claude Code：`aw run` 写一个只属于本会话的临时 settings 文件（只含 `hooks`），用 `--settings <path>` 传入。hook 用 **exec 形式**（`command` = aw 的绝对路径，`args` = `["hook","claude-code","--session",<id>]`），不依赖 PATH 和 shell；打开拦截时加 `onFailure: "block"`（需 v2.1.295+，低于此版本要提示「失败时无法保证拦住」）。
  - Codex：第一步先做**判定逻辑和输出格式**（能 deny、能 `allow+updatedInput`），注入方式（`-c` 还是临时 profile、是否需要 `--dangerously-bypass-hook-trust`）是**未确认**项，要真机验证后再自动注入；验证前只提供手动配置片段。
- 规则在哪判定：在 `aw hook` 进程里**本地判定**，不等后台。理由：hook 有时间预算，后台可能不在。审计记录异步发给后台，发不出去时落本地备份文件（见 §5.4）。
- 「问用户」：
  - Claude Code：直接用 `ask`，由 Claude Code 自己弹框（改写后的参数也会给用户看）。
  - Codex：`ask` 不支持，会变成放行。所以 Codex 上「问用户」**降级为拒绝**，理由里写「这一步需要你确认，请在 aw 里放行后重试」。审计里记 `downgraded: ask→deny`。

### 4.3 第 ③ 层为什么第一步不改写

- 现在的 handler 会把 body 整个攒进内存（`mitm.rs:288-311`、`:323-350`），改写就意味着要缓冲完整的流式回复，会把 agent 的流式输出卡住。
- 改模型 API 的请求或回复，等于替 agent「改脑子」，风险大，也可能违反服务条款；而且 ADR-0012 不允许存 body，审计「原文摘要」很难做得诚实。
- 所以第一步只做：按域名 / URL / 方法**拒绝**，返回 403 和一句中文原因，并记审计。改写留到以后单独评估。

### 4.4 第 ④ 层（第二步）

- Linux：`aw run` 启动 agent 前，在子进程里套 Landlock（只准写项目目录和临时目录、只准连指定端口）+ seccomp（直接拒绝少量危险调用）。这是「兜底」：agent 自己的关卡被关掉也挡得住。
- macOS：先用 Seatbelt 做同样的兜底；ES AUTH 等 SPIKE-08 授权批下来再说。
- Windows：只做监控和提醒；不做驱动。

## 5. 统一规则

### 5.1 规则文件

TOML，一个文件，三系统通用。默认不存在 = 不拦截。

```toml
# ~/.config/agentwatch/policy.toml（路径按平台，见实现）
version = 1
enabled = true            # 总开关，缺省 false
on_error = "deny"         # 规则读不了、判定出错时：deny | allow，缺省 deny（见 §5.3）

[[rule]]
id = "no-rm-rf"
layer = ["hook"]          # hook | mcp | proxy，可多选
agent = ["claude-code", "codex"]   # 缺省 = 全部
tool = ["Bash"]           # 工具名，hook/mcp 层用
match.command = { regex = '\brm\s+-rf\b' }
action = "deny"
reason = "不允许递归删除"

[[rule]]
id = "force-dry-run"
layer = ["hook"]
tool = ["Bash"]
match.command = { prefix = "terraform apply" }
action = "rewrite"
rewrite.command = { replace = ["terraform apply", "terraform plan"] }
reason = "只允许 plan"

[[rule]]
id = "ask-before-push"
layer = ["hook"]
tool = ["Bash"]
match.command = { regex = '^git push' }
action = "ask"

[[rule]]
id = "block-paste-sites"
layer = ["proxy"]
match.host = { glob = "*.pastebin.com" }
action = "deny"
reason = "不允许连这个网站"
```

- 匹配字段：`tool`、`agent`、`match.command`、`match.path`、`match.host`、`match.url`、`match.method`、`match.mcp_method`、`match.mcp_tool`、`match.arg.<字段名>`；每个字段支持 `exact` / `prefix` / `glob` / `regex`。
- 规则按文件顺序检查，**多条命中时取最严**：`deny > ask > rewrite > allow`（和 Claude Code 的优先级一致）。
- `rewrite` 只允许「字段级替换」（某个字段换值、字符串替换），不允许写脚本。改写后再用全部规则检查一遍，被 `deny` 命中就拒绝（防止改出危险命令）。

### 5.2 四个动作

| 动作 | hook 层（Claude） | hook 层（Codex） | MCP 层 | 代理层 |
|---|---|---|---|---|
| 放行 `allow` | 不输出决定（走 agent 自己的权限流程），**不是**自动批准 | 同左 | 原样转发 | 原样转发 |
| 拒绝 `deny` | `permissionDecision: deny` + 原因 | `permissionDecision: deny` + 原因 | 不转给服务端，直接回一个 JSON-RPC 错误 | 回 403 + 原因 |
| 改写 `rewrite` | `allow` + `updatedInput`（PreToolUse）；`updatedToolOutput`（PostToolUse） | `allow` + `updatedInput`（PreToolUse） | 改写请求参数或返回结果后转发 | 第一步不支持，按 `deny` 处理并在审计里写明 |
| 问用户 `ask` | `permissionDecision: ask` | 降级为 `deny`（见 §4.2） | 第一步降级为 `deny` | 第一步降级为 `deny` |

注意「放行」不等于「自动批准」：aw 不替用户点同意，只是不插手。

### 5.3 后台挂了 / 判定出错时：默认放行还是拒绝

因为规则在 `aw hook` / `aw mcp-tap` / 代理进程本地判定，**后台挂了不影响判定**，只影响审计写入。真正要定的是两件事：

1. **判定本身出错**（规则文件坏了、hook 超时、aw 程序找不到）：
   - 建议：**拒绝**（`on_error = "deny"`）。理由：用户打开拦截就是要「挡住」，出错时放行等于没装。Claude Code 用 `onFailure: "block"` 保证这一点；Codex 文档说出错可能放行，这一点要在界面上如实写明。
   - 规则文件不存在或 `enabled = false`：当作没开，全部放行（保持现状）。
2. **审计写不进去**（后台不在、本地备份也写不了）：
   - 建议：拒绝和放行照常；**改写降级为拒绝**。理由：改写是 aw 替 agent 改了东西，没留痕迹就不能改。
   - 这两条都**待用户定**（§9 第 1、2 问）。

### 5.4 审计痕迹

每次 `deny` / `rewrite` / `ask`（以及降级）写一条记录：

| 字段 | 内容 |
|---|---|
| `session`、`agent`、`layer`、`event` | 哪个会话、哪个 agent、哪一层、哪个事件（如 PreToolUse） |
| `rule_id`、`action`、`effective_action` | 命中规则、规则写的动作、实际执行的动作（降级时两者不同） |
| `tool` / `host` / `mcp_method` | 对象 |
| `before_summary`、`before_hash` | 原文**脱敏后**截断到 256 字的摘要 + 原文 SHA-256（加会话盐） |
| `after_summary`、`after_hash` | 改写后的同样两项（只有改写才有） |
| `reason` | 给 agent / 用户看的原因 |
| `evidence`、`source` | `E3`（agent 自报告链路）或 `S`（aw 自己的代理 / 转接层做的决定）；`source` 如 `intercept.claude-code/hook` |
| `delivered` | 后台收到 / 写入本地备份 / 都失败 |

- 不存原文全文，不存 body，不存提示词全文（ADR-0012）。脱敏走管道现有 Redact 规则。
- 投递：先发后台（新路由，见 §7）；发不出去时追加到会话目录下的 `intercept-audit.jsonl`（只有本用户可读），后台下次起来再收。两边都失败时按 §5.3 第 2 条处理，并记一条 `Gap`（`gap_kind = intercept_audit_dropped`）。

## 6. 安全边界（要写在界面和文档里）

- **agent 以管理员 / root 身份运行时，aw 管不住**：它可以改 aw 的规则、杀掉 aw、关掉 hook。第一步检测到目标以 root / 提权运行时，提示「拦截不可靠」。
- **agent 能改自己的配置**：Claude Code 的 `--settings` 比项目配置优先，项目里的 `disableAllHooks` 压不过；但管理员策略 `allowManagedHooksOnly`、`--bare`、`--safe-mode` 会让我们的 hook 不跑。`aw run` 发现这些参数时要提示。
- **hook 只管工具调用**：agent 自己访问模型 API、Codex 的托管工具（WebSearch）不走 hook。
- **代理能被绕过**：程序不读代理环境变量、或自己带证书库，就看不到、拦不住。
- **证书被拒（证书固定）时**：
  - `--proxy-on-reject fail`（默认）：连接失败，审计记 `cert_pinned`；对打开了拦截的会话，这是建议做法（宁可断，不可漏）。
  - `tunnel`：不解密，只能按 CONNECT 的主机名拒绝或放行，URL 级规则不生效，审计里写明 `NA(cert_pinned)`。
- **系统层只在第二步**：第一步所有拦截都是「软」的，agent 存心绕过就能绕过。文案不能说「已阻止所有……」，只能说「aw 在 XX 层拒绝了这一次调用」。

## 7. 第一步范围

**做**（三系统同一套代码，全部在平台无关 crate 里，满足 AGENTS.md §6）：

1. 规则：新模块（建议 `crates/aw-core` 定义类型、`crates/aw-pipeline` 或新 crate `aw-policy` 做加载和判定），TOML 解析、四个动作、多条命中取最严、改写后复检、`on_error`。纯函数，单元测试覆盖。
2. `aw hook`：读规则 → 判定 → 按 agent 输出对应 JSON（Claude / Codex 两套格式）。**规则缺省为关**时，行为和现在逐字节一致（现有测试继续过）。
3. Claude Code 注入：`aw run --agent claude-code --intercept`（或规则开启时）真正写临时 settings 并加 `--settings`，hook 用 exec 形式 + `onFailure: block`。
4. Codex：判定和输出格式；手动配置片段；自动注入等真机验证（未确认项）。
5. `aw mcp-tap`：按规则拒绝（回 JSON-RPC 错误）或改写请求参数 / 返回结果；不开规则时仍原样转发。
6. `aw-proxy`：`RecordingHandler` 按规则返回 403；不开规则时行为不变。注意：代理目前没有被 `aw run` 拉起（§2），所以第一步这一层**只到库和测试**，接到启动链路是后续任务。
7. 审计：记录结构、脱敏、本地备份文件；后台新路由 `POST /api/v1/agent/intercept` + 新迁移 `0012_intercept_events.sql`（API 和迁移变更必须串行，见 AGENTS.md §8）。
8. 顺手修：`aw hook` 走默认 socket / 管道时要说 HTTP（§2 第 2 行），否则审计永远到不了后台。
9. 文档：本方案、ADR-0014、requirements / vision 的「不做拦截」改写、P5-AGENT-02 任务卡「限制」改写、新任务卡。

**不做**（第二步及以后）：Linux Landlock/seccomp 兜底、macOS Seatbelt/ES、Windows 任何系统层、代理改写、提示词改写、UI 弹窗「问用户」、Cursor/Aider 等其他 agent。

## 8. 验收标准

- [ ] 规则缺省（无文件 / `enabled=false`）：`aw hook` 输出为空、退出 0，现有 hook / mcp-tap / proxy 测试全部不改期望值仍通过。
- [ ] Claude 格式：一条 `rm -rf` 的 PreToolUse 载荷 → 输出 `permissionDecision: "deny"`；`terraform apply` → `allow + updatedInput`，`updatedInput` 保留其他字段；`git push` → `ask`。
- [ ] Codex 格式：deny 与 `allow + updatedInput`（Bash 带字符串 `command`）；`ask` 输出为 deny 且审计标 `downgraded`。
- [ ] 多条命中取最严；改写后被 deny 命中 → 最终 deny。
- [ ] `on_error=deny` 时规则文件损坏 → 拒绝；`on_error=allow` → 放行；两种都有审计或 Gap。
- [ ] mcp-tap：命中 deny 的 `tools/call` 不到达服务端，客户端收到 JSON-RPC 错误（同一个 `id`）；改写后的参数到达服务端；未命中逐字节透传。
- [ ] 代理：命中 deny 的请求得到 403，不连上游；未命中照旧。
- [ ] 审计：每次 deny / rewrite / ask 恰好一条记录；记录里没有 `sk-`、`Bearer` 等明文（复用 `redact_corpus/`）；后台不在时写入本地备份文件。
- [ ] `cargo fmt --all --check`、`cargo clippy --workspace --all-targets -D warnings`、相关 crate 测试通过；`cargo xtask wording-lint` 通过。
- [ ] 真机（第一步结束前，至少 Linux 一台）：`aw run --agent claude-code` 下让 Claude 跑 `rm -rf /tmp/x`，被拒绝、界面有中文原因、审计可查。Mac、Windows 各跑一次，没跑的如实标「未验证」。

## 9. 待用户决定

1. 判定出错时（规则坏了、hook 超时、aw 找不到）：**拒绝**（建议）还是放行？
2. 审计写不进去时：改写降级为拒绝（建议），还是照样改写？
3. 「问用户」在 Codex 上降级为拒绝（建议），还是放行并提醒？以后要不要做 aw 自己的弹窗？
4. 网络代理要不要做内容改写？（建议第一步不做，以后单独评估，尤其不改模型 API 流量）
5. 规则文件放哪、谁能改：只放用户目录（建议），还是允许项目目录里的规则（会被 agent 自己改）？
6. 检测到 agent 以 root / 管理员运行时：拒绝启动、还是启动但提示「拦截不可靠」（建议后者）？
7. 证书被拒时，打开了拦截的会话是否强制 `fail`（建议是）？
8. 第二步 Linux 系统层兜底的默认范围：只准写项目目录 + 临时目录（建议），还是由规则配置？
9. Codex 自动注入需要 `--dangerously-bypass-hook-trust`（如真机验证需要）：能否接受由 aw 替用户加这个参数？

## 10. requirements.md / vision.md 修改草稿

- `requirements.md` §3 非目标，原「不做阻断/拦截（只审计）；拦截能力可在 P5 之后评估。」改为：
  「不做系统层强制拦截（第二步再做 Linux 兜底）；默认只审计。启动模式下的可选拦截与改写见 REQ-12。」
- `requirements.md` 新增：
  「### REQ-12 启动模式下的可选拦截与改写（S）
  通过 `aw run` 启动的 agent，可按用户规则在 agent 自带关卡、工具转接层、网络代理三层放行、拒绝、改写或问用户。规则缺省关闭；每次拒绝、改写、问用户都留审计（脱敏摘要 + 哈希）；不保证拦住有管理员权限或刻意绕过的程序。详见 [拦截方案](../proposals/aw-intercept-design.md)、ADR-0014。」
- `vision.md` §4 非目标，原「不做拦截或阻断（1.0 之前只审计）；」改为：
  「默认只审计；拦截与改写是可选功能，只在 `aw run` 启动的会话里、用户写了规则后生效，不承诺拦住刻意绕过的程序；」

（以上已在同一提交中写入对应文件，ADR-0014 状态为「提议」，用户确认后改为「已接受」。）

## 11. 风险

| 风险 | 应对 |
|---|---|
| agent 更新后 hook 格式变化 | 适配器按 agent 版本测试；载荷解析失败按 `on_error` 处理并记 Gap |
| Codex 出错时放行 | 文档和界面如实写明；第二步系统层兜底 |
| 改写出 bug，执行了不该执行的东西 | 改写后复检；改写只允许字段级替换；审计留前后哈希 |
| hook 拖慢 agent | 本地判定，不等后台；规则编译结果缓存 |
| 误伤正常工作 | 规则缺省关；先在单会话试用；审计可查每一次拒绝 |
