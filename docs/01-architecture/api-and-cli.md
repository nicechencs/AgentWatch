# 本地 API 与 CLI

> 状态：草案
> 最后更新：2026-10-10
> 关联：REQ-02、REQ-05、REQ-07.6、REQ-11、[ADR-0005](../03-adr/0005-privileged-daemon-split.md)、[storage](storage.md)、[ui](ui.md)、[inter-agent-communication](inter-agent-communication.md)

## 1. 通信与鉴权

| 通道 | 平台 | 用途 | 鉴权 |
|---|---|---|---|
| Unix 域 socket `/run/agentwatch/api.sock`（Linux）、`/var/run/agentwatch/api.sock`（macOS） | Linux / macOS | CLI 主通道 | `SO_PEERCRED` / `LOCAL_PEERCRED` 拿到对端 uid；socket 权限 0660，属组 `agentwatch` |
| 命名管道 `\\.\pipe\agentwatch-api` | Windows | CLI 主通道 | `GetNamedPipeClientProcessId` + 客户端 token 拿到 SID；管道 DACL 允许 Administrators + `AgentWatch Users` 组 |
| HTTP `127.0.0.1:<port>`（默认 7456，`api.http_port` 可配置，`0` 关闭） | 全平台 | Web UI | Bearer token（见下）；校验 `Host` 头必须为 `127.0.0.1:<port>` 或 `localhost:<port>`，防 DNS rebinding；不开 CORS |

内部通道的实现状态（2026-10-10）：
- Linux / macOS：`agentwatchd` 前台运行时监听 Unix socket（`crates/aw-daemon/src/api/ipc.rs`）；报文与 HTTP 相同（HTTP/1.1 请求和响应），不带 `Authorization`，也不做 `Host` 校验。只提供 `/health` 和 `/api/v1/*`，不提供页面资源。socket 与 HTTP 共用同一份状态，所以在 socket 上签的 ticket 可以在 HTTP 上兑换。
- 路径顺序由 `crates/aw-channel` 统一，daemon、`aw`、桌面 App 一致：先系统路径（Linux `/run/agentwatch/api.sock`，macOS `/var/run/agentwatch/api.sock`），再按用户路径（Linux `$XDG_RUNTIME_DIR/agentwatch/api.sock`，无则 `$HOME/.local/state/agentwatch/api.sock`；macOS `$HOME/Library/Application Support/AgentWatch/api.sock`）。daemon 建不了系统路径（非 root 运行）时自动改绑按用户路径；客户端取第一个存在的。`AW_SOCKET` 覆盖全部。
- 权限：存在 `agentwatch` 组时 socket 为 `root:agentwatch 0660`；没有该组时为 `0666`，任何本机账户都能连，但每个请求都按对端 uid 判身份（普通用户只看自己的会话）。所以 root 跑的 daemon 普通用户的桌面 App 也连得上。
- 对端身份：Linux 用 `SO_PEERCRED`，macOS 用 `getpeereid`（即 `LOCAL_PEERCRED` 的 uid）；uid 0 为管理员；读不到 uid 记为 `unverified-peer`、非管理员。
- Windows：`agentwatchd` 在 `\\.\pipe\agentwatch-api` 上监听（tokio 命名管道），报文同上。管道带显式 DACL（`crates/aw-collector-windows/src/pipe.rs`）：SYSTEM、Administrators、管道属主完全控制；`AgentWatch Users` 组（不存在时退到交互用户 `IU`）可读写但不能新建管道实例。客户端身份按 `GetNamedPipeClientProcessId` → 进程令牌取 SID；令牌已提权或为 LocalSystem 才是管理员。取不到身份的连接直接 403。
- 只走内部通道的 daemon 控制：`POST /api/v1/daemon/stop`（`aw daemon stop` / `restart`）和 `GET /api/v1/daemon/logs?tail=N|offset=B`（`aw daemon logs [-n N] [-f]`），只允许管理员或 daemon 自己的账户。`POST /api/v1/auth/ui-ticket` 的回复在内部通道上多带 `http_port`：HTTP 监听实际绑定的端口，`0` 表示 HTTP 关闭。
- 客户端错误分类（`aw_channel::DialError`）：只有"不存在 / 连接被拒"算服务没运行（`daemon_unreachable`，`aw` 退出码 3）；权限不足单独报（`daemon_forbidden`，退出码 4）；管道实例全忙短暂重试 2 秒（`daemon_busy`）；超时 `daemon_timeout`。
- `aw daemon start` 在通道无响应时拉起 `agentwatchd --foreground`（`AW_DAEMON_CONFIG` 作为 `--config` 传入）并等待 `/health`；子进程提前退出会直接报出；等不到就把拉起的进程停掉再报错，不留孤儿进程。不注册系统服务。

CLI 和 UI 请求到达后走同一套 axum 路由。传输层不同，但请求体和响应体完全一致。

**会话令牌（UI）**
1. `aw ui` 经由 socket 或管道向 daemon 申请一个一次性 `ui_ticket`，60 秒有效。ticket 与 token 都是操作系统 CSPRNG 生成的 256 位随机数（十六进制），签发、兑换、校验用同一个时钟，过期即拒；过期未兑的 ticket 在下次签发时清掉。
2. 用 `http://127.0.0.1:<port>/#ticket=<t>` 打开浏览器。`<port>` 取 daemon 随 ticket 返回的 `http_port`（HTTP 实际绑定的端口，跟随 `api.http_port`）；`--port` 可强制指定；`http_port` 为 `0`（HTTP 关闭）时 `aw ui` 直接说明 HTTP 已关闭、请用桌面 App，不打开链接。
3. 前端用 ticket 换取 `ui_token`（12 小时）。token 存在内存，并镜像到本标签页的 sessionStorage，同一标签页刷新仍保持登录，不需要再用一次 ticket；不写 localStorage，新标签页或重开浏览器不会继承。之后的请求都带 `Authorization: Bearer <ui_token>`。
   - 本机预览（`debug.preview_ui = true`）：`GET /` 签一张票并 302 到 `/index.html#ticket=<t>`。片段不会发回服务端，所以落点必须是不会再触发签票的路径，否则会无限跳转；前端换票后把地址改回 `/`。
   - `Content-Security-Policy`（含 `frame-ancestors 'none'`）只由 daemon 在响应头下发，`index.html` 不带 CSP meta：浏览器会忽略 meta 里的 `frame-ancestors` 并在控制台报错。
4. token 与申请者的用户身份绑定。

**授权模型**
- 普通用户只能看到自己发起的会话（`sessions.user_id`）。
- 管理员（root / Administrators）可以看到全部会话。
- 附着到属于其他用户的进程需要管理员权限。
- 针对配置修改、删除他人会话、开启 uprobe 这三类操作的端点，只对管理员开放。

## 2. CLI 命令树

全局参数：
- `--json`：机器可读输出；
- `--socket <path>`；
- `--lang zh|en`；
- `-q/--quiet`；
- `-v/--verbose`。

退出码：`0` 成功；`1` 一般错误；`2` 参数错误；`3` daemon 不可达；`4` 权限不足；`run` 透传目标进程的退出码。

本构建中，`aw run` 默认先调用 `POST /sessions/run`，再由 CLI 以调用者身份启动目标程序并调用 `/sessions/{sid}/adopt`；`--env` 仅传给该子进程，不会传给 daemon。`aw attach --pid` 调用 `POST /sessions`（`mode:"attach"`），`aw stop` 调用 `POST /sessions/{sid}/stop`。三者都走与 `aw ui`、`aw daemon stop` 相同的内部通道（socket / 命名管道），daemon 不可达退出码 3，通道无权限或 403 退出码 4。默认 `aw run` 结束后的摘要来自 `GET /sessions/{sid}` 的 `stats`，是目标退出那一刻 daemon 已记录的数字。默认 `aw run` 不接受 `--no-follow-children`（daemon 轮询采样器总是跟随子进程），需要时用 `--no-daemon`。`aw run --no-daemon` 不连接 daemon，保留 CLI 内的本地轮询路径；Linux 上先尝试把子进程放进委派的 cgroup v2 会话目录，本机没有可委派的 cgroup（cgroup v1，或 `cgroup.subtree_control` 没有委派控制器、目录不可写）时退化为按进程树跟踪（scope_pids），照常启动并透传退出码，摘要里写明「没采：cgroup 会话范围」（`--json` 的 `launch_note`）；只有连这样也启动不了程序时才报错。默认 `aw run` 不用 cgroup：子进程由 CLI 直接启动，daemon 按 adopt 的 pid 轮询跟踪进程树，会话的 `collectors` 照实列出没采的类别。记录仅在 Linux 可用；其他平台的会话创建返回 `503 collector_unavailable`，应改用 `--no-daemon`。

`aw attach --name`、`--no-follow-children`、`--no-existing-children` 和 `--move-to-cgroup` 在当前 daemon 轮询采样器中没有对应能力，CLI 会明确拒绝这些参数；请用 `aw ps` 找到 pid 后传入 `--pid`。

```text
aw
├── run [OPTIONS] -- <CMD> [ARGS...]        启动模式
│     --agent <id|auto>                    标注 Agent 类型（默认 auto）
│     --name <text>                        会话名
│     --proxy                              启用 MITM 代理以获取完整 URL
│     --proxy-on-reject <fail|tunnel>      客户端拒绝会话 CA 时的行为（默认 fail）
│     --no-follow-children                 只监控根进程
│     --include-proc <name>...             把会话外的指定守护进程纳入（归属为 I）
│     --self-report <auto|off|hooks|otel>  E3 接入方式
│     --cwd <dir>  --env K=V...            覆盖工作目录 / 追加环境变量
│     --summary <none|short|full>          结束时打印摘要（默认 short）
│     --pin                                会话不参与自动清理
│     --group <name>                       加入监控组（独立启动的多 Agent 组合，REQ-11）
│     --mcp-tap                            启动模式下注入 stdio 包装器，记录 MCP method / 工具名（E2）
│     --no-daemon                          不连 daemon，在 CLI 进程内跑轮询采集器（全部 S 级，ADR-0005）
│     --raw <file>                         调试：另写未聚合原始事件 JSONL（有大小上限，ADR-0011）
│     --unsafe-no-redact                   （管理员）关闭内置脱敏；会话被永久标记（ADR-0012）
├── attach [OPTIONS] (--pid <PID> | --name <pattern>)
│     --no-follow-children
│     --no-existing-children               不纳入附着时已有的子进程
│     --move-to-cgroup                     （Linux）把子树移入会话 cgroup
│     --agent / --name / --pin / --group   同 run（附着模式不支持 --mcp-tap）
│     --until-exit | --duration <dur>      结束条件（默认：根进程退出或 Ctrl-C）
├── stop <SESSION>                         停止监控（不杀进程）
├── ps [--agents-only] [--filter <text>]   列出可附着的进程（树状，经内部通道读 daemon 的 GET /processes；非管理员只看自己的进程）
├── sessions
│   ├── list [--since <time>] [--agent <id>] [--active] [--limit N]
│   ├── show <SESSION>                     概览：统计、发现、缺口、采集器能力
│   ├── rename <SESSION> <name>
│   ├── pin|unpin <SESSION>
│   └── delete <SESSION>... [--yes]
├── timeline <SESSION> [--filter <expr>] [--from <t>] [--to <t>] [--follow] [--limit N]
├── procs <SESSION> [--tree] [--filter <expr>]
├── files <SESSION> [--filter <expr>] [--group-by path|dir|proc] [--sort <field>]
├── flows <SESSION> [--filter <expr>] [--group-by domain|ip|proc|port] [--sort up|down|total]
├── http <SESSION> [--filter <expr>]
├── findings <SESSION> [--min-severity info|notice|warn] [--evidence <list>]
├── gaps <SESSION>
├── around <SESSION> <TABLE>:<ID> [--window 10s]   查看某条记录前后的事件（REQ-05.4）
├── search <TEXT> [--since <time>] [--kind file|proc|url]   跨会话搜索
├── export <SESSION> [--format jsonl|csv|md] [-o <file>] [--filter <expr>]
│     [--include agents,links,rpc]
│     [--redact-paths] [--redact-hosts] [--lang zh|en]
├── ui [--no-open] [--port N]              打开本地 Web UI
├── doctor [--json] [--perf]               自检：权限、内核/系统版本、采集器可用性、能力矩阵实测；--perf 输出资源占用与降级级别
├── daemon
│   ├── status | start | stop | restart
│   ├── install | uninstall [--purge]      安装/卸载系统服务（--purge 删数据库与 CA）
│   │     uninstall --check                只检查卸载后残留（服务/扩展/CA/数据），不执行（NFR-09）
│   └── logs [--follow]
├── config
│   ├── show [--effective] | get <key> | set <key> <value> | edit
│   ├── schema                             输出配置 JSON Schema
│   └── rules list | rules test <rule.toml> <fixture.jsonl>
├── proxy                                  代理 CA 管理（管理员）
│   ├── ca-info                            指纹、创建/到期时间
│   ├── rotate-ca [--revoke-now]           轮换 CA（--revoke-now 立即终止代理会话）
│   └── trust --user | untrust             （高风险）显式安装/移除到用户证书库
├── db
│   ├── stats                              体积、各表行数、最旧会话
│   ├── vacuum | migrate [--dry-run]
│   └── purge [--older-than <dur>] [--all] [--yes]
├── fixtures                               开发用
│   ├── record <SESSION> -o <file>         （需 debug.keep_raw_events）
│   ├── replay <file> [--expect <snap>]    离线跑管道
│   ├── scrub <file>                       替换用户名/主机名/IP
│   └── upgrade <file>                     升级到当前 schema
├── group                                  监控组（独立启动的多个会话，REQ-11）
│   ├── create|list|show|delete <name>
│   └── graph <name> [--format dot|mermaid|json]
├── agents <SESSION|--group NAME>          Agent 实例列表与角色
├── links <SESSION|--group NAME> [--kind ...] [--min-evidence E1]
├── rpc <SESSION> [--method tools/call] [--target <glob>]
├── chain <SESSION> <TABLE>:<ID>           从某条记录回溯委托链路
├── merge <A.jsonl> <B.jsonl> -o <db>      跨主机离线合并（可选，P6-STORE-02）
├── hook <AGENT> [--session <SESSION>]      由 Agent hooks 调用：从 stdin 读事件 JSON，转发为 AgentToolCall（E3，SPIKE-07）
├── mcp-tap -- <CMD> [ARGS...]             （内部）stdio 透明包装器；fail-open，不存参数内容
├── dev [--] <subcommand>                  单进程模式（daemon+CLI，需 sudo）
└── version [--check]                      --check：用户确认后手动检查新版本（唯一主动联网处，默认不联网）
```

`<SESSION>` 可以是 `public_id`、会话名，或 `@last`（最近一次会话）。时间参数支持三种写法：RFC 3339、`-10m` 这样的相对时间、相对会话开始的 `+30s`。

### 2.1 `aw run` 终端体验

```
$ aw run --proxy -- claude
[aw] 会话 s-7k2m 已开始 · 代理 127.0.0.1:50211 · 采集器 linux.ebpf (E1) · UI: aw ui
... （目标程序正常交互） ...
[aw] 会话 s-7k2m 结束 · 18m42s · 进程 214 · 文件 3,410 · 外联域名 9 · ↑ 2.1 MB ↓ 48.7 MB
[aw] 发现 4 条（敏感访问 1，推测 2，直连 1）· 缺口 0 · aw sessions show s-7k2m
```

- 信息输出到 stderr，以 `[aw]` 为前缀。`--quiet` 可以关闭。
- 目标进程的 stdio 完全透传。

## 3. HTTP API

- 前缀 `/api/v1`；使用 JSON；分页采用 cursor 方式：请求传 `?cursor=&limit=`，响应返回 `next_cursor`。
- 错误格式为 `{"error":{"code":"not_found","message":"..."}}`。
- 详细定义从代码自动生成 OpenAPI（`utoipa`），地址为 `/api/v1/openapi.json`。

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/health` | daemon 状态、版本、存储健康、活动会话数（无需鉴权，只返回非敏感字段） |
| POST | `/auth/ui-ticket` | 仅限 socket/管道：申请 UI ticket |
| POST | `/auth/ui-token` | 用 ticket 换 token |
| GET | `/compare?a=<SESSION>&b=<SESSION>` | 两个会话对比：进程/文件/域名/流量差异（P5） |
| GET | `/doctor` | 自检报告（采集器 `probe()` 与 `capabilities()`）。`host.privileged` 是 daemon 进程自身的特权，向操作系统查询：Linux 看有效 uid 为 0 或持有 `CAP_SYS_ADMIN`，macOS 看有效 uid 为 0，Windows 看令牌完整性级别为 High 或 System（未提权的管理员账户算否）。查询失败时为 `null`，不写成 `false` `collectors` 是**运行状态**（由前台采样循环每次采样后写入，不读配置）：`poll` 项带 `status`（`running`/`stopped`/`unknown`，循环还没报告时为 `unknown`）、`daemon_sample`、`watched_roots`、`last_sample_ns` 和 `capabilities`；本平台的内核采集器（eBPF/ETW/eslogger）列为 `not_built`。`capabilities` 与会话回复里 `poll` 的能力是同一份（`kind, evidence, na_reason?`，另加 `available`），新建会话页和概览一致。 |
| GET | `/processes` | 当前系统进程表（「附着到进程」选择器和 `aw ps` 共用），收到请求时用轮询采集器同一个 `sysinfo` 源现读，证据 S，不缓存不入库。参数：`?agents_only=1&q=`（`q` 按进程名子串或 pid 匹配，不区分大小写；`agents_only` 只留按内置 Agent 配置识别到的，识别是推测 I）。管理员（root / Administrators）看全部进程（`scope:"all"`）；其他调用方只看属主 uid/SID 等于自己的进程（`scope:"own"`），属主读不到的不给。返回 `{available:true, scope, source:"poll", evidence:"S", count, roots:[树], processes:[平铺]}`，每项 `{pid, ppid, name, exe, argv, user_id, agent, evidence, children}`：`argv` 先过内置脱敏再给，读不到为 null；不读工作目录。本平台读不到进程表时回 200 `{available:false, reason, roots:[], processes:[]}`，界面写「没采」和原因，`aw ps` 报 `not_collected`（退出码 1），都不写成「没有记录」。 |
| POST | `/sessions` | 创建会话并开始记录（轮询采集，证据 S；本版本仅 Linux，其他平台 503 `collector_unavailable`，不建会话）。`aw attach --pid` 调用 `{mode:"attach", pid, agent?}`；`aw attach --name` 与 `--no-follow-children`、`--no-existing-children`、`--move-to-cgroup` 由 CLI 拒绝，不静默忽略。`{mode:"attach", pid, name?, agent?}`：pid 须在运行；属于其他用户的进程需管理员（403）。`{mode:"launch", argv, cwd?, env?, name?, agent?}`：程序以**调用方的账户**运行。账户只取自操作系统给出的对端身份（内部通道的对端 uid，或经该通道签给这个对端的 UI 令牌）；body 里的 `uid`/`user` 一律忽略。调用方就是 daemon 自己的账户时原样启动；daemon 以 root 运行时，子进程在 exec 前依次 `setgroups(0)`（不带附加组）→ `setgid` → `setuid`，再以调用方身份进入 `cwd`（缺省为其家目录），环境变量清空后只设 `HOME/USER/LOGNAME/SHELL/PATH`（另保留 `LANG/LC_ALL/TZ`，body 的 `env` 最后覆盖）；启动后读 `/proc/<pid>/status`，真实/有效/保存/文件系统 uid 与 gid 不全是调用方的就杀掉并回 500 `drop_failed`。身份不明 403 `caller_unidentified` / `caller_unknown`，绝不退回以 root 运行；daemon 以普通账户运行而调用方是别的账户时 403 `launch_other_user`。附加组不初始化（需要 fork 后的 unsafe 代码），依赖附加组权限的程序拿不到那部分权限。返回 201 `{id, session_id, mode, root_pid}`。根进程退出时会话结束（`end_reason=exited`，daemon 自己启动的带 `exit_code`）；`stop` 结束记录但不杀进程；daemon 停止时为 `daemon_shutdown`，重启时把上次遗留未结束的会话标为 `daemon_shutdown`。 启动失败按原因给错误码（400）：`program_not_found`（程序或工作目录不存在）、`program_not_permitted`（没有执行权限）、其他 `spawn_failed`；消息是英文短句，界面按错误码显示中文。 |
| POST | `/sessions/run` | 默认 `aw run` 用。CLI 发送 `{argv, cwd?, name?, agent?}`（绝不发送 `--env` 值），daemon 记一条 `mode=launch` 会话并返回 201 `{id, session_id, mode:"launch", root_pid:null, ticket, adopt_timeout_ms:5000}`；CLI 以调用者身份创建目标程序后，在 5 秒内调 `/sessions/{sid}/adopt {ticket,pid}`。adopt 失败时 CLI 会停止并回收该子进程，避免未受监控运行；超时会话以 `adopt_timeout` 结束。`--no-daemon` 不调用此接口，使用本地轮询路径。`sessions.argv` 先过内置脱敏再存。 |
| POST | `/sessions/{sid}/adopt` | `{ticket, pid}`。ticket 不符 403，超时 410 `adopt_timeout`，没有等待中的启动 404（他人的也是 404）。 |
| POST | `/sessions/{sid}/attach` | `{pid}`：在自己的、未结束的会话里再多记录一个根进程；他人进程需管理员。会话已结束 409。没有打开会话数据库的 daemon（前台运行总会打开 `agentwatch.db`，只在测试桩里出现）回 503 `store_unavailable`，不是 501。 |
| GET | `/sessions` | 列表。参数：`?since&until&agent&active&q&cursor&limit`。每行带 `collectors`（同会话详情）和 `stats`（同 `/summary` 的计数），列表和概览的数字一致；类别没采时界面两处都写「没采」。 每行另带 `argv`（存储时已脱敏的命令，数组；没有为 null），没有名字的会话界面显示命令（如 `sleep 90`）。 |
| GET | `/sessions/{sid}` | 会话详情 + `stats`（与会话列表、`/summary` 同一个计数函数 `aw_store::session_counts`：`process_count, flow_count, dns_count, gap_count, bytes_up, bytes_down, finding_count`；库里还没有 `findings` 表时 `finding_count` 为 null，不是 0），另带 `mode` 和 `collectors`。`collectors` 是数组，每项 `{name, mode, capabilities:[{kind, evidence, na_reason?}]}`：轮询采集器 `poll` 列 `proc`=S，`file`、`dns`=NA（`collector_unavailable`），`net` 在 Windows 为 S、其他平台为 NA。库里存的采集器名没有能力描述时（未知名字），该项 `capabilities` 为空并带 `note: "collector_not_described"`，界面据此说“不能确认是否采集”，不说“没有发生”。`/summary` 同样带这两个字段。 |
| PATCH | `/sessions/{sid}` | `{name?, pinned?}` |
| PATCH | `/sessions/{sid}/findings/{id}` | body：`{user_state: "confirmed"\|"ignored"\|null}`。只接受这三个值。`null` 清除标记。写入 `user_state_by`（当前用户）和 `user_state_ns`（Unix 纳秒）。不属于该用户的会话或发现返回 404。 |
| POST | `/sessions/{sid}/stop` | `aw stop <SESSION>` 调用此接口。接口只认 public id（`s-…`）；`@last` 和会话名由 CLI 先查 `GET /sessions` 换成 public id（`@last` 取自己最新开始的一条；同名多条时报错，请改用 public id）。停止监控但不结束目标进程，写入 `ended_ns`；之后不再往这个会话写新记录。daemon 自带的 `daemon-sample` 会话也一样：采样器每次采样前读一次 `ended_ns`，已停止就停掉，daemon 重启后也不再恢复采样。 |
| DELETE | `/sessions/{sid}` | 删除 |
| GET | `/sessions/{sid}/summary` | 概览页数据：Top 目录、Top 域名、按类别计数、按证据等级计数、缺口摘要 |
| GET | `/sessions/{sid}/timeline` | 参数：`?filter&from&to&cats&cursor&limit`。每行在视图列（`session_id, ts_ns, cat, id, proc_uid, evidence`）之外带 `summary`（按 `cat` 从来源表的已存列拼一行，NULL 的列不出现，不推测）、`fields`（拼 summary 用到的列，原样）和 `proc: {pid, exe_name}`。来源行不存在时 `summary` 为空串。`/around` 同样。 `proc` 行带 `pre_existing`：仅当会话是 `attach`、该进程属于采样器开始时的基线（`processes.how = snapshot`）且开始时间早于 `sessions.started_ns` 时为 true。`launch` 会话里的进程都由会话启动，即使根进程的开始时间（/proc 只到整秒）读出来比会话早一点，也不算。界面的「会话开始前已存在」只看这个字段。 |
| GET | `/sessions/{sid}/timeline/histogram` | 参数：`?filter&from&to&buckets`。返回时间轴密度图数据 |
| GET | `/sessions/{sid}/processes` | 参数：`?tree=1&filter` |
| GET | `/sessions/{sid}/processes/{proc_uid}` | 进程详情：镜像链、统计、子进程 |
| GET | `/sessions/{sid}/files` | 参数：`?filter&group_by&sort&cursor&limit` |
| GET | `/sessions/{sid}/flows` | 参数：`?filter&group_by&sort` |
| GET | `/sessions/{sid}/flows/{id}/buckets` | 单流的时间序列 |
| GET | `/sessions/{sid}/traffic` | 参数：`?group_by=domain\|proc&from&to&step`。返回流量时间序列（堆叠图） |
| GET | `/sessions/{sid}/dns` | |
| GET | `/sessions/{sid}/http` | 参数：`?filter&cursor&limit&from&to&redact_paths&redact_hosts`。字段与 `http` 表一致，`proc_uid` 为十六进制，另附 `proc: {pid, exe_name}`。游标为 `ts_ns,id`。会话属于当前用户且 `proxy_enabled = 0` 时返回 200：`{"http":[],"reason":"no_proxy","next_cursor":null}`，不是 404。没有数据库的内存会话仍是 501。 |
| GET | `/sessions/{sid}/agent-events` | E3 自报告，`?cursor&limit`，按 id 升序：`{"events":[...],"next_cursor"}`。证据等级照存储原样返回，不升级。库里还没有 `agent_events` 表时为 200 空页并带 `reason: "no_self_reports"`。 |
| GET | `/sessions/{sid}/agents` | AgentInstance 列表与角色 |
| PATCH | `/agents/{id}` | `{role?, label?}` 手工标注 |
| GET | `/sessions/{sid}/links` | 参数：`?kind&min_evidence` |
| GET | `/sessions/{sid}/rpc` | 参数：`?method&target`。MCP / A2A 调用列表 |
| GET | `/chain` | 参数：`?ref=<table>:<id>`。委托链路 |
| GET | `/groups` | 监控组列表 |
| POST | `/groups` | `{name}` 创建监控组 |
| GET | `/groups/{gid}` | 组详情与成员会话 |
| DELETE | `/groups/{gid}` | 删除组（不删会话） |
| GET | `/groups/{gid}/graph` | Agent 通信图（节点 + 边） |
| GET | `/sessions/{sid}/findings` | 参数：`?lang=zh\|en&min_severity=info\|notice\|warn&evidence=E1\|E2\|E3\|S\|I\|NA\|content_match&cursor&limit`。每条含 `wording_id`、`params`，以及 `wording::render` 生成的 `text`。渲染失败时 `text` 为 null，并带 `error`，不拼接替代句。`content_match` 按 `kind` 过滤，其余按 `evidence`。游标为 `first_ns,id`。 |
| GET | `/sessions/{sid}/gaps` | |
| GET | `/sessions/{sid}/around` | 参数：`?ref=file_access:123&window=10s` |
| GET, POST | `/sessions/{sid}/export` | 参数：`?format&filter&redact_paths&redact_hosts&lang`。`format=md`（GET 或 POST）返回 `text/markdown`：会话信息、采集能力、缺口、按证据等级分组的发现（`content_match` 单独一节）、按流记录条数的域名、按访问行数的文件，文末固定附证据等级说明。未知字段写「不可得」并带原因。全文先过 `wording::lint`（内容匹配句只放行 `ContentMatchPhrase`）；有违规时 HTTP 422，body 为 `{"error":{"code":"wording_lint","violations":[...]}}`，不返回报告正文。`format=jsonl` 返回 `application/x-ndjson`，`format=csv` 返回各表 CSV 的 zip（`application/zip`），行与脱敏规则和 `aw export` 相同（`aw-store` 的同一写出函数），`filter`、`redact_paths`、`redact_hosts` 同样生效。其他 `format` 以及没有数据库的内存会话仍是 501。 |
| GET | `/sessions/{sid}/live` | SSE 实时事件流（已脱敏、已归属的记录增量） |
| GET | `/search` | 参数：`?q&kind&since&limit`。跨会话搜索。回复 `{"fts_enabled", "hits":[{src, src_id, session_id, public_id, text, ts_ns, evidence}]}`：`text` 是来源行存的文字（`file_access.path`；`process_images` 为 `exe`，没有 `exe` 时为 `argv`），`ts_ns` 是 `file_access.first_ns` 或 `process_images.ts_ns`（Unix 纳秒），`evidence` 照来源行原样。来源行没有的值为 null，不推测。 每条命中另带 `session_name`：会话名，没有名字时是命令行，都没有为 null。 |
| GET/PUT | `/config` | 读取/修改配置（PUT 仅管理员）。GET 回复 `{"config": {...}, "builtin_redaction_rules": [{id, scope, pattern}]}`：内置脱敏规则始终生效、只读，`scope` 为 `text`/`argv`/`env`/`url`/`header`，结构性规则（如 `env.secret_name`）`pattern` 为 null。列表来自 `aw_pipeline::builtin_rules()`，与实际运行的规则同一张表。自定义规则在 `config.redaction.rules`，按正则表达式匹配。 |
| GET | `/rules` | 已加载的规则 |
| GET | `/db/stats` | |
| POST | `/db/purge` | 仅管理员（非管理员 403）。body：`{older_than?: "30d", all?: bool, dry_run?: bool, confirm?: bool}`，`older_than` 与 `all` 至少一个。两步：`dry_run: true` 只列出将删除的会话 `{"dry_run":true,"would_purge":[{public_id,session_id}]}`，不删；真正删除必须带 `confirm: true`，否则 400 `confirm_required`。固定（pinned）和未结束的会话永不删除；每删一个在 `schema_meta` 留 `purged:<public_id>` 审计记录（storage §5）。返回 `{"purged":[{public_id,session_id,reason,deleted_ns}]}`。CLI `aw db purge` 在 `--yes` 或交互确认后才发 `confirm: true`。 |

记录的 JSON 字段与 [storage](storage.md) 中的表字段同名，另外有两点增强：
- `proc_uid` 序列化为十六进制字符串；
- 引用到进程的记录会带上 `proc: {pid, exe_name}` 摘要，避免前端再发一次请求。

## 4. 筛选查询语法

CLI `--filter`、API `filter=`、UI 搜索框以及关联规则的 `where` 共用一个解析器，实现在 `aw-core::filter`。解析结果是 AST，再编译为两种形式：
- 参数化 SQL，供存储查询使用；
- 内存谓词，供规则引擎和 `/live` 使用。

### 4.1 示例

```text
kind:file path:~/.ssh/**                      # 任意对 ~/.ssh 下的文件访问
kind:file op:delete dir:/home/u/proj          # 项目目录内的删除
kind:net domain:*.github.com bytes_up>1MB     # 上传超 1MB 到 github
proc:node and not domain:api.anthropic.com    # node 进程的非 Anthropic 流量
evidence:I,S                                   # 只看推测和采样
kind:net direct:true                           # 绕过代理的直连
tag:sensitive or kind:finding
exe:"/usr/bin/curl" argv~"-d @"                # argv 子串匹配
(kind:http status>=400) and time>+5m
```

### 4.2 BNF

```bnf
<query>      ::= <or_expr> | ""
<or_expr>    ::= <and_expr> ( ("or" | "OR" | "||") <and_expr> )*
<and_expr>   ::= <unary> ( ( "and" | "AND" | "&&" | <ws> ) <unary> )*     ; 空格即 and
<unary>      ::= ( "not" | "NOT" | "-" | "!" ) <unary> | <primary>
<primary>    ::= "(" <or_expr> ")" | <term> | <bare>
<term>       ::= <field> <op> <value_list>
<field>      ::= <ident> ( "." <ident> )*                               ; 如 remote.port、a.path
<op>         ::= ":" | "=" | "!=" | ">" | ">=" | "<" | "<=" | "~" | "in"
<value_list> ::= <value> ( "," <value> )* | "[" <value> ( "," <value> )* "]"
<value>      ::= <quoted> | <glob> | <number> <unit>? | <duration> | <reltime> | <bool>
<bare>       ::= <quoted> | <glob>                                      ; 无字段 = 对 path/argv/url/domain 做子串匹配
<quoted>     ::= '"' ( [^"\\] | "\\" . )* '"' | "'" [^']* "'"
<glob>       ::= ( [A-Za-z0-9_./~*?\-@:\\] )+                         ; * 不跨分隔符，** 跨
<number>     ::= [0-9]+ ( "." [0-9]+ )?
<unit>       ::= "B" | "KB" | "MB" | "GB" | "KiB" | "MiB" | "GiB"
<duration>   ::= <number> ( "ms" | "s" | "m" | "h" | "d" )
<reltime>    ::= ( "+" | "-" ) <duration>                               ; + 相对会话开始，- 相对现在
<bool>       ::= "true" | "false"
<ident>      ::= [a-z_][a-z0-9_]*
```

### 4.3 语义

| 操作符 | 含义 |
|---|---|
| `:` | 字符串字段做 glob 匹配（不含通配符就是精确匹配；`path`、`dir` 字段在 Windows 上不区分大小写）；数值字段等同 `=`；给出多个值时任一匹配即可 |
| `~` | 子串匹配（不区分大小写）。**不支持正则**，避免 ReDoS 和对大表做全表正则扫描 |
| `>` `<` 等 | 数值、时间、字节比较 |

- `~` 开头的路径展开为**会话用户**的家目录。

**字段表（跨类别通用）**

| 字段 | 适用 | 说明 |
|---|---|---|
| `kind` | 全部 | `proc` `file` `net` `dns` `http` `agent` `ipc` `rpc` `finding` `gap` |
| `time` | 全部 | 记录时间 |
| `evidence` | 全部 | `E1` … `NA` |
| `source` | 全部 | 采集器来源 |
| `proc` | 全部 | 进程可执行文件名（basename） |
| `pid` / `proc_uid` | 全部 | |
| `subtree` | 全部 | `subtree:<proc_uid>`，匹配该进程及其后代 |
| `tag` | 全部 | `sensitive`、`sensitive.<rule>`、`doh_suspected`、`preexisting` 等 |
| `exe` `argv` `cwd` | proc | |
| `path` `dir` `op` `access` `bytes_read` `bytes_written` | file | `dir:X` 等价于 `path:X/**` |
| `domain` `ip` `port` `remote.ip` `remote.port` `local.port` `proto` `bytes_up` `bytes_down` `direct` `via_proxy` | net | `ip`/`port` 指远端 |
| `qname` `qtype` `rcode` | dns | |
| `method` `url` `host` `status` `req_bytes` `resp_bytes` | http | |
| `tool` `agent` | agent | |
| `ipc_kind` `peer` `channel` | ipc | `pipe` / `unix_stream` / `named_pipe` 等 |
| `method` `target` | rpc | MCP / A2A 的 method 与工具名 |
| `rule` `severity` | finding | |

未知字段报错，并给出建议（编辑距离）。字段与 `kind` 不匹配时，例如 `kind:file domain:x`，结果为空，并返回警告。
