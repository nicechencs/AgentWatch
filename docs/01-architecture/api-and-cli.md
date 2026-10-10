# 本地 API 与 CLI

> 状态：草案
> 最后更新：2026-10-07
> 关联：REQ-02、REQ-05、REQ-07.6、REQ-11、[ADR-0005](../03-adr/0005-privileged-daemon-split.md)、[storage](storage.md)、[ui](ui.md)、[inter-agent-communication](inter-agent-communication.md)

## 1. 通信与鉴权

| 通道 | 平台 | 用途 | 鉴权 |
|---|---|---|---|
| Unix 域 socket `/run/agentwatch/api.sock`（Linux）、`/var/run/agentwatch/api.sock`（macOS） | Linux / macOS | CLI 主通道 | `SO_PEERCRED` / `LOCAL_PEERCRED` 拿到对端 uid；socket 权限 0660，属组 `agentwatch` |
| 命名管道 `\\.\pipe\agentwatch-api` | Windows | CLI 主通道 | `GetNamedPipeClientProcessId` + 客户端 token 拿到 SID；管道 DACL 允许 Administrators + `AgentWatch Users` 组 |
| HTTP `127.0.0.1:<port>`（默认 7456，`api.http_port` 可配置，`0` 关闭） | 全平台 | Web UI | Bearer token（见下）；校验 `Host` 头必须为 `127.0.0.1:<port>` 或 `localhost:<port>`，防 DNS rebinding；不开 CORS |

内部通道的实现状态（2026-10-10）：
- Linux / macOS：`agentwatchd` 前台运行时监听 Unix socket（`crates/aw-daemon/src/api/ipc.rs`），权限 0660；报文与 HTTP 相同（HTTP/1.1 请求和响应），不带 `Authorization`，也不做 `Host` 校验。只提供 `/health` 和 `/api/v1/*`，不提供页面资源。socket 与 HTTP 共用同一份状态，所以在 socket 上签的 ticket 可以在 HTTP 上兑换。
- Linux 用 `SO_PEERCRED` 取对端 uid，uid 0 为管理员。macOS 暂未取到 `LOCAL_PEERCRED`，对端记为 `unverified-peer`、非管理员，只靠 socket 权限把关。属组 `agentwatch` 尚未设置。
- Windows：`agentwatchd` 在 `\\.\pipe\agentwatch-api` 上监听（tokio 命名管道），报文同上。管道沿用系统默认 DACL，只有 LocalSystem、Administrators 和 daemon 自己的账户能以读写方式打开，所以连上的客户端记为管理员 `pipe-admin`。`AgentWatch Users` 组的 DACL 和按 `GetNamedPipeClientProcessId` 取客户端 SID 尚未实现：普通 Windows 用户暂时打不开管道。只做了交叉编译检查，没有在 Windows 上实跑。
- `AW_SOCKET` 环境变量同时覆盖 daemon 的监听路径和 `aw` 的默认连接路径，用于测试和非 root 开发运行。`aw daemon start` 在通道无响应时拉起 `agentwatchd --foreground`（`AW_DAEMON_CONFIG` 作为 `--config` 传入）并等待 `/health`，不注册系统服务。

CLI 和 UI 请求到达后走同一套 axum 路由。传输层不同，但请求体和响应体完全一致。

**会话令牌（UI）**
1. `aw ui` 经由 socket 或管道向 daemon 申请一个一次性 `ui_ticket`，60 秒有效。ticket 与 token 都是操作系统 CSPRNG 生成的 256 位随机数（十六进制），签发、兑换、校验用同一个时钟，过期即拒；过期未兑的 ticket 在下次签发时清掉。
2. 用 `http://127.0.0.1:7456/#ticket=<t>` 打开浏览器。
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
├── ps [--agents-only] [--filter <text>]   列出可附着的进程（树状）
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
| GET | `/doctor` | 自检报告（采集器 `probe()` 与 `capabilities()`）。`host.privileged` 是 daemon 进程自身的特权，向操作系统查询：Linux 看有效 uid 为 0 或持有 `CAP_SYS_ADMIN`，macOS 看有效 uid 为 0，Windows 看令牌完整性级别为 High 或 System（未提权的管理员账户算否）。查询失败时为 `null`，不写成 `false` |
| GET | `/processes` | 当前系统进程树（进程选择器）。参数：`?agents_only&q=` |
| POST | `/sessions` | 创建会话。body：`{mode:"launch"\|"attach", argv?, cwd?, env?, pid?, follow_children, proxy, agent, name, include_procs, self_report, pin, group?, mcp_tap?}` |
| GET | `/sessions` | 列表。参数：`?since&until&agent&active&q&cursor&limit` |
| GET | `/sessions/{sid}` | 会话详情 + `stats` |
| PATCH | `/sessions/{sid}` | `{name?, pinned?}` |
| PATCH | `/sessions/{sid}/findings/{id}` | body：`{user_state: "confirmed"\|"ignored"\|null}`。只接受这三个值。`null` 清除标记。写入 `user_state_by`（当前用户）和 `user_state_ns`（Unix 纳秒）。不属于该用户的会话或发现返回 404。 |
| POST | `/sessions/{sid}/stop` | 停止监控 |
| DELETE | `/sessions/{sid}` | 删除 |
| GET | `/sessions/{sid}/summary` | 概览页数据：Top 目录、Top 域名、按类别计数、按证据等级计数、缺口摘要 |
| GET | `/sessions/{sid}/timeline` | 参数：`?filter&from&to&cats&cursor&limit` |
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
| GET | `/search` | 参数：`?q&kind&since&limit`。跨会话搜索 |
| GET/PUT | `/config` | 读取/修改配置（PUT 仅管理员） |
| GET | `/rules` | 已加载的规则 |
| GET | `/db/stats` | |

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
