# 存储设计

> 状态：草案
> 最后更新：2026-10-07
> 关联：REQ-05、REQ-07、REQ-11、NFR-03、[ADR-0003](../03-adr/0003-sqlite-storage.md)、[ADR-0011](../03-adr/0011-aggregate-first.md)、[ADR-0013](../03-adr/0013-inter-agent-observation.md)、[SPIKE-06](../06-research/SPIKE-06-sqlite-throughput.md)、[inter-agent-communication](inter-agent-communication.md)

## 1. 总体

- **数据库**：单个 SQLite 文件 `agentwatch.db`，使用 `rusqlite`，并开启 bundled 特性以自带固定版本的 SQLite。
- **PRAGMA**：
  - `journal_mode=WAL`、`synchronous=NORMAL`、`foreign_keys=ON`、`temp_store=MEMORY`、`mmap_size=268435456`；
  - `auto_vacuum=INCREMENTAL`，在建库时设置。
- **连接**：一个写连接，由 Batcher 线程独占；另有 N 个只读连接（默认 4 个）供 API 查询使用。
- **文件权限**：见 security-privacy §4。
- **为什么不按会话分库**：跨会话查询（历史搜索）是刚需。会话级删除改用 `DELETE ... WHERE session_id = ?` 加增量 vacuum。【待验证】大会话删除的耗时见 [SPIKE-06](../06-research/SPIKE-06-sqlite-throughput.md)。如果不可接受，就改为按月分库，用 `ATTACH` 联合查询。

## 2. 约定

- 时间：`*_ns` 为 Unix 纪元纳秒（墙钟，INTEGER）。单调时间不入库；入库前管道已经换算完毕，并保证同一会话内单调不减。
- 证据：`evidence TEXT`，取值为 `E1|E2|E3|S|I|NA`；`na_reason TEXT` 可以为空。字段级证据存在 `field_evidence TEXT`（JSON）中，空即 NULL。
- 进程引用：`proc_uid INTEGER`，以有符号 64 位存储 `ProcUid`。
- 外键默认只在 `session_id` 上声明并级联删除。`proc_uid` 不声明外键，因为事件可能先于进程记录到达。
- P6 例外（与 [inter-agent-communication §7](inter-agent-communication.md#7-存储) 一致，不要删）：`agent_rpc.channel_id` → `ipc_channels`（级联）、`agent_instances.parent_id` → `agent_instances`、`agent_links.from_agent` / `to_agent` → `agent_instances`、`sessions.group_id` → `watch_groups`。`agent_links.session_id` 与 `group_id` 不加外键：边可以跨会话，且监控组与会话的删除顺序不由这两列约束。`agent_rpc` 没有 `session_id`，会话经 `channel_id` → `ipc_channels.session_id` 取得。
- 所有文本都是已脱敏的内容。

## 3. DDL

```sql
-- ============ 元数据 ============
CREATE TABLE schema_meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
-- 初始行：('schema_version','1'), ('created_ns', ...), ('app_version', ...), ('host_id', <随机 UUID>)

-- ============ 监控组（P6-STORE-01；必须先于 sessions.group_id 的外键） ============
-- 迁移顺序：先 CREATE TABLE watch_groups，再 ALTER TABLE sessions ADD COLUMN group_id。
-- foreign_keys=ON 时，不能在 watch_groups 尚不存在时引用它。
CREATE TABLE watch_groups (
  id            INTEGER PRIMARY KEY,
  name          TEXT NOT NULL UNIQUE,
  created_ns    INTEGER NOT NULL
);

-- ============ 会话 ============
CREATE TABLE sessions (
  id              INTEGER PRIMARY KEY,           -- SessionId
  public_id       TEXT NOT NULL UNIQUE,          -- base32 短串，用于 CLI/URL
  name            TEXT,                          -- 用户可编辑
  mode            TEXT NOT NULL CHECK (mode IN ('launch','attach')),
  agent           TEXT,                          -- AgentProfile.id，可为空
  root_proc_uid   INTEGER,
  argv            TEXT,                          -- JSON 数组，已脱敏（launch）
  cwd             TEXT,
  user_id         TEXT NOT NULL,                 -- 发起会话的用户（uid / SID）
  started_ns      INTEGER NOT NULL,
  ended_ns        INTEGER,
  end_reason      TEXT,                          -- exited / stopped / daemon_shutdown / crashed
  exit_code       INTEGER,
  proxy_enabled   INTEGER NOT NULL DEFAULT 0,
  proxy_port      INTEGER,
  platform        TEXT NOT NULL,                 -- linux / windows / macos
  os_version      TEXT,
  collectors      TEXT NOT NULL,                 -- JSON：[{name, version, mode, capabilities}]
  collector_profile TEXT,                        -- 采集档位，如 macOS M1(eslogger)/M2(原生 ES+NE)；见 P4-MAC-06
  config_digest   TEXT,                          -- 生效配置的哈希，便于复现
  pinned          INTEGER NOT NULL DEFAULT 0,    -- 1 = 不参与自动清理
  stats           TEXT,                          -- JSON 汇总缓存（会话结束时写入）
  -- 以下列由 P6-STORE-01 迁移加入
  group_id        INTEGER REFERENCES watch_groups(id)  -- 监控组；独立启动的多 Agent 组合，见 inter-agent-communication §3.3
);
CREATE INDEX idx_sessions_started ON sessions(started_ns);

-- ============ 进程 ============
CREATE TABLE processes (
  session_id      INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  proc_uid        INTEGER NOT NULL,
  pid             INTEGER NOT NULL,
  parent_uid      INTEGER,
  ppid            INTEGER,
  depth           INTEGER NOT NULL DEFAULT 0,    -- 距根进程的层级
  start_ns        INTEGER NOT NULL,
  exit_ns         INTEGER,
  exit_code       INTEGER,
  exit_signal     INTEGER,
  how             TEXT NOT NULL,                 -- fork / exec / spawn / snapshot
  user_id         TEXT,
  signer          TEXT,
  evidence        TEXT NOT NULL,
  field_evidence  TEXT,
  source          TEXT NOT NULL,
  agent           TEXT,                          -- 识别出的 Agent（若本进程就是 Agent）
  PRIMARY KEY (session_id, proc_uid)
) WITHOUT ROWID;
CREATE INDEX idx_proc_parent ON processes(session_id, parent_uid);
CREATE INDEX idx_proc_pid    ON processes(session_id, pid);

-- 进程镜像（exec 阶段）。一个进程可有多条；Windows 恰好一条。
CREATE TABLE process_images (
  id              INTEGER PRIMARY KEY,
  session_id      INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  proc_uid        INTEGER NOT NULL,
  seq             INTEGER NOT NULL,              -- 0,1,2...
  ts_ns           INTEGER NOT NULL,
  exe             TEXT,
  argv            TEXT,                          -- JSON 数组，已脱敏
  cwd             TEXT,
  env             TEXT,                          -- JSON，仅白名单变量，已脱敏
  evidence        TEXT NOT NULL,
  field_evidence  TEXT,
  source          TEXT NOT NULL,
  UNIQUE (session_id, proc_uid, seq)
);
CREATE INDEX idx_img_ts  ON process_images(session_id, ts_ns);
CREATE INDEX idx_img_exe ON process_images(exe);

-- ============ 文件 ============
CREATE TABLE file_access (
  id              INTEGER PRIMARY KEY,
  session_id      INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  proc_uid        INTEGER NOT NULL,
  op              TEXT NOT NULL CHECK (op IN ('access','create','delete','rename','exec')),
  path            TEXT NOT NULL,
  path_to         TEXT,                          -- rename 目标
  access          TEXT,                          -- read / write / read_write / exec / unknown（op=access 时）
  first_ns        INTEGER NOT NULL,
  last_ns         INTEGER NOT NULL,
  opens           INTEGER NOT NULL DEFAULT 1,
  reads           INTEGER,                       -- NULL = 不可得
  bytes_read      INTEGER,
  writes          INTEGER,
  bytes_written   INTEGER,
  created         INTEGER,
  truncated       INTEGER,
  modified        INTEGER,
  result          INTEGER,                       -- 非 0 表示打开失败（errno / NTSTATUS）
  partial         INTEGER NOT NULL DEFAULT 0,    -- 1 = 仍在打开，中间快照
  sensitive_rule  TEXT,                          -- 命中的敏感路径规则 ID
  evidence        TEXT NOT NULL,
  na_reason       TEXT,
  field_evidence  TEXT,
  source          TEXT NOT NULL
);
CREATE INDEX idx_fa_session_ts ON file_access(session_id, first_ns);
CREATE INDEX idx_fa_proc       ON file_access(session_id, proc_uid, first_ns);
CREATE INDEX idx_fa_path       ON file_access(path);
CREATE INDEX idx_fa_sensitive  ON file_access(session_id, sensitive_rule) WHERE sensitive_rule IS NOT NULL;

-- ============ 网络 ============
CREATE TABLE net_flows (
  id              INTEGER PRIMARY KEY,
  session_id      INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  proc_uid        INTEGER NOT NULL,
  proto           TEXT NOT NULL CHECK (proto IN ('tcp','udp')),
  direction       TEXT NOT NULL,                 -- outbound / inbound / unknown
  local_ip        TEXT NOT NULL,
  local_port      INTEGER NOT NULL,
  remote_ip       TEXT NOT NULL,
  remote_port     INTEGER NOT NULL,
  domain          TEXT,                          -- 最佳域名
  domain_source   TEXT,                          -- sni / dns_self / dns_session / dns_global / dns_unattributed（解析器代查、无法归属发起进程，I 级）/ proxy_connect
  domain_alts     TEXT,                          -- JSON 数组，其他候选
  sni             TEXT,
  alpn            TEXT,
  start_ns        INTEGER NOT NULL,
  end_ns          INTEGER,
  bytes_up        INTEGER,                       -- NULL = 不可得
  bytes_down      INTEGER,
  via_proxy       INTEGER NOT NULL DEFAULT 0,
  direct          INTEGER NOT NULL DEFAULT 0,    -- 代理会话中未经代理
  preexisting     INTEGER NOT NULL DEFAULT 0,
  is_loopback     INTEGER NOT NULL DEFAULT 0,
  result          INTEGER,
  platform_total_up   INTEGER,                   -- 平台累计值（校准用）
  platform_total_down INTEGER,
  evidence        TEXT NOT NULL,
  na_reason       TEXT,
  field_evidence  TEXT,
  source          TEXT NOT NULL
);
CREATE INDEX idx_nf_session_ts ON net_flows(session_id, start_ns);
CREATE INDEX idx_nf_proc       ON net_flows(session_id, proc_uid);
CREATE INDEX idx_nf_domain     ON net_flows(domain);
CREATE INDEX idx_nf_remote     ON net_flows(remote_ip, remote_port);

CREATE TABLE net_flow_buckets (
  flow_id         INTEGER NOT NULL REFERENCES net_flows(id) ON DELETE CASCADE,
  session_id      INTEGER NOT NULL,              -- 冗余，便于按会话扫
  bucket_ns       INTEGER NOT NULL,              -- 桶起始时间（对齐到 bucket_secs）
  bytes_up        INTEGER NOT NULL DEFAULT 0,
  bytes_down      INTEGER NOT NULL DEFAULT 0,
  evidence        TEXT NOT NULL,
  PRIMARY KEY (flow_id, bucket_ns)
) WITHOUT ROWID;
CREATE INDEX idx_nfb_session_ts ON net_flow_buckets(session_id, bucket_ns);

CREATE TABLE dns (
  id              INTEGER PRIMARY KEY,
  session_id      INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  proc_uid        INTEGER,                       -- 委托解析器时可能为空
  ts_ns           INTEGER NOT NULL,
  qname           TEXT NOT NULL,
  qtype           INTEGER NOT NULL,
  rcode           INTEGER,
  answers         TEXT,                          -- JSON [{rtype, data}]
  ttl_min         INTEGER,
  server          TEXT,
  evidence        TEXT NOT NULL,
  source          TEXT NOT NULL
);
CREATE INDEX idx_dns_session_ts ON dns(session_id, ts_ns);
CREATE INDEX idx_dns_qname      ON dns(qname);

CREATE TABLE http (
  id              INTEGER PRIMARY KEY,
  session_id      INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  proc_uid        INTEGER,
  flow_id         INTEGER REFERENCES net_flows(id) ON DELETE SET NULL,
  ts_ns           INTEGER NOT NULL,
  method          TEXT NOT NULL,
  url             TEXT NOT NULL,                 -- 已脱敏
  host            TEXT NOT NULL,
  http_version    TEXT,
  status          INTEGER,
  req_headers     TEXT,                          -- JSON，白名单 + 脱敏
  resp_headers    TEXT,
  req_body_bytes  INTEGER,
  resp_body_bytes INTEGER,
  content_type    TEXT,
  duration_ms     INTEGER,
  error           TEXT,                          -- cert_pinned / upstream_tls / ...
  evidence        TEXT NOT NULL,
  source          TEXT NOT NULL
);
CREATE INDEX idx_http_session_ts ON http(session_id, ts_ns);
CREATE INDEX idx_http_host       ON http(host);

-- ============ 自报告（E3） ============
CREATE TABLE agent_events (
  id              INTEGER PRIMARY KEY,
  session_id      INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  proc_uid        INTEGER,
  ts_ns           INTEGER NOT NULL,
  agent           TEXT NOT NULL,
  agent_session   TEXT,
  tool            TEXT NOT NULL,
  phase           TEXT NOT NULL,
  call_id         TEXT,
  summary         TEXT,                          -- JSON，已脱敏、已截断
  evidence        TEXT NOT NULL DEFAULT 'E3',
  source          TEXT NOT NULL
);
CREATE INDEX idx_ae_session_ts ON agent_events(session_id, ts_ns);

-- ============ 发现 ============
CREATE TABLE findings (
  id              INTEGER PRIMARY KEY,
  session_id      INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  rule_id         TEXT NOT NULL,
  rule_version    INTEGER NOT NULL,
  kind            TEXT NOT NULL,                 -- fact / fact_conjunction / inference / content_match
  evidence        TEXT NOT NULL,                 -- E1 / I / ...
  severity        TEXT NOT NULL,                 -- info / notice / warn
  wording_id      TEXT NOT NULL,
  params          TEXT NOT NULL,                 -- JSON：渲染模板的参数（展示时按语言渲染）
  first_ns        INTEGER NOT NULL,
  last_ns         INTEGER NOT NULL,
  count           INTEGER NOT NULL DEFAULT 1,
  dedup_key       TEXT NOT NULL,
  refs            TEXT NOT NULL,                 -- JSON：[{table, id}] 依据记录
  caveats         TEXT,                          -- JSON：[{gap_id}|{text_id}]
  -- 以下 3 列由 P3-STORE-01 迁移加入。NULL = 用户尚未标记。
  -- 取值与 ui.md §3.8 的「已确认 / 忽略」一致，不是 open/acknowledged/dismissed。
  user_state      TEXT CHECK (user_state IN ('confirmed','ignored')),
  user_state_by   TEXT,                          -- 标记操作者
  user_state_ns   INTEGER,                       -- 标记时间，Unix 纳秒
  UNIQUE (session_id, rule_id, dedup_key)
);
CREATE INDEX idx_find_session ON findings(session_id, first_ns);

-- ============ 缺口 ============
CREATE TABLE gaps (
  id              INTEGER PRIMARY KEY,
  session_id      INTEGER REFERENCES sessions(id) ON DELETE CASCADE,  -- NULL = 全局（影响所有活动会话）
  collector       TEXT NOT NULL,
  kind            TEXT NOT NULL,
  affects         TEXT NOT NULL,                 -- JSON 数组：["file","net",...]
  from_ns         INTEGER NOT NULL,
  to_ns           INTEGER NOT NULL,
  count           INTEGER,
  detail          TEXT
);
CREATE INDEX idx_gaps_session_ts ON gaps(session_id, from_ns);

-- ============ 调试（仅 debug.keep_raw_events） ============
CREATE TABLE raw_events (
  session_id      INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  seq             INTEGER NOT NULL,
  ts_ns           INTEGER NOT NULL,
  kind            TEXT NOT NULL,
  json            TEXT NOT NULL,                 -- RawEvent JSON（已脱敏）
  PRIMARY KEY (session_id, seq)
) WITHOUT ROWID;

-- ============ Agent 间通信（P6-STORE-01；完整语义见 inter-agent-communication §7） ============
-- watch_groups 已在本段 DDL 开头建表（sessions.group_id 引用它）。
CREATE TABLE agent_instances (
  id            INTEGER PRIMARY KEY,
  session_id    INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  root_proc_uid INTEGER NOT NULL,
  profile       TEXT,
  role          TEXT NOT NULL,             -- primary / sub_agent / mcp_server / tool / unknown
  parent_id     INTEGER REFERENCES agent_instances(id),
  evidence      TEXT NOT NULL,
  label         TEXT                       -- 用户标注的名称
);

CREATE TABLE ipc_channels (
  id            INTEGER PRIMARY KEY,
  session_id    INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  kind          TEXT NOT NULL,             -- pipe / unix_stream / unix_dgram / named_pipe / loopback_tcp / loopback_udp
  a_proc_uid    INTEGER NOT NULL,
  b_proc_uid    INTEGER,                   -- NULL = 对端未知（见 field_evidence）
  b_session_id  INTEGER,                   -- 对端在同组另一个会话中时填写
  name          TEXT,                      -- socket 路径 / 管道名 / 端口（已脱敏）
  a_to_b_bytes  INTEGER,
  b_to_a_bytes  INTEGER,
  protocol      TEXT,                      -- mcp / a2a / lsp / http / unknown
  first_ns      INTEGER NOT NULL,
  last_ns       INTEGER NOT NULL,
  evidence      TEXT NOT NULL,
  field_evidence TEXT,
  source        TEXT NOT NULL
);
CREATE INDEX idx_ipc_session ON ipc_channels(session_id, first_ns);

CREATE TABLE agent_rpc (
  id            INTEGER PRIMARY KEY,
  channel_id    INTEGER NOT NULL REFERENCES ipc_channels(id) ON DELETE CASCADE,
  ts_ns         INTEGER NOT NULL,
  duration_ns   INTEGER,
  method        TEXT NOT NULL,             -- tools/call / resources/read / ...
  target        TEXT,                      -- 工具名 / 资源 URI（已脱敏）
  arg_shape     TEXT,                      -- JSON：键名 → {type, len}
  req_bytes     INTEGER,
  resp_bytes    INTEGER,
  is_error      INTEGER,
  content_match TEXT,                      -- 内容哈希命中的文件引用（可选）
  evidence      TEXT NOT NULL              -- E2
);

CREATE TABLE agent_links (
  id            INTEGER PRIMARY KEY,
  group_id      INTEGER,                   -- 监控组；单会话时为 NULL
  session_id    INTEGER NOT NULL,
  from_agent    INTEGER NOT NULL REFERENCES agent_instances(id),
  to_agent      INTEGER REFERENCES agent_instances(id),
  to_external   TEXT,                      -- 对端不在监控范围内时的描述（exe / 主机）
  kind          TEXT NOT NULL,             -- spawned / ipc / rpc / self_reported / shared_artifact / remote
  bytes         INTEGER,
  count         INTEGER NOT NULL DEFAULT 1,
  first_ns      INTEGER NOT NULL,
  last_ns       INTEGER NOT NULL,
  evidence      TEXT NOT NULL,
  refs          TEXT NOT NULL              -- JSON：依据记录
);
```

### 3.1 时间线视图

UI 的时间线不读取物理大表，而是由查询层按需做 `UNION ALL`：

```sql
CREATE VIEW timeline AS
  SELECT session_id, first_ns AS ts_ns, 'file'    AS cat, id, proc_uid, evidence FROM file_access
  UNION ALL SELECT session_id, start_ns, 'net',     id, proc_uid, evidence FROM net_flows
  UNION ALL SELECT session_id, ts_ns,    'dns',     id, proc_uid, evidence FROM dns
  UNION ALL SELECT session_id, ts_ns,    'http',    id, proc_uid, evidence FROM http
  UNION ALL SELECT session_id, ts_ns,    'proc',    id, proc_uid, evidence FROM process_images
  UNION ALL SELECT session_id, ts_ns,    'agent',   id, proc_uid, evidence FROM agent_events
  UNION ALL SELECT session_id, first_ns, 'ipc',     id, a_proc_uid, evidence FROM ipc_channels
  -- agent_rpc 没有 session_id（与 inter-agent-communication §7 一致）；会话从所属通道继承。
  UNION ALL
  SELECT c.session_id, r.ts_ns, 'rpc', r.id, NULL, r.evidence
  FROM agent_rpc r
  JOIN ipc_channels c ON c.id = r.channel_id
  UNION ALL SELECT session_id, first_ns, 'finding', id, NULL,     evidence FROM findings
  UNION ALL SELECT session_id, from_ns,  'gap',     id, NULL,     'E1'     FROM gaps;
```

查询时必须带 `session_id` 和时间范围条件。各表都有 `(session_id, ts)` 索引，SQLite 会把条件下推到每个分支。`rpc` 分支的 `session_id` 来自 `ipc_channels`，条件下推到 `idx_ipc_session`，再按 `channel_id` 取 `agent_rpc`。时间线分页采用 keyset 分页：`(ts_ns, cat, id) > (?, ?, ?)`。

### 3.2 全文搜索（S，P2）
对路径、argv、URL 建 FTS5 索引 `fts_text(table, id, text)`，采用 trigram tokenizer，支持子串搜索。这会增加约 30% 的体积【待验证】，默认开启，可以关闭。

`process_images` 行写入时进索引：有 `argv` 用 `argv`，没有时用 `exe`（轮询采集器只存可执行文件路径，`argv`、`cwd` 为 NA）；两者都没有就不建索引行，不写空串。同一 `(session_id, proc_uid, seq)` 再次写入时忽略（`ON CONFLICT DO NOTHING`），不让整批回滚，也不重复建索引。FTS 关闭时的 `instr` 回退同样匹配 `coalesce(argv, exe)`。

时间列一律是 Unix 纳秒（墙钟）。采集器内部的单调时钟只用来排序和算间隔：`gaps.from_ns/to_ns` 按缺口事件自带的（单调, 墙钟）一对换算；进程退出、以及没见到开始的进程，用事件的墙钟时间。

## 4. 写入路径

- Batcher 每批执行 `BEGIN IMMEDIATE ... COMMIT`。
- 重复更新的记录使用 UPSERT，包括 `net_flows` 的字节数、`file_access` 中的 partial 记录、`ipc_channels` 按 `(session_id, kind, a_proc_uid, b_proc_uid, name)` 累加字节，以及 `findings` 的 count 累加：
  ```sql
  INSERT INTO findings (...) VALUES (...)
  ON CONFLICT (session_id, rule_id, dedup_key)
  DO UPDATE SET last_ns = excluded.last_ns, count = count + 1, refs = json_insert(refs, '$[#]', ...);
  ```
  `refs` 最多保留 50 条。
- `net_flow_buckets` 的写入也是 UPSERT，把新增字节累加到同一个桶。
- `processes` 按主键 `(session_id, proc_uid)` UPSERT。同一个进程常被写两次：启动在一批，退出在后面一批（轮询下基线进程的退出没有对应的启动）。第二次只补第一次未知的列：`exit_ns` / `exit_code` / `exit_signal` 取新值（新值未知时保留旧值），`parent_uid` / `ppid` / `user_id` / `signer` / `agent` 保留首次写入的值，`start_ns`、`how`、`depth`、`evidence`、`source` 不变。重复写入不再因主键冲突让整批回滚。
- 读写量估算：一次典型 Agent 会话 1 小时产生约 5 万条 file_access、5 千条 net_flows、2 万个桶。按每行约 300 B（含索引）计算约 25 MB，满足 NFR-03。【待验证】

## 5. 保留与轮转

配置（`[retention]`）：

| 键 | 默认 | 说明 |
|---|---|---|
| `max_db_bytes` | 2 GiB | 主库 + WAL 的总体积上限 |
| `max_age_days` | 30 | 超过该天数的会话会被删除 |
| `min_free_disk_bytes` | 1 GiB | 磁盘剩余空间低于此值时停止写入新会话的细节，只写会话元数据和缺口 |
| `max_session_bytes` | 512 MiB | 单会话上限；超过后该会话进入降级阶梯的 L3 |
| `check_interval_secs` | 300 | 清理检查间隔 |

清理算法（在 Batcher 线程的空闲时段执行）：

```
loop every check_interval:
  1. 删除 ended_ns < now - max_age_days 且 pinned = 0 的会话。
  2. size = page_count * page_size + wal_size
     while size > max_db_bytes * 0.9:
        取 pinned = 0 且已结束的最旧会话，删除。
        没有可删的会话（只剩活动会话或固定会话）则停止，并发出告警 storage_full。
  3. 每次删除后执行 PRAGMA incremental_vacuum(N)，分步回收，每步 ≤ 50 ms。
  4. PRAGMA wal_checkpoint(TRUNCATE)（仅在没有活动读事务时）。
```

- 大会话分批删除，每批 5000 行，避免长事务阻塞写入。
- 删除会在 `schema_meta` 中留下审计记录（键为 `purged:<public_id>`，值为时间和原因），这样会话列表能显示“已按保留策略清理”。

## 6. 迁移策略

- 存储版本号保存在 `schema_meta.schema_version` 中，与事件 schema 版本相互独立。
- 迁移脚本放在 `crates/aw-store/migrations/NNNN_description.sql`，只增不改，并编译进二进制。可以用 `refinery`，也可以用一个约 50 行的自写执行器。
- daemon 启动时的处理：
  1. 若版本低于当前版本：先备份为 `agentwatch.db.bak-v<old>`（使用 SQLite 在线备份 API），再在一个事务内依次执行迁移。
  2. 失败则回滚并拒绝启动，提示用户。
  3. 若版本高于当前版本（降级安装）：以只读模式启动，并提示升级。
- 离线迁移命令：`aw db migrate --dry-run`。
- 测试：每个迁移都配一个旧版本的样例库夹具，放在 `fixtures/db/v<N>.db`，用来验证升级后的查询结果。

## 7. 导出格式

| 格式 | 内容 | 用途 |
|---|---|---|
| JSONL（默认） | 开头一行 `{"type":"header","export_version":1,"session":{...},"collectors":[...],"gaps_summary":{...}}`；之后每行一条记录 `{"type":"file_access", ...表字段}`，按时间排序。`processes` 行另带 `exe_name`（该进程最新一条 `process_images.exe` 的文件名，读不到为 `null`）和 `exit_code`（`null` = 没采，未观测，绝不表示 `0`），读 JSONL 不必再查 `process_images` 才知道进程名 | 程序处理、归档 |
| CSV | 每类记录一个文件，打包为 zip：`processes.csv`、`file_access.csv`、`net_flows.csv`、`dns.csv`、`http.csv`、`findings.csv`、`gaps.csv`、`watch_groups.csv`、`agent_instances.csv`、`ipc_channels.csv`、`agent_rpc.csv`、`agent_links.csv`、`README.txt`（字段说明与字节口径）。`processes.csv.exit_code` 为空 = 没采，未观测，绝不表示 `0`。`agent_rpc.csv` 额外带上所属通道的 `session_id`（表本身没有这列） | 表格分析 |
| Markdown 报告（S，P3） | 会话概览、发现列表、敏感访问、外联域名 Top N、缺口列表 | 人工评审、附到 Issue |
| SQLite 子集（C） | 只含单个会话的独立 .db | 跨机器打开 |

导出规则：
- 所有导出都带 `evidence` 列。
- `findings` 导出时渲染为指定语言的文本，同时保留 `wording_id` 和 `params`。
- 导出前可以再叠加一层脱敏：`--redact-paths` 把用户名替换为 `<user>`；`--redact-hosts` 对内网域名做哈希。
