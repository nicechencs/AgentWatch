# SPIKE-06 SQLite 写入吞吐与查询延迟

> 状态：部分完成（仅 Windows 开发机上的最小 events 表；产品 DDL、多磁盘、VACUUM、FTS5 未测）
> 最后更新：2026-10-07
> 关联：ADR-0003、ADR-0011、NFR-03、NFR-05、REQ-05
> 时间盒：1 人天
> 负责人：

## 1. 问题

1. 按 storage.md 的表结构，单写线程加批量事务的持续写入吞吐是多少行每秒？分别在 NVMe 和机械硬盘或虚拟机磁盘上测。
2. 100 万条 `file_access` 加 10 万条 `net_flows` 的会话，常用筛选的 p95 延迟是多少？常用筛选包括：按路径前缀、按进程子树、按域名、按时间窗口、按证据等级。
3. 1 小时典型 Agent 会话的库文件有多大？路径字典化存储能省多少空间？
4. 按会话删除加增量 VACUUM 的耗时是多少，对写入有什么影响？
5. 路径的前缀查询和 glob 查询，是用 FTS5（trigram）还是用普通索引加 `LIKE 'prefix%'`？

本次只回答了缩小后的一部分：最小 `events` 表上，批大小 1 / 100 / 1000 的写入吞吐与提交 P99，内联路径对路径字典的文件体积，以及一条按 `proc_uid` 的索引查询。上面 1–5 的其余部分未测。

## 2. 假设

- 写入超过每秒 5 万行；常用查询小于 300 ms；1 小时会话小于 50 MB。

这些仍是目标。本文只把本机这一次测到的数字写在第 5 节。

## 3. 方法

- 代码：`crates/aw-store/benches/sqlite_throughput.rs`（`harness = false`）。依赖只在 `crates/aw-store` 的 dev-dependencies：`rusqlite = { version = "0.32.1", features = ["bundled"] }`。没有 criterion，没有第二数据库引擎，没有开启会拉 OpenSSL 的 feature。
- 环境：Windows 10, this dev machine only。`rustc 1.99.0`（host `x86_64-pc-windows-msvc`）。未区分 NVMe 与机械盘；库文件写在进程的临时目录（`aw-store-spike06-<nanos>`）。Linux 与 macOS 未执行。
- 表不是 storage.md 的产品 DDL。两种形状：
  - inline：`events(id, ts_mono_ns, proc_uid, pid, kind, path TEXT, bytes, evidence)`
  - dict：同上，但 `path_id INTEGER`，加 `path_dict(id, path)`，先插入 64 条路径
  - 两种都有 `CREATE INDEX idx_events_proc_uid ON events(proc_uid)`
- PRAGMA（建表前设 `auto_vacuum`）：`journal_mode=WAL`、`synchronous=NORMAL`、`foreign_keys=ON`、`temp_store=MEMORY`、`mmap_size=268435456`、`auto_vacuum=INCREMENTAL`。事务是 `BEGIN IMMEDIATE` … `COMMIT`。每条事务提交一次。输出里的 `p99_commit_us` 不是单独的 `COMMIT` 或 fsync：计时包住整段 `insert_batch`（`BEGIN IMMEDIATE` + N 次插入 + `COMMIT`）。P99 是这些整批耗时的第 99 百分位（排序后下标 `len * 99 / 100`，再限到最后一个样本），单位微秒。例如 150 次提交时下标是 148。
- 合成行。路径只有 `/tmp/placeholder/0` … `/tmp/placeholder/63`。`proc_uid = row % 16`，`pid = 1000 + (row % 32)`，`kind = row % 4`，`bytes = row % 4096`，`evidence = "E1"`。没有用户名、主机名、argv、环境变量、URL、令牌或文件内容。
- 上限（程序打印，也是实际停止条件）：吞吐每个场景停在 3 秒或 150_000 行，先到为止。体积与查询插入 100_000 行（批大小 1000），再 `PRAGMA wal_checkpoint(TRUNCATE)`，关闭连接后量文件。没有直接插入 100 万行。下文的 100 万行体积是 `bytes_per_row * 1_000_000`，标为外推。
- 计时的查询只有一条：`SELECT COUNT(*) FROM events WHERE proc_uid = 7`。打印出来的 `plan=` 不是这条 SQL 的计划：`EXPLAIN QUERY PLAN` 跑的是 `SELECT id FROM events WHERE proc_uid = ?1`。两者都不是常用筛选的 p95。

命令（依赖已在本机缓存，含 bundled SQLite 的 C 编译）：

```text
cargo bench -p aw-store --offline -- --nocapture
```

未跑：Linux、macOS、NVMe 对机械盘、storage.md 全量 DDL（`file_access` / `net_flows` / 会话表）、直接插入 100 万行、路径前缀 / 子树 / 域名 / 时间窗 / 证据等级筛选、FTS5 trigram 对 `LIKE`、按会话 `DELETE` 加增量 `VACUUM`、1 小时 `typical_agent` 会话。

## 4. 通过标准

| 指标 | 通过 | 不通过时的预案 |
|---|---|---|
| 写入吞吐 | ≥每秒 2 万行 | 加大聚合力度；调整 PRAGMA |
| 常用查询 p95 | <300 ms | 增加索引或物化的汇总表 |
| 1 小时会话大小 | <50 MB | 字典化；缩小桶的粒度 |

本次测到的写入数字高于 2 万行/秒，但那是最小表、短跑，不是产品表的持续写入。后两行未测，不能勾。

## 5. 结果

下面整段输出来自 2026-10-07 这一次 `cargo bench -p aw-store --offline -- --nocapture`（release bench profile）。退出码 0。

```text
machine_note=Windows 10, this dev machine only
cap_secs=3
cap_rows=150000
size_rows=100000
path_slots=64
pragma=journal_mode=WAL synchronous=NORMAL foreign_keys=ON temp_store=MEMORY mmap_size=268435456 auto_vacuum=INCREMENTAL
begin=IMMEDIATE
throughput layout=inline batch=1 rows=150000 elapsed_ms=2992.797 rows_per_s=50120.3 commits=150000 p99_commit_us=40
throughput layout=inline batch=100 rows=150000 elapsed_ms=428.476 rows_per_s=350077.9 commits=1500 p99_commit_us=3412
throughput layout=inline batch=1000 rows=150000 elapsed_ms=195.014 rows_per_s=769177.1 commits=150 p99_commit_us=6583
size layout=inline rows=100000 file_bytes=5513216 wal_bytes=0 total_bytes=5513216 bytes_per_row=55.13 extrapolated_1e6_bytes=55132160 extrapolation=yes_from_100000_rows
query layout=inline rows=100000 proc_uid=7 hits=6250 elapsed_us=147 plan=SEARCH events USING COVERING INDEX idx_events_proc_uid (proc_uid=?)
throughput layout=dict batch=1 rows=150000 elapsed_ms=2914.747 rows_per_s=51462.4 commits=150000 p99_commit_us=38
throughput layout=dict batch=100 rows=150000 elapsed_ms=383.125 rows_per_s=391517.0 commits=1500 p99_commit_us=3150
throughput layout=dict batch=1000 rows=150000 elapsed_ms=176.736 rows_per_s=848724.0 commits=150 p99_commit_us=5456
size layout=dict rows=100000 file_bytes=3702784 wal_bytes=0 total_bytes=3702784 bytes_per_row=37.03 extrapolated_1e6_bytes=37027840 extrapolation=yes_from_100000_rows
query layout=dict rows=100000 proc_uid=7 hits=6250 elapsed_us=132 plan=SEARCH events USING COVERING INDEX idx_events_proc_uid (proc_uid=?)
```

吞吐每个场景都先到 150_000 行，没有被 3 秒截断（batch=1 的耗时最接近上限：2.99 s 与 2.91 s）。

| 布局 | 批大小 | 行数 | 耗时 | 行/秒 | 提交次数 | 整批 P99 |
|---|---:|---:|---:|---:|---:|---:|
| inline | 1 | 150000 | 2992.797 ms | 50120.3 | 150000 | 40 µs |
| inline | 100 | 150000 | 428.476 ms | 350077.9 | 1500 | 3412 µs |
| inline | 1000 | 150000 | 195.014 ms | 769177.1 | 150 | 6583 µs |
| dict | 1 | 150000 | 2914.747 ms | 51462.4 | 150000 | 38 µs |
| dict | 100 | 150000 | 383.125 ms | 391517.0 | 1500 | 3150 µs |
| dict | 1000 | 150000 | 176.736 ms | 848724.0 | 150 | 5456 µs |

体积（checkpoint 之后，WAL 文件长度为 0；100 万行一列是外推，不是再插了一次）：

| 布局 | 行数 | 库文件 | WAL | 合计 | 字节/行 | 外推 1e6 行 |
|---|---:|---:|---:|---:|---:|---:|
| inline | 100000 | 5513216 | 0 | 5513216 | 55.13 | 55132160 |
| dict | 100000 | 3702784 | 0 | 3702784 | 37.03 | 37027840 |

dict 比 inline 小 `5513216 - 3702784 = 1810432` 字节（同为 100_000 行）。这包括 64 行 `path_dict`。路径只有 64 种，字符串是 `/tmp/placeholder/0` … `/tmp/placeholder/63`（单位数时 18 字节，双位数时 19 字节）。更长或更分散的路径没有测。

查询（一次 `COUNT(*)`，不是 p95；命中 6250 行。下面的计划是 `SELECT id` 的，不是 `COUNT(*)` 的）：

| 布局 | 行数 | 耗时 | 命中 |
|---|---:|---:|---:|
| inline | 100000 | 147 µs | 6250 |
| dict | 100000 | 132 µs | 6250 |

同一天在同一台机器上复核：把这个 bench 从当时正在改的工作区拷到以 `97d726d` 为 HEAD 的独立 worktree 后再跑一次。体积完全一致（inline 5513216、dict 3702784、WAL 0、命中 6250、外推 55132160 / 37027840）。耗时不一致，但三个批大小的排序没变：第二次 inline 53316.1 / 352009.0 / 766205.2 行/秒，dict 53588.3 / 388779.0 / 815951.3 行/秒；查询 141 µs / 138 µs。下文结论用的是第一次的数字；耗时是这台机器上的一次读数，不是上限。

另两条命令，同一天，退出码 0（第二次在上述 worktree 中重跑，仍是 0）：

```text
cargo test -p aw-store --offline
```

`tests::placeholder` 通过（1 passed）。

```text
cargo clippy -p aw-store --all-targets --offline -- -D warnings
cargo clippy -p aw-store --benches --offline -- -D warnings
cargo clippy -p aw-store --bench sqlite_throughput --offline -- -D warnings
```

三条退出码都是 0，输出都是 `Finished`，没有打印 warning。第三条是缓存命中（`Finished dev profile in 0.12s`，没有新的 `Checking` 行）。bench 源码本身是由上面的 `cargo bench`（release）编译的；clippy 跑的是 dev profile。

## 6. 结论

只就这一台 Windows 10 开发机、这一次最小表而言。

推荐批大小：**1000**。三个实测点里它吞吐最高（inline 769177.1 行/秒，dict 848724.0 行/秒）。这是数据里的结论，不是因为设计文档写了 1000。整批 P99（含插入，不是单独的 `COMMIT`）从 batch=1 的 40 µs（inline）/ 38 µs（dict）涨到 6583 µs（inline）和 5456 µs（dict）。按每行算，1000 仍是三个点里最快的。这个 P99 远小于 ADR-0003 里「100 ms 或 1000 条」的 100 ms 一端，但按时间积到 100 ms 再提交本次没有测。没有测过大于 1000 的批，也没有测过持续写入，所以不要把这个数字当成产品表的持续吞吐。batch=1 也过了每秒 5 万行这条目标（inline 50120.3，dict 51462.4），但比 100 和 1000 慢一个数量级。

字典表：**这次体积上 dict 更小**（37.03 字节/行，对 inline 的 55.13）。吞吐也略高，差距小于体积差距。只覆盖 64 条短路径。产品里路径更长、更少重复时，这个差距会变，【待验证】。

体积公式（用本次测到的字节/行，不是 storage.md 里约 300 字节的估计）。`55.13` 和 `37.03` 是程序打印的两位小数；外推用未舍入的 `total_bytes / 100000`：

```text
inline_bytes ≈ rows * (5513216 / 100000)    # 打印为 55.13 字节/行
dict_bytes   ≈ rows * (3702784 / 100000)    # 打印为 37.03 字节/行
```

程序打印的外推 1_000_000 行：inline 55132160 字节，dict 37027840 字节。这是 `bytes_per_row * 1_000_000`，不是再插了 100 万行。也不是 1 小时 `typical_agent` 会话的大小：没有按产品表插入，也没有跑剧本。不能用它去判定「1 小时 < 50 MB」。

计时的是 `COUNT(*)`，在 100_000 行上是 147 µs（inline）和 132 µs（dict），命中 6250 行。打印的计划属于 `SELECT id`：`SEARCH events USING COVERING INDEX idx_events_proc_uid (proc_uid=?)`。没有为 `COUNT(*)` 再跑一次 `EXPLAIN`。100 万行、其他筛选、p95，均【待验证】。

以下未测，推荐为「not measured」，不要改 ADR-0003、storage.md 或 performance-budget.md：

- Linux / macOS
- NVMe 对机械盘或虚拟机磁盘
- storage.md 的会话表、`file_access`、`net_flows` 以及其余表
- 直接写入 100 万行后的查询
- 路径前缀、进程子树、域名、时间窗口、证据等级
- FTS5 trigram 对 `LIKE 'prefix%'`
- 按会话删除与增量 VACUUM
- 1 小时典型会话是否小于 50 MB

## 7. 对文档的影响

- [ ] storage.md 的索引与 PRAGMA（未改；本次不是产品 DDL）
- [ ] performance-budget.md（未改；上面的 5 万行/秒与 50 MB 仍是目标，不是本次对产品表的实测）
