# 证据模型

> 状态：草案
> 最后更新：2026-10-06
> 关联：REQ-06、[ADR-0004](../03-adr/0004-evidence-levels.md)、[pipeline](pipeline.md)、[ui](ui.md)

本文件是证据等级的**唯一定义处**。代码中对应 `aw_core::Evidence`，措辞模板对应 `aw_pipeline::wording`。

## 1. 为什么需要证据模型

审计工具最大的风险是把**相关性说成因果**：
- “读了 `.env` 后联网”不等于“上传了 `.env`”；
- “连了 1.2.3.4”也不等于“访问了 evil.com”：可能是共享 IP，也可能是 DNS 缓存过期。

证据模型让每条信息都能回答“你怎么知道的”。

## 2. 证据等级

| 等级 | 名称 | 定义 | 典型来源 | 可信边界 |
|---|---|---|---|---|
| **E1** | 系统观测 | 操作系统或内核在该动作发生时产生的事件，直接归属到进程 | eBPF、ETW、ES、fanotify、NE | 可信度取决于内核。事件可能丢失，丢失时记录 Gap |
| **E2** | 协议观测 | 看到了明文协议元数据 | MITM 代理、TLS uprobe | 只覆盖经过该通道的流量。进程归属依赖端口对应关系（见 network-attribution） |
| **E3** | 自报告 | 被监控程序自己上报的信息 | Agent hooks、遥测、transcript | 可能不完整，也可能被篡改。只用于解释意图，不能当作发生过的证据 |
| **S** | 采样 | 周期性快照得到的状态 | `aw-collector-poll`、nettop、`fs_usage` | 可能漏掉短命进程和短连接；时间精度受采样间隔限制 |
| **I** | 推测 | 由关联规则对其他记录推理得出 | `aw-pipeline::correlate` | **永远不是事实**；必须显示为“推测”并引用依据 |
| **NA** | 不可得 | 该字段或事件在当前平台或模式下无法获取 | — | 必须附带 `na_reason` |

### 2.1 粒度：记录级与字段级

证据等级有两级：
- **记录级** `evidence`：表示“这件事发生了”的可信度。
- **字段级** `field_evidence`：可选，只在某个字段的来源与记录不同时才记录。

示例：macOS 上一条 `file_access`，记录级为 E1（ES OPEN 事件），但 `bytes_read` 的字段级为 NA，原因是 `es_no_read_event`。

常见的字段级特例：

| 字段 | 情形 | 字段级 |
|---|---|---|
| `file_access.bytes_read` | macOS ES | NA (`es_no_read_event`) |
| `file_access.bytes_read` | mmap 读取 | NA (`mmap_not_observable`)，只在检测到 mmap 时填写 |
| `net_flows.domain` | 来自 DNS 应答映射 | E1；若取自全局 DNS 缓存而非本进程的查询，则为 I |
| `net_flows.domain` | 来自 SNI | E1 |
| `net_flows.url` | 未经代理 | NA (`tls_no_proxy` / `direct_bypass_proxy`) |
| `net_flows.bytes_*` | macOS nettop | S |
| `processes.argv` | Windows ETW 启动后补读 PEB | S（可能已被进程改写） |

### 2.2 合并规则

- 多个来源描述同一事实时，取最高等级：E1 > E2 > S > E3。其余来源记入 `corroborated_by`。
- E2 与 E1 描述同一连接时不冲突：E1 给出字节和归属，E2 给出 URL，两者作为各自字段的来源保留。
- E3 与 E1 矛盾时（如 Agent 自称只读了 A，系统观测到还读了 B），生成 `Finding{kind: self_report_mismatch}`，证据等级为 E1。这是一个事实：两份记录不一致。

## 3. 不可得原因码（`na_reason`）

| 代码 | 含义 | 展示文案 |
|---|---|---|
| `es_no_read_event` | macOS ES 没有 read 事件 | macOS 不提供逐次读取事件，只知道“以读方式打开” |
| `mmap_not_observable` | 内存映射读写不产生 read/write 事件 | 文件通过内存映射访问，字节数不可得 |
| `tls_no_proxy` | 加密流量，会话未启用代理 | TLS 加密且未启用代理，URL 不可得 |
| `direct_bypass_proxy` | 启用代理但该连接未经代理 | 进程绕过了代理直连，URL 不可得 |
| `cert_pinned` | 代理握手被客户端拒绝 | 客户端拒绝代理证书（可能做了证书固定） |
| `quic` | UDP/443 QUIC | QUIC/HTTP3 不经过 HTTP 代理，URL 不可得 |
| `ech` | TLS ECH 隐藏了 SNI | 启用了加密 ClientHello，域名不可得 |
| `no_dns_observed` | 未观测到对应的 DNS 解析 | 未观测到 DNS 解析（可能使用了 DoH 或硬编码 IP） |
| `preexisting` | 附着前已存在 | 附着前已存在，之前的数据不可得 |
| `collector_unavailable` | 当前平台/权限下没有对应采集器 | 当前运行模式不支持采集此信息（详见 aw doctor） |
| `redacted` | 被脱敏规则移除 | 已按隐私规则移除 |
| `attribution_break` | 由会话外进程代为执行 | 该操作由会话外的进程（如 dockerd）代为执行，归属链中断 |

新增原因码必须同时更新本表和 `aw_core::NaReason`。

## 4. 展示样式

| 等级 | 徽标 | 颜色语义 | 悬停提示 |
|---|---|---|---|
| E1 | `E1 系统` | 实心，中性色 | 来源：`<source>`，事件时间 |
| E2 | `E2 协议` | 实心，中性色 | 来源：代理 / uprobe |
| E3 | `E3 自报` | 空心描边 | “由 Agent 自行上报，未经系统层确认” |
| S | `S 采样` | 虚线描边 | “采样间隔 N 秒，可能遗漏短事件” |
| I | `推测` | 斜体 + 警示色虚线边框 | 规则名 + 依据记录链接 |
| NA | `不可得` | 灰色 | `na_reason` 的展示文案 |

规则：
- UI 中不得用红色“危险”样式单独标注 I 级结论。敏感路径的高亮是独立的一层标记。
- 导出的 CSV / JSONL 中，每行都带 `evidence`，字段级证据放在 `field_evidence` 对象中。

## 5. 固定措辞模板

所有自动生成的结论文本必须来自下表模板。模板存放在 `crates/aw-pipeline/src/wording/` 的 `zh.toml` / `en.toml` 中；单元测试会对全部输出做禁用词检查（§7）。

| 模板 ID | 中文 | English |
|---|---|---|
| `fact.file_read` | 【E1】{proc} 读取了 `{path}`（{bytes}）。 | [E1] {proc} read `{path}` ({bytes}). |
| `fact.file_opened_read` | 【E1】{proc} 以读方式打开了 `{path}`；读取字节数不可得（{na_reason}）。 | [E1] {proc} opened `{path}` for reading; bytes read unavailable ({na_reason}). |
| `fact.sensitive_access` | 【E1】{proc} 访问了敏感路径 `{path}`（规则：{rule}）。 | [E1] {proc} accessed sensitive path `{path}` (rule: {rule}). |
| `fact.net_send` | 【{ev}】{proc} 向 {dest} 发送了 {bytes_up}，接收了 {bytes_down}。 | [{ev}] {proc} sent {bytes_up} to and received {bytes_down} from {dest}. |
| `infer.temporal` | 【推测·时序相关】{proc_a} 在 {t_a} 读取了 `{path}`（{ev_a}），之后 {delta} 内 {proc_b} 向 {dest} 发送了 {bytes_up}（{ev_b}）。**没有内容级证据表明该文件被上传。** | [Inferred · temporal] {proc_a} read `{path}` at {t_a} ({ev_a}); within {delta}, {proc_b} sent {bytes_up} to {dest} ({ev_b}). **No content-level evidence that the file was uploaded.** |
| `infer.temporal_no_proxy` | 同上，末尾追加：“本会话未启用代理，无法做内容比对。” | Same, with: "Proxy not enabled; content comparison not possible." |
| `infer.temporal_hash_miss` | 同上，末尾追加：“已对经过代理的请求体做分块哈希比对，未发现匹配。” | Same, with: "Proxied request bodies were chunk-hashed; no match found." |
| `evidence.content_match` | 【内容匹配证据】{proc} 在 {t} 向 `{url}` 发送的请求体中，有 {matched}/{total} 个分块与 `{path}` 一致（约占文件 {pct}%）。 | [Content match] Request body sent by {proc} to `{url}` at {t} contains {matched}/{total} chunks identical to `{path}` (~{pct}% of file). |
| `fact.self_report_mismatch` | 【E1】系统观测到 {proc} 访问了 `{path}`，但 Agent 自报告中没有对应记录。 | [E1] {proc} accessed `{path}`, but no matching entry exists in the agent's self-report. |
| `gap.generic` | 【采集缺口】{from}–{to} 期间 {collector} 的 {kinds} 数据可能不完整：{reason}。 | [Gap] {kinds} from {collector} may be incomplete between {from} and {to}: {reason}. |
| `attr.break` | 【归属中断】{proc} 通过 {via} 委托了操作，后续行为发生在会话之外，未纳入统计。 | [Attribution break] {proc} delegated work via {via}; subsequent activity is outside this session and not counted. |

## 6. 内容哈希匹配（I → 内容匹配证据的唯一升级路径）

### 6.1 前提
- 会话启用了代理，且该请求经过代理并成功解密。
- 文件已被会话内进程读取（E1）。在 macOS 上“以读方式打开”也算。
- 文件命中敏感路径规则，或用户在配置中开启了 `correlation.hash_all_read_files`（默认关闭，开销大）。

### 6.2 算法
1. **文件侧**：文件在会话中被读取后，daemon 以自身权限读取该文件。这是**唯一**允许读取敏感文件内容的场景，内容只在内存中用完即弃。
   - 使用内容定义分块（FastCDC，平均 256 B，最小 64 B，最大 1 KB）。小文件使用重叠滑动窗口。
   - 计算 BLAKE3 哈希。小于 64 B 的文件整体哈希。
   - 哈希集合只存在内存中，会话结束即丢弃。默认不落盘；即使落盘也只存加盐哈希。
   - 文件大小超过 `correlation.max_hash_file_size`（默认 10 MB）时跳过，并记录原因。
2. **请求侧**：代理对请求体实时做同样的分块哈希，但先做两件事：
   - 按 `Content-Encoding` 解压 gzip/br/zstd；
   - 若为 JSON，另外对其中的字符串值做 JSON 反转义和 base64 解码。

   请求体本身不保存。
3. **判定**：匹配分块数 ≥ `min_chunks`（默认 3），且匹配覆盖 ≥ 文件长度的 `min_coverage`（默认 20%）。小文件则要求整体命中。
4. **输出**：生成 `Finding{kind: content_match}`，措辞用 `evidence.content_match`。

### 6.3 已知局限（在发现详情中展示）
- 内容经过加密、压缩为未知格式、重新编码或摘要后，就无法匹配。
- 未匹配**不等于**未上传。只能说“未发现匹配”。
- 代理之外的通道（直连、QUIC、其他协议）无法比对。

## 7. 禁止的表述（反例清单）

以下表述不得出现在自动生成的文本、UI 文案和导出中。内容匹配证据模板除外，它自己有限定语。

| 禁止 | 原因 | 应改为 |
|---|---|---|
| “X 上传了文件 Y” / “uploaded file” | 没有内容级证据 | 使用 `infer.temporal` |
| “泄露”“窃取”“外泄”“exfiltrated”“leaked”“stole” | 含有意图判断 | “发送了 N 字节” |
| “访问了 evil.com”（仅凭 IP 反查或全局缓存） | 域名归属不确定 | “连接了 1.2.3.4（推测域名：evil.com）” |
| “Agent 读取了 X”（实际是子进程） | 归属不精确 | 写出具体进程和它与根进程的关系 |
| “没有上传任何文件”“安全”“no data leaked” | 无法证明否定 | “在已观测范围内未发现 …”，并列出缺口 |
| “读取了 0 字节”（实际是 NA） | 把不可得当成 0 | “读取字节数不可得” |
| “所有流量” | 忽略未观测通道 | “已观测的流量” |

实现上，`aw-pipeline` 提供 `wording::lint(text) -> Vec<Violation>`，按上表关键词表检查。覆盖范围包括：
- 单元测试对所有模板的渲染结果；
- `ui/` 的 i18n 资源文件。

CI 中运行。

## 8. 测试要求

- 每条关联规则至少有一个回放夹具。断言内容包括输出的 `evidence`、模板 ID，以及不含禁用词。
- 模拟器剧本 `read_then_send` 覆盖三种结果：内容匹配、哈希未匹配、未启用代理。
