# 网络归属、流量统计与 URL

> 状态：草案
> 最后更新：2026-10-07
> 关联：REQ-04、REQ-06、REQ-11、[ADR-0006](../03-adr/0006-explicit-mitm-proxy-for-url.md)、[ADR-0013](../03-adr/0013-inter-agent-observation.md)、[SPIKE-04](../06-research/SPIKE-04-proxy-trust-injection.md)、[evidence-model](evidence-model.md)、[capability-matrix](../02-platforms/capability-matrix.md)、[inter-agent-communication](inter-agent-communication.md)

## 1. 要回答的问题与信息来源

| 问题 | 主来源 | 补充来源 | 拿不到时 |
|---|---|---|---|
| 哪个进程建立了连接 | 内核连接事件（E1） | socket 表轮询（S） | — |
| 本地/远端 IP 与端口 | 同上 | — | — |
| 上传/下载多少字节 | 内核 send/recv 事件（E1） | 平台累计计数（sock_diag、nettop，S） | NA |
| 连的是什么域名 | SNI（E1）、本进程 DNS 应答（E1） | 会话内其他进程的 DNS、系统 DNS 缓存（I） | NA `no_dns_observed` / `ech` |
| 完整 URL、方法、状态码 | 显式代理（E2） | Linux TLS uprobe（E2，可选） | NA `tls_no_proxy` / `direct_bypass_proxy` / `cert_pinned` / `quic` |

## 2. 字节口径（必须在 UI 和导出中注明）

| 字段 | 含义 | 包含 | 不包含 |
|---|---|---|---|
| `bytes_up` / `bytes_down` | 传输层应用载荷字节（socket 层） | TLS 记录开销、HTTP 头、协议帧 | IP/TCP/UDP 头、重传、ACK |
| `http_req_body_bytes` / `http_resp_body_bytes` | 代理看到的 HTTP body（解压前、底层传输编码解码后） | — | 请求头 |

各平台采集点与口径的对应关系以 capability-matrix 为准。统一口径的依据如下：
- Linux 的 `tcp_sendmsg` 参数 / `tcp_cleanup_rbuf` 已复制字节；
- Windows Kernel-Network 事件的 `size`；
- macOS nettop 的 `bytes_in/out`。

【待验证】这三者是否都不含协议头、不含重传，分别见 [SPIKE-01](../06-research/SPIKE-01-linux-aya-poc.md)、[SPIKE-02](../06-research/SPIKE-02-windows-etw-poc.md)、[SPIKE-03](../06-research/SPIKE-03-macos-eslogger-poc.md)。

**校准方法**：模拟器向本地 HTTP 服务器上传已知大小的 body，对比采集值与理论值。理论值 = body + 请求头，TLS 场景另加握手和记录开销。验收标准见 REQ-04。

## 3. 连接与进程归属

- E1 采集器在事件中直接给出 PID，由 Enrich 阶段转为 `ProcUid`。
- **继承的 socket**：父进程创建 socket 后 fork，子进程继续使用。Linux eBPF 按实际调用 send 的进程归属，Windows/macOS 按平台提供的 PID 归属。【待验证】三者可能不一致，写入各平台文档。
- **回环连接**：会话内进程连接本机服务时，去查监听该端口的进程：
  - 监听者在会话内：这是内部通信，不计入“外发”；两端配对与字节计入 [CAP-IPC](../02-platforms/capability-matrix.md#10-agent-间通信cap-ipc) 的 `loopback_tcp` / `loopback_udp` 通道；
  - 监听者在会话外：视为委托，见 process-tracking §6。对端被识别为 Agent 时，UI 提示加入监控组；
  - 代理端口特殊处理，见 §5.3。

## 4. IP → 域名映射

### 4.1 数据来源
| 来源 | 方式 | 证据 |
|---|---|---|
| TLS SNI | 解析 ClientHello（eBPF 在 `tcp_sendmsg` 中截取首包 / pktap / WinDivert 或 pktmon） | E1，直接绑定到该流 |
| 本进程的 DNS 应答 | Linux eBPF：`udp_recvmsg` 解析 53 端口；Windows：Microsoft-Windows-DNS-Client ETW；macOS：pktap 53 端口 | E1 |
| 系统解析器代理的查询 | Linux systemd-resolved、macOS mDNSResponder 代表进程查询，属于委托 | 若能从事件中拿到委托者 PID（Windows ETW 中有），则为 E1；否则是 I |
| 代理 CONNECT 目标 | 代理看到 `CONNECT host:port` | E2 |
| DoH / DoT | 解析在客户端内部完成，不可见 | 对应连接的 domain 记为 NA `no_dns_observed`。如果该连接本身去往已知 DoH 提供商，打标签 `doh_suspected` |

### 4.2 匹配规则
连接建立时，按下列顺序取第一个命中：

1. SNI（流级，优先级最高）。通常在连接之后才到，到达后覆盖之前的推断。
2. 代理 CONNECT 目标。
3. 同进程、连接前 `ttl` 内的 DNS 应答，其答案包含该远端 IP。有多个时取最近一条。
4. 同会话其他进程的 DNS 应答 → I。
5. daemon 全局观测到的 DNS 缓存 → I。
6. 都没有 → NA `no_dns_observed`。不做反向 DNS（PTR）查询，因为那会产生外发流量。

一个 IP 对应多个域名时（CDN），保存全部候选域名，UI 显示为“域名（另有 N 个候选）”。

## 5. 显式 MITM 代理（`aw-proxy`）

### 5.1 作用范围
- 仅用于**启动模式**且显式开启 `--proxy` 的会话。
- 附着模式无法给已运行进程注入代理配置，所以不支持。
- 不做透明代理：不改路由和防火墙，不装系统级证书。理由见 [ADR-0006](../03-adr/0006-explicit-mitm-proxy-for-url.md)。

### 5.2 注入方式
启动目标进程时注入以下环境变量（会覆盖用户的同名变量，并在会话元数据中记录原值是否存在）：

| 变量 | 值 | 影响 |
|---|---|---|
| `HTTPS_PROXY` / `HTTP_PROXY` / `https_proxy` / `http_proxy` | `http://127.0.0.1:<port>` | curl、Python requests、Go net/http、多数 CLI |
| `ALL_PROXY` | 同上 | 部分工具 |
| `NO_PROXY` | `localhost,127.0.0.1,::1`，并追加用户原有的值 | 避免代理回环流量 |
| `NODE_EXTRA_CA_CERTS` | `<session>/ca.pem` | Node.js |
| `NODE_USE_ENV_PROXY` | `1` | Node.js 新版本内置 fetch 对代理变量的支持【待验证】 |
| `SSL_CERT_FILE` | `<session>/bundle.pem`（系统 CA + 会话 CA） | OpenSSL 系、Go（Linux） |
| `REQUESTS_CA_BUNDLE` / `CURL_CA_BUNDLE` | 同上 | Python requests、curl |
| `GIT_SSL_CAINFO` | 同上 | git |
| `PIP_CERT` / `NPM_CONFIG_CAFILE` | 同上 | pip / npm |

已知不生效的情况会在 `aw doctor` 和会话概览里提示：
- Node.js 旧版本的内置 `fetch`/undici 默认不读代理变量；
- Rust reqwest 默认读代理变量，但使用 rustls 且只信任内置根证书时不认会话 CA；
- Go 在 macOS / Windows 上使用系统证书库，忽略 `SSL_CERT_FILE`；
- Electron / Chromium 需要 `--proxy-server` 参数。

【待验证】以上整体情况见 [SPIKE-04](../06-research/SPIKE-04-proxy-trust-injection.md)。

### 5.3 直连检测
启用代理的会话中，任何去往非回环地址的 TCP/UDP 连接都会被标为 `direct = 1`，并触发 `direct_bypass_proxy` 发现。例外是发起者为代理自身的连接：它属于 daemon，不在会话内。UDP/443 另标 `quic`。

代理自身的上游流量不计入会话的网络统计，只进入 `http` 表。会话内进程到代理的回环连接则重写：
- `net_flows.remote` 记为代理上游的真实目标；
- `via_proxy = 1`；
- 字节数仍取自内核观测到的回环连接（E1）。

这样，“进程 X 向 api.example.com 发送了 N 字节”在有无代理时口径一致。

### 5.4 记录内容
- **记录**：方法、脱敏后的完整 URL、HTTP 版本、状态码、白名单请求头和响应头（含值，脱敏）、body 字节数、耗时、`Content-Type`。
- **不记录**：body 内容、`Authorization`、`Cookie`、`Set-Cookie`、`Proxy-Authorization`、`X-Api-Key` 等，完整列表见 security-privacy §3。
- 代理按 [evidence-model §6](evidence-model.md#6-内容哈希匹配i--内容匹配证据的唯一升级路径) 对请求体做分块哈希。
- WebSocket：记录升级请求和每个方向的帧数、字节数；帧内容只做哈希。
- SSE / 流式响应：响应结束时记录总字节。
- MCP over HTTP / A2A：`--mcp-tap` 时对已知 MCP 回环端口做反向代理，识别 JSON-RPC method 与 `params.name`，输出 `AgentRpc`（source `proxy/mcp`、`proxy/a2a`）。不存 body。见 [inter-agent-communication §5](inter-agent-communication.md#5-协议层e2mcp-与常见-agent-协议)。

### 5.5 失败处理
| 情况 | 行为 |
|---|---|
| 客户端拒绝会话 CA（握手失败） | 记录 `cert_pinned`。默认**不**自动放行为隧道（避免静默降级），连接失败。配置 `proxy.on_tls_reject = "tunnel"` 可以改为放行：变成 CONNECT 隧道，只记录域名和字节数，不记 URL。 |
| 上游证书无效 | 向客户端返回等价错误；不得替客户端接受无效证书 |
| 代理过载 | 对客户端施加背压，不丢请求 |

### 5.6 技术选型
- `hudsucker`（hyper + rustls）；证书由 `rcgen` 动态签发，缓存 LRU 1024 个。
- 每个会话一个代理监听端口，端口号与会话一一对应，方便归属。
- CA 生命周期见 [security-privacy §5](security-privacy.md#5-代理-ca-证书生命周期)。

## 6. Linux TLS uprobe（可选，P3+）

- 参考 ecapture：对 OpenSSL / BoringSSL 的 `SSL_write`/`SSL_read` 及 Go `crypto/tls` 的 `writeRecordLocked` 挂 uprobe，得到明文，从中提取 HTTP/1 请求行和 HTTP/2 HEADERS 帧。
- 优点：不需要信任注入，对附着模式也有效。
- 限制：
  - Node.js 把 OpenSSL 静态链接进二进制，需要按符号定位；
  - rustls 和去掉符号的二进制不支持；
  - HTTP/2 的 HPACK 需要维护连接状态。
- 产生的 `HttpRequest` 为 E2，`source = linux.uprobe/openssl`。
- 默认关闭。开启时在 UI 提示：“将在内存中读取加密前的明文”。

## 7. 按 Agent / 会话汇总

“网络”视图的统计维度：
- 会话（= Agent 实例）；
- 进程；
- 进程子树：指定某进程，含其后代；
- 域名：已知域名单独成行，其余按远端 IP 成行；
- 远端端口；
- 协议。

任一维度组合都由 `net_flow_buckets` 聚合得到，支持任意时间范围。
