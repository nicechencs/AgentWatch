# SPIKE-04 各运行时对代理和 CA 环境变量的认可度

> 状态：未开始
> 最后更新：2026-10-06
> 关联：CAP-URL-01、CAP-URL-04、ADR-0006、REQ-04.4
> 时间盒：2 人天
> 负责人：

## 1. 问题

只通过**环境变量**（不改系统证书库、不改程序配置），能否让下列运行时和工具走显式代理，并信任 AgentWatch 的 CA？

| 运行时 / 工具 | 代理变量（假设） | CA 变量（假设） | 待确认的问题 |
|---|---|---|---|
| Node.js `fetch`（undici） | **默认不认** `HTTPS_PROXY`。Node 24 起可以用 `NODE_USE_ENV_PROXY=1` 打开【待验证】 | `NODE_EXTRA_CA_CERTS`（仅在启动时读取） | 各主版本的行为；是否还有其他打开方式，如 `--use-env-proxy` |
| Node.js `https` 模块、axios、got | 各库自己处理。axios 认 `HTTPS_PROXY` | 同上 | Claude Code、Codex CLI、Gemini CLI 实际用的是哪个 HTTP 客户端，以及它们是否认代理变量（例如 Claude Code 文档中给出的 `HTTPS_PROXY` 支持） |
| Python requests | 认 `HTTPS_PROXY` | `REQUESTS_CA_BUNDLE`（会覆盖默认的 certifi） | |
| Python httpx | 认（`trust_env=True`） | `SSL_CERT_FILE` | |
| Python urllib / aiohttp | urllib 认；aiohttp 需要设 `trust_env=True` | `SSL_CERT_FILE` | |
| Go net/http | 认 `HTTPS_PROXY`；但目标是 localhost 时不走代理 | Linux 上 `SSL_CERT_FILE` 或 `SSL_CERT_DIR`；macOS 和 Windows 上用系统证书库，**不认环境变量**【待验证】 | macOS/Windows 上的 Go 程序可能拿不到 E2 |
| Rust reqwest | 认环境变量 | 用 rustls-native-certs 时认 `SSL_CERT_FILE`；用 webpki-roots 时不认；用 native-tls 时各平台不同 | Codex CLI（Rust）的实际行为 |
| curl | 认 `https_proxy`（小写）和 `HTTPS_PROXY` | `CURL_CA_BUNDLE`、`SSL_CERT_FILE`；Windows 上的 Schannel 版本用系统证书库 | |
| git（https） | 认 `https_proxy`，也认 `http.proxy` 配置 | `GIT_SSL_CAINFO` | |
| pip / npm | pip 认代理变量；npm 认 `HTTPS_PROXY` 和 `npm_config_proxy` | `PIP_CERT`；npm 用 `NODE_EXTRA_CA_CERTS` 或 `npm_config_cafile` | |
| Electron / Chromium（如 Cursor） | 不认环境变量，只认 `--proxy-server` 启动参数 | 用系统证书库 | 预期无法覆盖，标为“直连” |
| Java | 不认环境变量，认 `JAVA_TOOL_OPTIONS=-Dhttps.proxyHost=...` | `-Djavax.net.ssl.trustStore` | 优先级低 |

另外要回答：
- 是否引入一个可选功能，在启动模式下为 Node 注入 `--require` 脚本（用 `global-agent` 或 undici 的 `setGlobalDispatcher`），来强制 `fetch` 走代理？侵入性和可维护性如何？
- HTTP/2 和 WebSocket 能否正常穿过 hudsucker？SSE 流式响应（LLM API 常用）是否会被缓冲或延迟？
- 上游可能还有一个企业代理，即用户原本就设置了 `HTTPS_PROXY`。这时我们的代理要把它设为上游，可行吗？

## 2. 假设

- Python、curl、git、大部分 Node 库可以覆盖。
- Node 原生 `fetch`、Electron、macOS/Windows 上的 Go 不能覆盖。

## 3. 方法

- 用 hudsucker 起一个最小代理，记录每个请求。
- 为每种运行时写一个最小客户端，请求 `https://example.com`。三个平台各跑一遍，把结果填成矩阵。
- 对真实的 Agent（Claude Code、Codex CLI、Gemini CLI、Aider）各跑一次对话，统计经过代理的连接占全部外发连接的比例。
- 代码位置：`spikes/SPIKE-04/`

## 4. 通过标准

| 指标 | 通过 | 不通过时的预案 |
|---|---|---|
| 主流 CLI Agent 的代理覆盖率 | ≥70% 的外发连接 | 评估 Node `--require` 注入方案；在 Linux 上提高 TLS uprobe（CAP-URL-02）的优先级 |
| SSE 延迟增加 | <50 ms | 调整 hudsucker 的流式配置 |

## 5. 结果

（待填：把上表的“待确认”列换成三平台的实测结果）

## 6. 结论

（待填）

## 7. 对文档的影响

- [ ] ADR-0006 中的注入变量清单
- [ ] network-attribution.md
- [ ] capability-matrix 中的 CAP-URL-01
