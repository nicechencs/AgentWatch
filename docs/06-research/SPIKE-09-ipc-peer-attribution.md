# SPIKE-09 本机 IPC 两端配对与 MCP stdio 拦截

> 状态：未开始
> 最后更新：2026-10-07
> 关联：CAP-IPC, ADR-0013, 任务 P6-LNX-01 / P6-WIN-01 / P6-MAC-01 / P6-AGENT-01
> 时间盒：5 人天
> 负责人：

## 1. 问题

1. 三个平台上，能否以 E1 配对匿名管道、Unix socket、命名管道、回环 TCP 的两端进程？配对准确率是多少？
2. 各类通道的字节数能否取得？只统计跨 Agent 通道时，开销是多少？
3. Claude Code、Codex CLI、Cursor 是否支持通过参数或环境变量指定 MCP 配置文件，从而让 `mcp-tap` 不修改用户配置就能生效？
4. `mcp-tap` 透传对 MCP 调用延迟的影响有多大？

## 2. 假设

- Linux：eBPF `unix_stream_connect` + `unix_stream_sendmsg`，配合 pipe inode 可以做到 E1 配对和字节数。
- Windows：命名管道可以通过 Kernel-File 对 NPFS 的事件配对；匿名管道只能近似配对。
- macOS：ES 只能拿到 `uipc_connect` / `uipc_bind`，字节数 NA。
- 三个 Agent 至少有两个支持外部指定 MCP 配置。
- `mcp-tap` 增加的延迟小于 1 ms。

## 3. 方法

- 环境：Ubuntu 24.04（6.8）、Windows 11、macOS 14；各自使用管理员/root 权限。
- 步骤：
  1. 编写测试程序：父进程分别经匿名管道、Unix socket / 命名管道、回环 TCP 向子进程和无关进程发送已知字节；同时跑一个高通信量的干扰进程（`tar | gzip`）。
  2. 各平台采集并对比真值：配对是否正确、字节误差多少、CPU 开销多少。
  3. 用一个只会回显的最小 MCP server，分别在三个 Agent 中验证：能否用临时配置注入 `aw mcp-tap -- <server>`，以及解析出的 method 和工具名是否完整。
  4. 压测 `mcp-tap`：1000 次 `tools/call`，分别测 p50/p99 延迟增量。
- 代码位置：`spikes/SPIKE-09/`

## 4. 通过标准

| 指标 | 通过 | 不通过时的预案 |
|---|---|---|
| Linux 两端配对准确率 | ≥ 99% | 降级到 sock_diag 采样（S） |
| Linux 字节误差 | < 5% | 只报告连接动作 |
| Windows 命名管道配对 | ≥ 95% | 标为 I（推断配对） |
| macOS Unix socket 两端 | 可取得路径与两端 PID | 字节数标 NA，写入能力矩阵 |
| 开销（干扰进程跑满时） | 额外 CPU < 1% | 提高内核侧过滤的选择性 |
| 支持外部 MCP 配置的 Agent 数 | ≥ 2 | 对不支持的 Agent 只用 E3（hooks 中的 `mcp__*` 工具名） |
| `mcp-tap` p99 延迟增量 | < 1 ms | 优化为零拷贝转发、异步上报 |

## 5. 结果

（待填写）

## 6. 结论与对文档的影响

（待填写：更新 capability-matrix §10、inter-agent-communication §4/§5、ADR-0013 状态）
