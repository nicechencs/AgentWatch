# 风险登记册

> 状态：草案
> 最后更新：2026-10-07
> 关联：[roadmap](roadmap.md)、[capability-matrix](../02-platforms/capability-matrix.md)、[security-privacy](../01-architecture/security-privacy.md)

评分：可能性 / 影响各取 **高 / 中 / 低**。每个阶段结束时复核一次：更新状态（开放 / 监控中 / 已发生 / 已关闭），已关闭的条目保留不删。

## 总表

| 编号 | 风险 | 可能性 | 影响 | 状态 |
|---|---|---|---|---|
| RISK-01 | Apple ES / NE 授权审批慢或被拒 | 中 | 高 | 开放 |
| RISK-02 | Windows ETW 文件事件量过大，导致 CPU 超预算或丢事件 | 高 | 中 | 开放 |
| RISK-03 | eslogger 输出格式随 macOS 版本变化 | 中 | 中 | 开放 |
| RISK-04 | 代理被绕过（证书固定、不认代理环境变量、QUIC） | 高 | 中 | 开放 |
| RISK-05 | Linux 内核版本碎片化，部分发行版无 BTF | 中 | 中 | 开放 |
| RISK-06 | 进程归属断链（委托给已有守护进程）导致漏记 | 高 | 中 | 开放 |
| RISK-07 | 工具自身成为敏感数据泄露源（数据库、CA 私钥、本地 API） | 低 | 高 | 开放 |
| RISK-08 | 结论措辞夸大，将时序相关误报为上传 | 中 | 高 | 开放 |
| RISK-09 | Rust 编译慢影响 AI 迭代效率 | 中 | 低 | 开放 |
| RISK-10 | macOS CI 无法做特权端到端，回归靠人工 | 高 | 中 | 开放 |
| RISK-11 | 签名证书成本与获取周期（Windows 代码签名、Apple Developer ID） | 中 | 中 | 开放 |
| RISK-12 | 第三方库维护停滞（ferrisetw、endpoint-sec、hudsucker） | 中 | 中 | 开放 |
| RISK-13 | 许可证污染（参考 GPL 项目时照抄代码、WinDivert LGPL/GPL） | 低 | 中 | 开放 |
| RISK-14 | SQLite 写入吞吐不足，高峰时积压 | 低 | 中 | 开放 |
| RISK-15 | 被监控 Agent 在启动模式下行为变化（代理、环境变量、cgroup 影响兼容性） | 中 | 中 | 开放 |
| RISK-16 | `mcp-tap` 与 Agent 的 MCP 配置方式不兼容，或 IPC 计字节开销超出预算 | 中 | 中 | 开放 |

## 明细

### RISK-01 Apple ES / NE 授权审批慢或被拒
- **影响**：macOS 无法做原生 E1 采集，流量统计停留在 S 级；P4 无法按期完成。
- **应对**：P0 第一天提交申请（P0-MAC-01）；P1/P2 用 eslogger + nettop + pktap 兜底（ADR-0009）；UI 和发布说明如实标注降级。
- **触发信号**：提交后 6 周无答复；被拒。
- **负责任务**：P0-MAC-01、SPIKE-08、P4-MAC-*。

### RISK-02 Windows ETW 文件事件量过大
- **影响**：NFR-01 超标；ETW 缓冲区溢出导致丢事件。
- **应对**：用户态在解析前按 PID 集合丢弃（只读事件头）；调大缓冲区；只开启需要的关键字；丢失计数写入 gaps（ADR-0011）。
- **触发信号**：SPIKE-02 测得全量编译场景 CPU >5%；EventsLost >0。
- **负责任务**：SPIKE-02、P2-WIN-01、P2-WIN-02。

### RISK-03 eslogger 输出格式不稳定
- **影响**：macOS 升级后解析失败。
- **应对**：解析器宽松处理未知字段；每个 macOS 大版本录制 fixture 做回归；解析失败记 gap。长期以 P4 原生 ES 替代。
- **触发信号**：macOS beta 发布；fixture 回归失败。
- **负责任务**：P1-MAC-01、P4-MAC-01。

### RISK-04 代理被绕过
- **影响**：完整 URL 覆盖率低。
- **应对**：未经代理的连接一律标“直连”，URL 显示 NA 并写原因；提供各运行时的信任注入清单（SPIKE-04）；可选阻断 UDP/443 以迫使回退到 TCP（默认关闭，需用户确认）。
- **触发信号**：剧本中直连比例 >10%。
- **负责任务**：SPIKE-04、P3-PROXY-*、P3-PIPE-02。

### RISK-05 Linux 内核碎片化
- **影响**：eBPF 程序加载失败。
- **应对**：CO-RE + 启动时能力探测；失败自动降级到 fanotify + sock_diag + proc connector（ADR-0010）；`aw doctor` 输出当前模式。
- **触发信号**：用户报告加载失败；CI 内核矩阵失败。
- **负责任务**：P1-LNX-05、P1-POLL-01。

### RISK-06 进程归属断链
- **影响**：Agent 通过 docker daemon、ssh-agent、git credential helper、同步盘等完成的工作未被计入。
- **应对**：已知守护进程清单 + IPC 连接观测（Unix socket / 命名管道），产生“归属链路中断”gap；不硬套归属。
- **触发信号**：剧本 `delegate-daemon` 中未产生 gap。
- **负责任务**：P1-PIPE-03、P3-PIPE-04。

### RISK-07 工具自身成为泄露源
- **影响**：审计数据（含路径、命令行、域名）或 CA 私钥被其他进程读取；本地 API 被浏览器页面 CSRF。
- **应对**：写入前脱敏（ADR-0012）；数据库与 CA 私钥权限收紧；API 回环 + 随机 token + Origin 校验；安全评审任务。
- **触发信号**：安全评审发现；脱敏测试失败。
- **负责任务**：P2-SEC-*、P3-SEC-01、P4-SEC-01。

### RISK-08 结论措辞夸大
- **影响**：违反 REQ-06，误导用户。
- **应对**：措辞只能来自模板；快照测试；CI 中对 UI 与 CLI 文案做禁用词扫描（如“上传了”“窃取”“exfiltrated”）；`evidence` 标签的 PR 需人工审。
- **触发信号**：禁用词扫描命中。
- **负责任务**：P3-PIPE-05、P3-CI-01。

### RISK-09 Rust 编译慢
- **应对**：crate 细拆；日常 `cargo check`；sccache；Linux mold；dev profile 降低依赖优化级别；CI 用 rust-cache。
- **触发信号**：增量 check >10 s（NFR-08）。
- **负责任务**：P0-CI-01、P0-CI-02。

### RISK-10 macOS 特权端到端靠人工
- **应对**：尽量把逻辑放在可回放的管道中；提供 `sim` 一键脚本和手工验证清单；中期评估自托管 Mac runner。
- **负责任务**：P1-SIM-03、P4-CI-03。

### RISK-11 签名证书
- **应对**：预发布阶段不签名；P3 中期开始采购（Windows 优先考虑 Azure Trusted Signing，成本低于 EV）【待验证】。
- **负责任务**：P4-CI-02。

### RISK-12 第三方库停滞
- **应对**：平台库只在采集器 crate 内使用，外层只依赖 `aw-core` 的统一事件；必要时 fork 或直接调用系统 API。
- **负责任务**：P0-CORE-01（边界设计）。

### RISK-13 许可证污染
- **应对**：AGENTS.md 明确禁止从 GPL 项目复制代码；`cargo deny` 检查依赖许可；WinDivert 仅作可选功能并单独评估。
- **负责任务**：P0-CI-02。

### RISK-14 SQLite 吞吐不足
- **应对**：聚合优先（ADR-0011）；批量事务；WAL；单写线程；SPIKE-06 定下上限。
- **负责任务**：SPIKE-06、P1-STORE-02。

### RISK-15 启动模式影响被监控程序
- **应对**：代理默认关闭（`--proxy` 显式开启）；注入的环境变量在会话元数据中记录；提供 `--no-scope-isolation` 选项。
- **负责任务**：SPIKE-05、P1-DAEMON-03。

### RISK-16 mcp-tap 兼容性与 IPC 开销
- **影响**：Agent 不支持外部指定 MCP 配置时，工具名只能依赖 E3 自报告；管道与 Unix socket 流量大，计字节可能超出 CPU 预算。
- **应对**：SPIKE-09 先验证；包装器 fail-open；只对跨 AgentInstance 的通道计字节，过滤在内核侧完成；不兼容的 Agent 降级为 E3，并在 UI 中标注。
- **触发信号**：SPIKE-09 中支持外部 MCP 配置的 Agent 少于 2 个；`typical_agent` 剧本开启 IPC 采集后 CPU 增量 ≥1%。
- **负责任务**：P6-DOC-01、P6-AGENT-01、P6-LNX-01。
