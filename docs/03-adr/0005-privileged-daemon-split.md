# ADR-0005 特权 daemon 与普通权限 CLI/UI 分离

> 状态：已接受
> 最后更新：2026-10-06
> 关联：REQ-02、REQ-07.6、ADR-0002、[security-privacy](../01-architecture/security-privacy.md)

## 背景

三个平台的原生采集都需要 root 或管理员权限。但被监控的 Agent 应该以普通用户身份运行，UI 也不应该以特权运行。

## 决策

- `agentwatchd`（即 `aw-daemon`）以系统服务方式常驻，并拥有特权：
  - Linux 上是 systemd 服务；Windows 上是以 LocalSystem 运行的服务；macOS 上是 LaunchDaemon。
  - 负责：采集器、管道、存储、代理、本地 API。
- `aw`（即 `aw-cli`）以普通权限运行，通过本地 IPC 与 daemon 通信。
  - IPC 方式：Linux/macOS 用 Unix socket，依靠文件权限和 `SO_PEERCRED`/`LOCAL_PEERCRED` 识别调用方的 uid；Windows 用命名管道，配上 ACL，并用 `GetNamedPipeClientProcessId` 识别调用方。
- Web UI 走 daemon 内置的 HTTP 服务。它只监听回环地址，并使用由 CLI 申请的一次性 token 换成的会话 cookie。
- **启动模式下由 CLI 自己创建目标进程**，这样进程身份、环境变量和终端都是用户自己的；daemon 只负责把它纳入范围。各平台的细节见平台文档和 SPIKE-05。
- 权限模型：普通用户只能看到自己发起的会话。管理员可以看到全部，并且可以附着到其他用户的进程。
- 没有安装 daemon 时，CLI 可以在进程内直接运行轮询采集器（`aw run --no-daemon`），等级为 S。

## 备选方案

| 方案 | 不选的原因 |
|---|---|
| 每次用 sudo 运行 CLI（无 daemon） | 被启动的 Agent 会变成 root，或者需要复杂的降权；历史查询和 UI 需要常驻服务 |
| UI 也以特权运行 | 攻击面大 |

## 后果

- 正面：最小权限；历史数据由一个地方统一管理。
- 代价：需要安装服务；IPC 协议和鉴权也要维护。
- 跟进：API 定义见 api-and-cli.md。daemon 崩溃重启时要写 Gap（NFR-06）。

## 重新评估的触发条件

- 出现无需特权就能得到 E1 采集的平台机制。
