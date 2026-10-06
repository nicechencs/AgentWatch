# ADR-0008 Windows 只用 ETW，不开发内核驱动

> 状态：已接受
> 最后更新：2026-10-06
> 关联：REQ-01~04、SPIKE-02、[windows](../02-platforms/windows.md)

## 背景

Windows 上可以拿到最完整文件和网络数据的方式，是 minifilter（文件）和 WFP callout（网络）驱动。但内核驱动必须经过 EV 证书签名和微软的 attestation；驱动一旦出错会蓝屏；开发和调试成本高。

## 决策

- 1.0 版本只用用户态 ETW：Kernel-Process、Kernel-File、Kernel-Network、DNS-Client。
- SNI 和抓包是可选功能，优先用系统自带的 pktmon，其次是携带已签名驱动的 WinDivert。
- 如果安装了 Sysmon，可以读取它的事件作为交叉验证。

## 备选方案

| 方案 | 结论 |
|---|---|
| 自研 minifilter + WFP callout | 能力最强，但签名、稳定性和成本都不可接受。等 ETW 被证明不够用时再评估 |
| 强制依赖 Sysmon | 用户得自己安装和配置，而且 Sysmon 没有文件读取事件 |
| API hook（如 Detours 注入） | 侵入性强，会被 EDR 拦截，而且容易被绕过 |

## 后果

- 正面：不需要驱动签名，安装简单，不会蓝屏。
- 代价：文件事件无法在内核中按 PID 过滤，CPU 开销较高；负载高时会丢事件；缓存管理器的 I/O 归属不精确。
- 跟进：SPIKE-02 测量系统繁忙时的 CPU 开销和丢失率。

## 重新评估的触发条件

- 典型场景下事件丢失率超过 1%，或者 daemon CPU 长期超过 5%。
