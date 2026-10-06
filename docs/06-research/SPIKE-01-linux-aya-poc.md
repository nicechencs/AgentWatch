# SPIKE-01 Linux：Aya eBPF 概念验证

> 状态：未开始
> 最后更新：2026-10-06
> 关联：CAP-PROC-01~04、CAP-FILE-01~07、CAP-NET-01~04、CAP-DNS-01/03、CAP-PRIV-01/03/04、ADR-0010、ADR-0007
> 时间盒：3 人天
> 负责人：

## 1. 问题

1. 用 Aya（stable 加 nightly 的 bpf-linker）能否在一个二进制里同时加载 exec、openat/close、read/write 聚合、tcp_sendmsg/tcp_cleanup_rbuf、udp 53 这几类探针，并且在 Ubuntu 22.04/24.04、Debian 12、Fedora 最新版上都能通过 verifier？
2. 按 cgroup id 过滤、在内核侧做 fd 聚合之后，压测场景下的 CPU 开销和丢失率各是多少？
3. `tcp_sendmsg` 返回值累加的结果，与已知上传字节数的误差是多少？
4. 哪些内核函数在哪些内核版本上挂不上？BPF LSM 在各发行版上是否默认可用？
5. eBPF 捕获的 `start_time` 与 `/proc/<pid>/stat` 换算后是否一致？对应 ADR-0007。
6. 读取 `tcp_sendmsg` 的 iov 首包来取 SNI，在 verifier 下是否可行？

## 2. 假设

- 内核 5.15 以上全部能进入 ebpf-full，只是 BPF LSM 不可用。
- 编译 Linux 内核（`make -j$(nproc)`）时，内核侧聚合的丢失率为 0，daemon CPU 开销小于 3%。
- 字节误差小于 1%（只是应用层载荷）。

## 3. 方法

- 环境：GitHub `ubuntu-latest` runner（sudo）、本地 VM，以及 `virtme-ng` 启动的 5.8 / 5.15 / 6.1 / 6.6 / 最新稳定版内核。
- 步骤：
  1. 用 `aya-template` 生成项目，实现 [linux.md §2](../02-platforms/linux.md#2-采集点详解) 中列出的探针，输出 JSONL。
  2. 跑 `sim/` 的雏形脚本：读取诱饵文件、派生 3 层子进程、用 curl POST 1 MiB 到本地服务器、做一次 DNS 查询。对照采集结果。
  3. 压测：编译内核、用 `rg` 搜全仓库、用 `npm install` 装一个大项目。用 `pidstat` 采集 CPU，并读取 ringbuf 丢失计数。
  4. 逐个内核版本记录哪些探针挂载成功、哪些失败。
- 代码位置：`spikes/SPIKE-01/`

## 4. 通过标准

| 指标 | 通过 | 不通过时的预案 |
|---|---|---|
| 发行版覆盖 | Ubuntu 22.04+ 和 Debian 12 全部探针可用 | 改用 tracepoint 替代 fentry；仍不行就评估 libbpf-rs（ADR-0010 的备选） |
| 字节误差 | <1% | 重新审视探针位置，比如改挂 `tcp_sendmsg_locked` |
| 压测 CPU | <3% | 加大内核侧聚合力度 |
| 压测丢失 | 0 | 增大 ringbuf，或者在内核侧聚合更多事件 |

## 5. 结果

（待填）

## 6. 结论

（待填）

## 7. 对文档的影响

- [ ] capability-matrix：CAP-PROC/FILE/NET/DNS 中的 Linux 行
- [ ] linux.md：探针表、档位表、已知坑
- [ ] ADR-0010 是否维持
- [ ] P1-LNX 任务的工作量估算
