# P0-CI-04 本地质量门禁检查记录

> 状态：草案
> 最后更新：2026-10-10
> 关联：[P0-CI-04](../04-plan/tasks/P0-foundation.md#p0-ci-04-恢复当前代码的格式clippy-与无特权测试门禁)、[ci-release](ci-release.md)、[testing](testing.md)

## 1. 范围与环境

基线为 `ac9d415`，修复分支为 `p0-ci-04-quality-gates`。实际检查环境为 Linux，无特权；没有加载 eBPF、开启 ETW/eslogger、安装服务或修改证书库。

本轮恢复现有代码的格式、严格 Clippy、单元与集成测试检查，并补齐 CI 的 UI job。没有实现新的采集器、代理编排、Agent 自动注入或 IPC 委托链，也没有改变事件类型、证据规则、HTTP API、数据库迁移或依赖清单。

## 2. 修复说明

- 统一 27 个原有 Rust 文件的格式。其中 23 个文件仅有 rustfmt 差异，其余 4 个同时包含以下修复。
- 模拟器：去掉多余借用，将条件合并到 match guard，使用 for 遍历和范围 contains；原计数行为、断言范围不变。
- 平台可达性：Windows 专用导入与错误构造函数按原调用平台使用；daemon 的 Windows 导入和 CLI 的 Windows 管道常量增加相应门控。Linux loader 与 cgroup 占位实现重新导出，仍拒绝真实操作。
- Windows 测试与示例：两个 ETW/PEB 集成测试按 Windows 门控，全部原断言保留；PoC 的非 Windows 入口明确报告不可用并退出 2。Windows 原实现保留在门控模块内，较大 diff 来自缩进。
- 模拟器服务时序：父进程保留启动 banner 的 stdout 管道，避免过早关闭导致服务 Broken pipe；本次运行自带 UDP 服务先写入真值再回显，调用方等待并验证回显，避免结束服务时漏复制真值日志。
- daemon 停止时序：批处理线程使用独立停止信号，在采集器停止后再释放并等待结束，修复共享信号引发的日志顺序竞争。原跨进程测试断言未放宽。
- 将 daemon 的 JSON 辅助函数移到测试模块前，修复 items_after_test_module。
- UI API 类型生成脚本显式导入 Node 内置 process，修复 ESLint no-undef。
- CI 新增 UI job，使用 ui/package.json 中的 pnpm 版本，以 frozen lockfile 安装，执行 lint、test、build；原 Rust 三平台矩阵和严格门禁保留。

## 3. 实际检查结果

以下命令均退出 0：

| 命令 | 输出摘要 |
|---|---|
| `cargo fmt --all --check` | 无格式差异 |
| `cargo check --workspace` | Finished dev profile；无编译警告 |
| `cargo clippy --workspace --all-targets -- -D warnings` | Finished dev profile；无警告 |
| `cargo test --workspace` | 574 passed，0 failed，0 ignored；各测试目标与文档测试通过 |
| `cargo xtask wording-lint` | 扫描 50 个文件，违规 0，豁免 0 |
| `pnpm -C ui lint` | ESLint 无错误 |
| `pnpm -C ui test` | 2 个测试文件，46 passed，0 failed，0 skipped |
| `pnpm -C ui build` | TypeScript 与 Vite 构建通过 |
| `git diff --check` | 无空白错误 |

针对本轮实际出现的时序失败额外验证：

- `cargo test -p aw-daemon --test foreground second_instance_exits_and_stop_is_ordered --quiet` 连续 5 次通过。
- `cargo test -p sim --test serve --test smoke --quiet` 连续 5 次通过，每次 7 个集成测试。

使用现有 UI 开发依赖中的 YAML 解析器检查了 ci.yml：语法可解析、Rust 矩阵仍有三个 OS，UI 的 frozen 安装及三项检查步骤存在。直接执行 ci.yml 中的 Python 文档链接检查，检查 815 个仓库相对文件链接并通过；该检查不验证锚点。

## 4. 验收边界

上述结果只证明 Linux 本地编译和无特权测试通过。Windows 专用 ETW/PEB 集成测试在 Linux 编译为空目标，原断言留待 Windows runner；macOS 纯解码测试在 Linux 执行不等于原生能力验收。Windows、macOS 原生分支没有在对应系统编译、测试，远端三平台 CI 也未运行。

用户已授权将本轮修复提交并推送到功能分支；GitHub Issue 尚未更新。新增任务卡的正式执行状态仍以后续 GitHub 同步为准，不能用本记录替代远端 CI 或阶段退出验收。
