# ADR-0002 UI 采用内嵌 Web UI（React + Vite + rust-embed）

> 状态：已接受
> 最后更新：2026-10-06
> 关联：REQ-05、NFR-04、ADR-0005

## 背景

需要提供时间线、筛选、进程树和流量视图。要求迭代快、体积小、三平台一致。

## 决策

- `ui/` 下用 React + TypeScript + Vite；表格用 TanStack Table 加虚拟滚动；时间线用 ECharts 或 vis-timeline，由 P2 阶段的任务定。
- 构建产物用 `rust-embed` 打包进 `aw-daemon`。`aw ui` 会生成带一次性 token 的 URL，并用系统浏览器打开。
- daemon 只监听 `127.0.0.1` 的随机端口（可配置），并做鉴权，见 security-privacy。
- Tauri 桌面外壳在 P4 作为**可选**项，内部复用同一套前端。

## 备选方案

| 方案 | 不选的原因 |
|---|---|
| Tauri 桌面应用作为唯一形态 | 每个平台又多一个要签名的应用；WebView 在各平台上存在差异；前期收益不大 |
| Electron | 体积 100 MB 以上，违反 NFR-04 |
| 原生 GUI（egui/Slint） | 做复杂表格和时间线的效率低；AI 对这些生态不熟 |
| 只做 TUI | 时间线和关联跳转的体验差；可以作为 CLI 的补充，放在后期 |

## 后果

- 正面：前端热重载迭代快，AI 最熟悉这套技术栈；不增加额外的安装体积，前端 gzip 后预计 1–2 MB。
- 代价：本地 HTTP 服务增加了攻击面，需要鉴权和 CSRF/DNS rebinding 防护；构建需要 Node 工具链，只在构建时用到。
- 跟进：CI 里先构建前端再编译 Rust；本地开发用 Vite dev server 代理到 daemon。

## 重新评估的触发条件

- 用户普遍要求托盘图标或实时通知 → 启用 Tauri 外壳。
