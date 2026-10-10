# ADR-0002 UI 以桌面 App 为主（React + Vite，Tauri 外壳）

> 状态：已接受
> 最后更新：2026-10-10（修订：从“浏览器打开、Tauri 以后可选”改为桌面 App 为主）
> 关联：REQ-05、NFR-04、ADR-0005

## 背景

需要提供时间线、筛选、进程树和流量视图。要求迭代快、体积小、三平台一致。

## 决策

- `ui/` 下用 React + TypeScript + Vite；表格用 TanStack Table 加虚拟滚动；时间线用 ECharts 或 vis-timeline，由 P2 阶段的任务定。
- **主要形态是桌面 App**：Tauri 2 外壳（`app/src-tauri/`，crate `aw-desktop`），窗口里加载打包进 App 的 `ui/dist`。
- 进程分工（ADR-0005 不变）：采集服务 `agentwatchd` 继续以管理员权限在后台运行；App 以**普通用户**权限运行，通过**内部通道**（Linux/macOS 的 Unix socket、Windows 的命名管道，见 api-and-cli §1）跟它通信。**App 不开端口、不登录**：daemon 按对端的系统身份（`SO_PEERCRED` 等）认人。
- 前端只在入口处区分两种运行方式：`ui/src/api/transport.ts` 在 Tauri 窗口里把请求交给外壳转发到内部通道，在浏览器里仍走同源 `/api/v1`。页面代码不感知差别。
- 浏览器方式降为**开发和应急**用途：daemon 仍可在 `127.0.0.1:<api.http_port>`（默认 7456，`0` 关闭）提供同一套 UI，`aw ui` 在内部通道上申请一次性 ticket 后用系统浏览器打开。这条路径保留 ticket、Host 校验和响应头 CSP。
- 安装包、签名、自动更新不在本次修订范围，另行排期（P4）。

## 备选方案

| 方案 | 不选的原因 |
|---|---|
| 浏览器为主、Tauri 以后可选（本 ADR 2026-10-06 的原决定） | 真机验收中浏览器登录链路（ticket、预览跳转、CSP meta）反复出问题，而且任何本机网页都能敲到 7456 端口；桌面 App 走内部通道可以把登录和端口整段去掉 |
| Go + Wails 外壳 | 要再引入一种语言和工具链（ADR-0001）；Tauri 与现有 Rust workspace 同语言 |
| Electron | 体积 100 MB 以上，违反 NFR-04 |
| 原生 GUI（egui/Slint） | 做复杂表格和时间线的效率低；AI 对这些生态不熟 |
| 只做 TUI | 时间线和关联跳转的体验差；可以作为 CLI 的补充，放在后期 |

## 后果

- 正面：前端热重载迭代快，AI 最熟悉这套技术栈；App 用系统 WebView，体积远小于 Electron；默认路径没有登录、没有对网页开放的端口。
- 代价：每个平台多一个要签名的 App；WebView 在各平台上有差异（Linux 依赖 webkit2gtk，Windows 依赖 WebView2）；构建需要 Node 工具链，只在构建时用到。
- 跟进：`aw-desktop` 不在根 workspace 里，单独构建（见 `app/README.md`）；浏览器方式保留期间，HTTP 那一侧仍要鉴权和 DNS rebinding 防护；本地开发用 Vite dev server 代理到 daemon。

## 重新评估的触发条件

- WebView 差异导致某平台无法使用 App → 该平台临时回到浏览器方式（`aw ui`），并记录原因。
