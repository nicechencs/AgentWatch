# CI 与发布

> 状态：草案
> 最后更新：2026-10-06
> 关联：NFR-04、NFR-08、NFR-09、REQ-08、[testing](testing.md)、[security-privacy §6](../01-architecture/security-privacy.md#6-其他安全要求)、[roadmap §5](../04-plan/roadmap.md#5-版本对应)

## 1. 工作流清单

| 文件 | 触发 | 内容 | 引入阶段 |
|---|---|---|---|
| `ci.yml` | PR、push main | 三平台矩阵：fmt → clippy → test；独立 job：deny、audit、wording-lint、ui、build-ebpf、size | P0（P0-CI-02） |
| `docs-lint.yml` | PR（`docs/**`、`*.md`） | 仓库内相对链接与锚点、编号引用（REQ/CAP/ADR/SPIKE/RISK 必须有定义）、文档头 | P0 |
| `e2e-linux.yml` | PR（采集器/daemon 路径）、每夜 | sudo 运行 `cargo xtask e2e --scenario smoke,read_then_send` | P1 |
| `e2e-windows.yml` | 同上 | 管理员运行同一套剧本 | P1 |
| `e2e-macos.yml` | `workflow_dispatch` | 自托管 runner（标签 `self-hosted, macOS, aw-fda`） | P1 |
| `bench.yml` | 每夜、手动 | criterion 微基准 + `bench-e2e`，结果作为 artifact，与历史对比 | P1 |
| `release.yml` | 推送 tag `v*` | dist 构建三平台产物、签名、公证、生成 SBOM 与校验和、创建 GitHub Release | P1（未签名）→ P4（签名） |
| `dependabot.yml` | 每周 | cargo、npm、github-actions | P0 |

### 1.1 `ci.yml` 结构

```yaml
name: ci
on: { pull_request: {}, push: { branches: [main] } }
concurrency: { group: ci-${{ github.ref }}, cancel-in-progress: true }
jobs:
  test:
    strategy:
      fail-fast: false
      matrix: { os: [ubuntu-latest, windows-latest, macos-latest] }
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with: { components: "rustfmt, clippy" }
      - uses: Swatinem/rust-cache@v2
      - run: cargo fmt --all --check
      - run: cargo clippy --workspace --all-targets -- -D warnings
      - run: cargo nextest run --workspace     # 或 cargo test --workspace
  deny:   { runs-on: ubuntu-latest, steps: ["… cargo deny check licenses bans advisories sources"] }
  audit:  { runs-on: ubuntu-latest, steps: ["… cargo audit"] }
  wording:{ runs-on: ubuntu-latest, steps: ["… cargo xtask wording-lint"] }
  ui:     { runs-on: ubuntu-latest, steps: ["… pnpm -C ui install --frozen-lockfile && pnpm -C ui lint && pnpm -C ui test && pnpm -C ui build"] }
  ebpf:   { runs-on: ubuntu-latest, steps: ["… cargo xtask build-ebpf"] }   # P0-LNX-01 完成前 if: false
  size:   { runs-on: ubuntu-latest, needs: [ui, ebpf], steps: ["… cargo xtask size-check"] }
```

（上为结构示意，`…` 处省略了 checkout、工具链安装等步骤。）

## 2. 缓存与时长

- `Swatinem/rust-cache@v2`：按 OS + Cargo.lock 缓存 `~/.cargo` 与 `target/`；只在 main 上保存缓存（`save-if: ${{ github.ref == 'refs/heads/main' }}`），避免 PR 把缓存撑爆。
- sccache：可选用 `mozilla-actions/sccache-action` 配 GitHub Actions 缓存后端；与 rust-cache 二选一评估【待验证：P0-CI-02 实测】。
- pnpm store 用 `actions/setup-node` 的 `cache: pnpm`。
- Linux 使用 mold；Windows 使用 `rust-lld`。
- **时长目标**：PR 全矩阵 < 20 min（NFR-08）；P0 空骨架 < 15 min。超时优先拆分 job，其次按路径过滤跳过不相关的 job（`dorny/paths-filter`）。

## 3. 质量门禁

| 门禁 | 工具 | 失败条件 |
|---|---|---|
| 格式 | `cargo fmt --check`、Prettier | 任何差异 |
| Lint | `cargo clippy -D warnings`、ESLint | 任何警告 |
| 测试 | nextest、vitest | 任何失败 |
| 许可证 / 禁用 crate / 来源 | `cargo deny`（`deny.toml`） | GPL/AGPL/LGPL 静态链接、未列入白名单的许可证、重复的重量级依赖（warn） |
| 已知漏洞 | `cargo audit` / `cargo deny advisories` | 未忽略的 RUSTSEC 公告 |
| 措辞 | `cargo xtask wording-lint` | 模板或 `ui/src/i18n/` 含禁用词 |
| 体积预算 | `cargo xtask size-check` | `aw` + `agentwatchd`（release、strip、含 UI）> 20 MB；增长 > 10% 时警告并附 `cargo bloat` 前 20 项 |
| 文档 | `docs-lint.yml` | 仓库内坏链接 / 锚点、未定义编号 |
| 依赖方向 | `cargo xtask check-deps`（P1 起） | 违反 [repo-layout §3](repo-layout.md#3-依赖方向) 的规则 |

本地一键复现：`cargo xtask ci`（fmt + clippy + test + deny + wording-lint）。

## 4. 发布

### 4.1 工具
- 使用 [dist](https://github.com/axodotdev/cargo-dist)（原 cargo-dist）生成 `release.yml` 与安装脚本，配置写在 `Cargo.toml` 的 `[workspace.metadata.dist]`。
- 发布前：`cargo xtask build-ui`（产出 `ui/dist`）与 `cargo xtask build-ebpf`（Linux）作为 dist 的前置步骤。

### 4.2 产物

| 平台 | 目标 | 产物 | 安装方式 |
|---|---|---|---|
| Linux | `x86_64-unknown-linux-gnu`、`aarch64-unknown-linux-gnu` | `.tar.gz`；`.deb`/`.rpm`（P4，附 systemd 单元） | 安装脚本 / 包管理器 |
| Windows | `x86_64-pc-windows-msvc`、`aarch64-pc-windows-msvc`（S） | `.zip`；`.msi`（P4，含服务注册） | MSI |
| macOS | `aarch64-apple-darwin`、`x86_64-apple-darwin` | `.tar.gz`；P4 起 `.pkg`（含宿主 App 与系统扩展） | pkg |

每个 Release 附：`SHA256SUMS`、`SHA256SUMS.sig`、CycloneDX SBOM（`cargo cyclonedx`）、更新说明。

### 4.3 签名与公证（P4）

| 平台 | 方式 | 所需 secrets |
|---|---|---|
| Windows | Authenticode（`signtool` 或 Azure Trusted Signing【待定】），签 exe 与 msi | `WINDOWS_CERT_PFX_BASE64`、`WINDOWS_CERT_PASSWORD`；或 `AZURE_TENANT_ID`、`AZURE_CLIENT_ID`、`AZURE_CLIENT_SECRET`、`AZURE_SIGNING_ACCOUNT`、`AZURE_CERT_PROFILE` |
| macOS | Developer ID Application / Installer 签名；`notarytool` 公证 + `stapler` | `APPLE_CERT_P12_BASE64`、`APPLE_CERT_PASSWORD`、`APPLE_INSTALLER_CERT_P12_BASE64`、`APPLE_TEAM_ID`、`APPLE_API_KEY_ID`、`APPLE_API_ISSUER_ID`、`APPLE_API_KEY_P8_BASE64`、`APPLE_PROVISIONING_PROFILE_BASE64`（系统扩展） |
| Linux | 签名校验和文件（minisign 或 GPG） | `LINUX_SIGNING_KEY`、`LINUX_SIGNING_KEY_PASSWORD` |

规则：
- secrets 只在 `release` environment 中可用，该 environment 要求人工批准；PR 工作流不得使用任何签名 secret。
- macOS 系统扩展的 entitlement 与 provisioning profile 必须与获批的 Team ID 匹配（见 [SPIKE-08](../06-research/SPIKE-08-apple-entitlements.md)）。
- 未签名的预发布（0.1–0.3）在 Release 说明中写明“未签名，仅供自用”。

### 4.4 卸载验证（NFR-09）

P4 起，`release.yml` 之前跑一个安装 → 启动会话（含 `--proxy`）→ 卸载的流程，卸载后检查：服务不存在、会话 CA 文件已删除且未出现在任何证书库、系统扩展已移除（macOS）、ETW 会话已停止（Windows）。

## 5. 版本策略

- SemVer。workspace 内所有 crate 共用一个版本号（`workspace.package.version`），不发布到 crates.io。
- 阶段对应（与 [roadmap §5](../04-plan/roadmap.md#5-版本对应) 一致）：0.1.0 = P1 结束、0.2.0 = P2、0.3.0 = P3、1.0.0 = P4、1.x = P5。阶段内的修复发 `0.N.x`。
- 预发布 tag：`v0.2.0-rc.1`，dist 自动标为 prerelease。
- 以下变化即使在 0.x 也要在更新说明中单列“破坏性变更”：事件 schema 主版本 `v`、数据库不可迁移、导出格式、CLI 参数移除。
- 更新说明由 Conventional Commits 自动生成（git-cliff【待定】），再人工补充“能力变化”（对应能力矩阵的变化）。

## 6. 发布流程

1. 确认里程碑内的 Issue 均已关闭或移出；`docs/02-platforms/capability-matrix.md` 与实际一致。
2. 在 main 上更新版本号与 CHANGELOG，提交 `chore(release): vX.Y.Z`。
3. `git tag vX.Y.Z && git push --tags`，触发 `release.yml`。
4. 在 `release` environment 中批准签名 job。
5. 在三平台各安装一次，跑 `aw doctor` 与 `smoke` 剧本，结果贴到 Release 讨论或里程碑复盘中。
