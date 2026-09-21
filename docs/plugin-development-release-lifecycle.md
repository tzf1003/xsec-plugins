# 插件开发与发布生命周期

本文是 Factory 发布操作的统一入口，核对基线为 2026-09-21 的已合并 `main`。
Desktop 开发入口见[完整开发指南](https://github.com/tzf1003/xSecDesktop/blob/main/docs/plugins/plugin-development-and-release-guide.md)。

## 开发与兼容

插件源码在独立仓库维护。Desktop 开发工作区检查目录后创建私有快照；开发者确认权限后
接入，保存源码并完成自身构建后显式重新载入。带 MCP 的本地包先按
[本地开发准备](local-plugin-development.md)生成当前系统的入口文件。

插件必须兼容 Windows、macOS、Linux。macOS 同时支持 arm64 与 x86_64，因此完整矩阵是
三平台、四个 OS/架构目标。日常开发、更新和发布默认不运行跨平台 Desktop Host Smoke，
也不等待其完成；源码 CI、包结构校验和受影响功能检查仍需执行。原生依赖、Host API、
安装器、路径或 WebView 行为变更按风险选择专项验证，并明确记录实际覆盖目标。

## 注册与包根目录

通过审查 PR 在 `.xsec-factory/official-registry.json` 登记插件 ID、源码仓库、包路径、
固定来源 refs、安装策略与状态。只有 `active` 条目进入发布。注册不是权限授权；官方与
外部插件安装时均需确认权限，原生执行另按 Host 的确认边界处理。

独立插件通常以仓库根目录为包根，`source.path` 为 `.`，其中包含 `plugin.json`、
`.codex-plugin/plugin.json` 和适用的 `com.xsec.desktop/`。不要在独立源码仓库重复嵌套
`plugins/<id>/`。历史 provenance 的内层路径保持原字节，作为审计前缀；新记录按当前
Registry 路径生成。完整约束见[注册与源码合约](first-party-plugin-factory.md)。

## 发布步骤

1. 完成源码审查、版本提升及受影响检查，推送精确提交。`beta → main` 可以作为源码
   分支审查流程；Marketplace 发布单位是不可变 SemVer。
2. 确认 Registry 的仓库、路径和状态与待发布源码一致。读取远程实际 SHA，保留来源证据。
3. 使用 Factory `main` 的受保护发布工作流；配置的第一方 source webhook 也可进入
   受保护 source batch。通用外部插件按 Registry 使用显式发布入口。
4. Factory 用只读 Source App 取得指定源码，验证来源、manifest、入口和安全归档路径，
   确定性打包。普通外部源码不会在发布器中执行任意 npm/pnpm、Git hook 或构建脚本；
   原生 MCP 使用明确允许的构建 recipe 和固定 Desktop revision。
5. Factory 写入不可变 artifact、release index 与来源证明，经 source gate、审查和
   exact-head Finalizer 合并。Source App 与 Finalizer App 的权限分别保管。
6. 回读已合并 Marketplace revision、插件 version、releaseId、下载 URL 和 SHA-256。
   Desktop 刷新后按 Host/API/OS/架构选择最高兼容版本，安装时确认权限。

当前 `publish.yml` 手动输入如下，以目标 revision 的 workflow 定义为准：

| 输入 | 用途 |
| --- | --- |
| `maintenance` | `release` 或 `align_desktop_defaults` |
| `plugin_id` | 已注册外部插件 ID；空值选择内置发布器 |
| `source_sha` | 已注册源码仓库的精确 40 位小写提交 SHA |
| `native_sidecars_source_sha` | 发布器要求的 Desktop `main` 精确 SHA，用于受控原生 sidecar 构建 |
| `reconcile_delivery_key`、`reconcile_dispatch_nonce` | 自动 reconcile 回执绑定；普通手工发布留空 |

当前手动入口不接受 `channel` 或 `release_id`。部分内部 schema 仍有历史渠道字段，
不能把它们当成额外的 Stable 晋级步骤。主分支 push 的默认集合维护也不等于发布新插件版本。

## 不可协商边界

| 场景 | 身份 | 可否同内容热更新 | 云端效果 |
| --- | --- | --- | --- |
| 本地 Desktop 开发者模式 | `dev_revision`（私有开发快照的修订） | 可以；用于本地热重载 | 不会 |
| 官方 Marketplace 发布 | 不可变 `releaseId` 和 artifact SHA-256 | 不可以；不同内容必须提高版本 | 仅通过受保护工作流发布 |

`dev_revision` 不是云端版本号，也不是 `releaseId` 的替代品。它只标识当前本地私有
快照，不得据此声称已上传到 Marketplace 或任何云端 preview。

一个 `plugin.json.version`（SemVer）只能对应一个不可变 release。内容、engine 条件或
artifact 摘要变化时，必须先提高 `plugin.json.version`。发布器会以
规范 JSON 重新计算 `releaseId`；不要手工保留、修改或伪造它。

已发布插件只能保留条目并设为 `disabled`，同时保留快照、release history、artifact 与
provenance。source gate 对照 trusted pre-change Factory revision：因此即使
同一 PR 同时删除 registry、快照和证据，也不能把已发布插件伪装成从未发布的授权。

外部源码可达性校验的 Git transport 也有独立信任边界：checkout 固定为
`https://github.com`，拒绝 `insteadOf` 等本地 Git URL 改写，并写入
verified ref。这只防止临时只读 token 被 Git transport 重定向，绝不表示外部插件
代码可被执行或信任。

Source App、Finalizer App 与管理员令牌权限分别保管；Finalizer 不复用 Publisher
凭证。

## 不可变性、修复与下架

同一 SemVer 不能对应不同 package bytes。`releaseId` 绑定 version、engine 条件与各目标
artifact 摘要；它不等于某个 archive 的 SHA-256。内容变化须提高版本。

修复已发布问题时发布更高版本；用户侧 rollback 使用已保留的兼容 artifact。
下架将 Registry 条目标为 `disabled` 并从发现索引移除，保留已发布快照、release history、
artifact 和 provenance。历史版本不能被覆盖或伪造为新发布。

Marketplace KMS/JWS 发布链已于 2026-09-20 退役。当前发布不请求市场签名、补签或
Smoke callback 晋级；Desktop 安装包/updater 与 Managed Skill 的签名规则另行执行。

## 交付证据

记录源码 repository/SHA、Factory revision、SemVer、releaseId、artifact SHA-256、
已执行检查和具体结果。[按需 Desktop Smoke](desktop-remote-marketplace-smoke-contract.md)
单独记录 workflow run 与 OS/架构；源码检查成功不能表述为真实 Host 或界面验收成功。
构建、合并、发布、安装验证各自按实际证据报告。
