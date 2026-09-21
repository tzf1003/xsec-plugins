# 插件注册与源码 Factory 合约

Factory 保存审查后的源码注册、生成快照、不可变制品与来源证明。独立仓库负责插件开发。
日常发布步骤统一见[发布生命周期](plugin-development-release-lifecycle.md)。

## Registry v2

`.xsec-factory/official-registry.json` 是权威注册表。每条记录包含：

```json
{
  "pluginId": "io.example.plugin",
  "trustTier": "external",
  "source": {
    "repository": "owner/repository",
    "path": ".",
    "refs": {"beta": "refs/heads/beta", "stable": "refs/heads/main"}
  },
  "policy": {"installation": "AVAILABLE", "authentication": "ON_INSTALL"},
  "category": "Security",
  "status": "active"
}
```

`first-party` 的 ID/仓库映射使用实现中的封闭 allowlist。`external` 使用独立命名空间、
`AVAILABLE` 安装策略，不能占用 `com.xsec.*` 或 Host 保留 identity。安装策略以当前
Registry 为准，不能把所有第一方包概括为默认安装。两类插件遵循相同的权限确认模型，
原生执行、文件写入等能力仍受实际 Host 授权约束。

`active` 可参与发布，`disabled` 保留历史并退出发现索引。`pending-adoption` 是旧拆仓
迁移的状态，不作为新插件登记方式。`com.xsec.project-workspace` 保持禁用的历史记录；
项目管理由 Desktop Host 提供。

## 包路径与源码读取

活动第一方独立仓库以 `path: "."` 表示仓库根目录。根目录包含 `plugin.json`、
`.codex-plugin/plugin.json` 及适用的 `com.xsec.desktop/`；portable Skill/MCP 继续位于包根。
已禁用的历史记录可保留旧 `plugins/<id>` 路径。后续发布按当前 Registry 读取，历史
provenance 中的路径和 source SHA 保持原字节。

Source App 只获得本次候选涉及仓库的 Contents read 权限。Factory 固定 GitHub 来源，
核对真实远程分支头和精确 SHA，并禁用 Git hook、URL 重写与任意源码执行。
私有源码的读取凭据不能进入快照、日志、插件包或 Desktop。

快照校验拒绝路径逃逸、符号链接、无效 manifest、缺失 entrypoint 和不兼容平台文件。
原生 MCP 的构建输入、Rust target、binary digest 与 artifact digest 必须能对应到固定
Desktop revision，见[运行时合约](agent-plugins-runtime-contract.md)。

## 来源证明与合并

生成快照、release history 和 `.xsec-factory/official-publications/` 保留审计链。
已有 release record 是不可变前缀；同版本不得替换 bytes，已有 artifact 必须仍能校验。
普通 PR 不能删除历史来源证明，也不能用状态文本替代 artifact 或 source gate 证据。

Finalizer 合并前重新读取候选的来源分支头和 Factory main，验证确切 PR head、审查与
必需检查。来源前进或验证失败须生成/验证新的候选；具体 Ruleset 与令牌职责见
[Finalizer policy](factory-finalizer-ruleset-policy.md)。

历史 adoption assertion 和 materializer 用于解释拆仓时的来源映射。其旧 KMS 签署与
两阶段 activation 操作已退役；当前注册和发布使用上述流程，历史证据保留在 Git 历史及
不可变记录中。任何再次迁移都应先核对源字节、release history 和现行 validator。

## 开发与验收入口

- [本地开发准备](local-plugin-development.md)：复用 Desktop Cargo 构建结果准备 MCP 入口。
- [迁移工作手册](agent-plugins-migration-playbook.md)：领域能力、Host 权限和数据所有权。
- [攻击路径参考](attack-path-agent-plugin-reference.md)：portable MCP 与嵌入式 Fabric。
- [按需 Smoke](desktop-remote-marketplace-smoke-contract.md)：三平台、四个 OS/架构目标，默认不作为日常发布门禁。
