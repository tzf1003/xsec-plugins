# 用户 Marketplace Factory 模板

`factory-template/` 是可由 Desktop 创建/初始化的用户 Marketplace Factory
目录模板。当前模板仍保留 Beta/Stable 工作流，本文只描述该模板的实际输入与
兼容行为；官方 Factory 的现行发布以[生命周期](plugin-development-release-lifecycle.md)为准。
Desktop 当前选择最高兼容 SemVer，模板渠道指针不能用于限制新 Desktop 可见版本。

每个第三方插件源码留在独立 GitHub 仓库中；Factory 的
`.xsec-factory/registry.json` 是经过审查的仓库 allowlist。发布工作流只读取
其中登记的仓库，并只接受：

- `beta` 渠道：来源提交可从 `refs/heads/beta` 到达；
- `stable` 渠道：来源提交可从 `refs/heads/main` 到达，且重新确定性打包后必须
  等于已经验证的 Beta `releaseId`。

模板会在 `.xsec-factory/snapshots/<id>/` 写入完整 package-input 快照（`plugin.json` 和所有
会进入 archive 的源文件）以及 `.xsec-market/releases.json`。校验器会重新打包
该快照并比对已选 Beta artifact 的 SHA-256。`.agents/plugins/marketplace.json` 继续以
`source.path: "./.xsec-factory/snapshots/<id>"` 引用这些快照，因此现有 Desktop 的本地市场
发现逻辑不必把外部 Git 仓库 URL 当作安装来源。实际 `.xsec-plugin` 是 Factory
GitHub Release 的不可变 asset，release index 绑定其 SHA-256 和 URL。

模板发布通过自身的手动 workflow dispatch 触发；使用前须核对 Desktop 版本与模板
输入契约。工作流先
校验 allowlist、分支可达性和精确 SHA，再以只读 GitHub App token checkout，绝不
运行来源仓库的 npm/pnpm/postinstall、构建脚本、Git hook 或插件代码。详情、登记表
schema、GitHub App secret 名称和恢复方式见
[模板 README](../factory-template/README.md)。

Factory 发布仅接受 `main`，且必须创建名为 `production` 的 GitHub Environment，
并将 required reviewers 限定为发布维护者（可用时启用禁止发起人自行审批）。两个会
写入 metadata / Release asset 的 job 都会先在该 Environment 等待审批；精确
`main` revision、来源 SHA、不可变 artifact 和 release record 共同定义发布边界。
GitHub branch protection/ruleset 可以作为仓库管理层的额外硬化，但工作流不读取
`github.ref_protected`，也不将其作为发版前置条件。每个 Beta release 都带有不可变
来源证据，Stable 还记录对应 `main` 证据，Factory validator 会验证这些证据仍对应
release record。已发布条目改为
`disabled` 时，仅从市场索引移除，必须保留完整快照、release history 和证据；从未
发布的 allowlist 条目可直接移除。

Factory 生成的 metadata、artifact、release index 与 Beta 发布证据可追溯；同一
`plugin.json.version` 不得对应不同 package bytes。Stable 推广只移动现有
`channels.stable.releaseId`，不会重传或覆盖 artifact；但在提交该 pointer 前会
下载选中的 Beta GitHub Release asset 并校验其 SHA-256 仍与 release record 一致。
Desktop 安装官方与外部来源的插件均需确认权限；模板 registry 中的 `policy` 不授予
官方身份或免确认能力。
