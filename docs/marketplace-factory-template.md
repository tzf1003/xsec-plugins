# 用户 Marketplace Factory 模板

`factory-template/` 是可由 Desktop 创建/初始化的用户 Marketplace Factory
目录模板。它不取代本仓库的官方 KMS 发布链，也不共享官方签名、默认安装资格或
Desktop 的官方信任锚。

每个第三方插件源码留在独立 GitHub 仓库中；Factory 的
`.xsec-factory/registry.json` 是经过审查的仓库 allowlist。发布工作流只读取
其中登记的仓库，并只接受：

- `beta` 渠道：来源提交可从 `refs/heads/beta` 到达；
- `stable` 渠道：来源提交可从 `refs/heads/main` 到达，且重新确定性打包后必须
  等于已经验证的 Beta `releaseId`。

模板会在 `plugins/<id>/` 写入 `plugin.json` 快照和
`.xsec-market/releases.json`。`.agents/plugins/marketplace.json` 继续以
`source.path: "./plugins/<id>"` 引用这些快照，因此现有 Desktop 的本地市场
发现逻辑不必把外部 Git 仓库 URL 当作安装来源。实际 `.xsec-plugin` 是 Factory
GitHub Release 的不可变 asset，release index 绑定其 SHA-256 和 URL。

发布由 Desktop 的显式 Beta/Stable 操作触发，而非插件仓库的任意 push。工作流先
校验 allowlist、分支可达性和精确 SHA，再以只读 GitHub App token checkout，绝不
运行来源仓库的 npm/pnpm/postinstall、构建脚本、Git hook 或插件代码。详情、登记表
schema、GitHub App secret 名称和恢复方式见
[模板 README](../factory-template/README.md)。

Factory 的 `main` 必须由 GitHub branch protection/ruleset 保护；模板工作流会
检查 `github.ref_protected`。还必须创建名为 `production` 的 GitHub Environment，
并将 required reviewers 限定为发布维护者（可用时启用禁止发起人自行审批）。保护分支
只能证明 Factory revision 的权威性，不能证明点击 `workflow_dispatch` 的人有发版
权限；两个会写入 metadata / Release asset 的 job 都会先在该 Environment 等待审批。
若团队允许其生成 metadata，则只给 GitHub Actions bot 一个最小化的 bypass，或将
最终 metadata 提交改为受审 PR；不能以去掉分支保护或 Environment 审批作为发布故障
的修复方式。每个 Beta release 都带有不可变来源证据，Stable 还记录对应 `main`
证据，Factory validator 会验证这些证据仍对应 release record。

Factory 生成的 metadata、artifact、release index 与 Beta 发布证据可追溯；同一
`plugin.json.version` 不得对应不同 package bytes。Stable 推广只移动现有
`channels.stable.releaseId`，不会重传或覆盖 artifact。Desktop 对该类市场保持
“未信任/需确认”语义，不能因 registry 中的 `policy` 变成官方默认安装插件。
