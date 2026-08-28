# 第一方插件拆仓 Factory 合约

`xsec-plugins` 是发布收录与签名 Factory，不是拆分后插件的日常源码仓库。每个
第一方插件源码仓库使用受保护的 `beta` 与 `main`；Factory 只保留生成快照、不可变
artifact、release history、签名和来源证明。

## Registry v2

`.xsec-factory/official-registry.json` 的根对象严格为：

```json
{"schemaVersion":2,"plugins":[{"pluginId":"...","trustTier":"first-party|external","source":{"repository":"owner/repository","path":"plugins/<id>","refs":{"beta":"refs/heads/beta","stable":"refs/heads/main"}},"policy":{"installation":"...","authentication":"ON_INSTALL"},"category":"Security","status":"active|disabled|pending-adoption"}]}
```

`external` 继续使用既有的安全边界：不能使用 `com.xsec.*`，只能
`AVAILABLE`，且不能声明 Desktop 保留的路由、工具或高权限能力。

`first-party` 是封闭 allowlist，只接受以下精确仓库、`plugins/<plugin-id>` 源码路径和
`INSTALLED_BY_DEFAULT`：

| 插件 ID | 仓库 |
| --- | --- |
| `com.xsec.asset-discovery` | [tzf1003/xsec-plugin-asset-discovery](https://github.com/tzf1003/xsec-plugin-asset-discovery) |
| `com.xsec.attack-path` | [tzf1003/xsec-plugin-attack-path](https://github.com/tzf1003/xsec-plugin-attack-path) |
| `com.xsec.project-workspace` | [tzf1003/xsec-plugin-project-workspace](https://github.com/tzf1003/xsec-plugin-project-workspace) |
| `com.xsec.system-terminal` | [tzf1003/xsec-plugin-system-terminal](https://github.com/tzf1003/xsec-plugin-system-terminal) |
| `com.xsec.workspace.approvals` | [tzf1003/xsec-plugin-approvals](https://github.com/tzf1003/xsec-plugin-approvals) |
| `com.xsec.workspace.browser` | [tzf1003/xsec-plugin-browser](https://github.com/tzf1003/xsec-plugin-browser) |
| `com.xsec.workspace.conversation-tree` | [tzf1003/xsec-plugin-conversation-tree](https://github.com/tzf1003/xsec-plugin-conversation-tree) |
| `com.xsec.workspace.files` | [tzf1003/xsec-plugin-files](https://github.com/tzf1003/xsec-plugin-files) |
| `com.xsec.workspace.project-outcomes` | [tzf1003/xsec-plugin-project-outcomes](https://github.com/tzf1003/xsec-plugin-project-outcomes) |
| `com.xsec.workspace.sub-agent` | [tzf1003/xsec-plugin-sub-agent](https://github.com/tzf1003/xsec-plugin-sub-agent) |
| `com.xsec.workspace.traffic` | [tzf1003/xsec-plugin-traffic](https://github.com/tzf1003/xsec-plugin-traffic) |

因此 Registry PR 不能通过把任意包标记为 `first-party` 来取得 `com.xsec.*`、默认安装或
现有终端/浏览器/项目写入权限。

首次迁移使用仅第一方允许的临时 `status: "pending-adoption"`：它只能保留已存在的
内置 Marketplace snapshot、release history、artifact 和已签名 release sidecar，不能
发布新源码。受保护的 `adopt-first-party.yml` 在精确来源分支头仍匹配后创建 KMS proof，
并在同一生成 PR 中把该状态改为 `active`。`external` 永远不能使用该状态。

## 无损 adoption

每个已发布的内置包在切换 Registry 前，由受保护 Factory main 生成：

```text
.xsec-factory/official-adoptions/<plugin-id>.json
.xsec-factory/official-adoption-proofs/<plugin-id>.json
```

第一个文件固定绑定来源仓库、`beta/main` SHA、旧 Factory revision、旧 release document
digest、原始 release document bytes、完整有序 release records，以及迁移瞬间的 Beta/Stable pointer；第二个是对第一
个文件的独立 KMS JWS sidecar，purpose 为
`xsec.plugin-marketplace.first-party-adoption`。校验器会验证历史 record 是当前 history
的不可变前缀、所有历史 artifact 仍可下载验证、release sidecar 和 adoption sidecar 都
能用固定 KMS issuer 的 JWKS 验证。迁移不会生成 release、改变 SemVer、替换 artifact
或移动频道指针。

受保护工作流调用：

```text
python scripts/external_source_factory.py adopt-first-party \
  --plugin-id com.xsec.workspace.sub-agent \
  --beta-sha <40-hex> --stable-sha <40-hex> --factory-revision <40-hex>
```

随后请求 KMS sidecar；不能在本地或普通 PR 中伪造该证明。未来 Beta 发布可追加 history，
但 adoption 中的历史 prefix 永远不能改写。只要当前 `releases.json` 增加了 adoption prefix
以外的 release，`.xsec-factory/official-publications/<plugin-id>.json` 与其 KMS proof 就成为
强制、append-only 的 source provenance；普通 PR 不能删除、重写或用 adoption proof 替代这些
post-adoption events。

## 可执行源码 materializer

`scripts/materialize_first_party_source.py` 只用于这 11 个固定第一方映射。它从保留的
`.xsec-market/releases.json` 选择当前 Beta/Stable pointer，重新验证每个 `any/any`
artifact 的记录 SHA-256、ZIP 路径、双 manifest 和 entrypoint，然后分别从两个
artifact 建立 `beta` 与 `main` 的精确源码树。生成的仓库固定为：

```text
README.md
.github/workflows/ci.yml
plugins/<plugin-id>/
```

历史通过 `git fast-export`/`fast-import` 从 Factory `main` 中仅保留
`plugins/<plugin-id>`，再在每个历史 commit 的 index 中移除 `.xsec-market`、
`.xsec-plugin` 和 `.sig.jws.json`。生成后会删除 filter 的 original refs、过期 reflog
并执行 GC；两条最终分支再次断言没有 Marketplace metadata、artifact 或 signature。
它不执行插件代码、不会写 adoption/proof，也不会改 Registry。

默认是临时目录 dry-run，stdout **只有**候选 source SHA 与可提交到 Factory PR 的
`pending-adoption` Registry v2 行：

```powershell
python scripts\materialize_first_party_source.py `
  --plugin-id com.xsec.workspace.sub-agent
```

脚本在任何 dry-run 或 `--push` 之前都要求本地工作树严格处于干净的
`HEAD == main == origin/main`，并要求 `origin` 精确为
`https://github.com/tzf1003/xsec-plugins.git`，还会以固定 HTTPS、无提示、只读 `ls-remote` 查询该
远端的当前 `main` 并要求 `HEAD` 精确相等；该查询在隔离的临时目录中执行，并关闭 Git 的 global/system 配置、代理、URL rewrite 和交互提示，故本地 `url.*.insteadOf` 不能把 Factory URL 改写到其他位置。本地缓存的 `origin/main` 过期时会拒绝执行。它先校验保留的 `releases.json` 及其 KMS sidecar，
才会读取 artifact。只有明确指定 `--push` 和该插件的精确 GitHub URL 才会写远端。脚本要求远端
`main` 和 `beta` 都不存在，并用单次 `git push --atomic` 创建两条分支（任何一条不能建立时两条都不写入）。目标预检同样在隔离目录中执行，且会拒绝 candidate repo 中任何 `url.*.insteadOf`/`pushInsteadOf` 条目，避免 Git 将获准 URL 改写到其他仓库；
若 operator 使用获准的 SSH URL，脚本会覆盖 `GIT_SSH_COMMAND`，以空 SSH 配置、固定 `github.com`/`git`、禁用 ProxyCommand/ProxyJump 和严格的 `github.com` host-key 验证运行；它不会采纳 `~/.ssh/config` 的 `Host` 重写，但仍可使用系统 SSH agent 完成认证。
Factory checkout 还必须是完整的非 shallow Git 历史，且不得有任何 `refs/replace/*`；每次可信 Factory 历史读取和 `fast-export` 都强制禁用 Git replacement objects，避免相同 `main` SHA 被本地替换对象呈现为其他祖先内容。
它不读取、打印或保存 token/KMS secret：

```powershell
python scripts\materialize_first_party_source.py `
  --plugin-id com.xsec.workspace.sub-agent `
  --target https://github.com/tzf1003/xsec-plugin-sub-agent.git `
  --push
```

将 stdout 的 Registry 行作为受保护的单独 PR 加入本仓库，保持
`status: "pending-adoption"`。确认远端分支 SHA 与该输出一致后，才运行上一节的
`adopt-first-party.yml`；materializer 本身永远不能激活插件。

## 自动 reconcile payload

Cloud 只能用专用 GitHub App 调用 GitHub Actions 的 `workflow_dispatch` API，固定目标是受保护
`main` 上的 `reconcile-source.yml`；它接受下方完整的 text-only inputs。顶层 workflow 要求
repository variable `XSEC_FACTORY_DISPATCHER_ACTOR` 精确等于该 App bot login，再按
`trigger_kind` 在内部路由 source publish 或受控的 `reconcile-smoke.yml` reusable workflow。
Factory 不监听公开 `repository_dispatch`，因此 Cloud 以外的事件不能绕过该 App 边界。
这里校验的是 GitHub 注入的 `github.actor`、`github.ref` 与 `github.ref_protected`，不是任何
workflow input；即使有人手工从 `main` 点击 dispatch，也会因 actor 不是 Dispatcher App 而在
checkout 前被拒绝。

source event payload：

```json
{"trigger_kind":"source_event","delivery_key":"...","plugin_id":"...","source_repository":"owner/repository","source_ref":"refs/heads/beta|refs/heads/main","source_sha":"40-hex","marketplace_revision":"","channel":"","smoke_workflow_run_id":"","smoke_workflow_run_attempt":""}
```

Factory 再读 protected Registry、固定 HTTPS 查询当前分支头并拒绝过期 SHA；`beta` 才调度
现有 `publish.yml`。Publisher 在取得全局 publication slot 后还会重新拉取注册分支，并要求
`source_sha` 仍是该分支**精确 head**（不能只是不早于 head 的 ancestor）；因此晚到或排队的
旧 Beta 永远不能覆盖较新的 Beta。`main` 只进入等待状态，绝不因 push 直接推广 Stable。

smoke callback payload：

```json
{"trigger_kind":"smoke_callback","delivery_key":"...","plugin_id":"","source_repository":"","source_ref":"","source_sha":"","marketplace_revision":"40-hex","channel":"beta|stable","smoke_workflow_run_id":"positive decimal","smoke_workflow_run_attempt":"positive decimal"}
```

Factory 要求 smoke revision 是当前 protected main 的祖先。仅 `beta` smoke 会读取该精确
revision 的 Beta pointer；如果 current Factory 仍指向同一 Beta，才读取每个注册来源的
当前 `main` SHA 并调度 `publish.yml` Stable。后者仍会在有只读 GitHub App token 的
publisher 中重新读取当前 Beta pointer，并证明 main 可达性与可重建同一个当前 `releaseId`。
它还会比对 smoke revision 中记录的 Beta source SHA；因此即使两个 commit 生成相同 artifact，
任何在排队期间合入的更晚 Beta、未知仓库、错误 ref、过期 SHA 或非专用 App 调度都不会移动 Stable。

`publish.yml` 会将前端状态写到
`.xsec-factory/official-status/<plugin-id>.json`：schema 1，包含 `trustTier`、来源
repository/path/refs/betaSha/stableSha、当前 Beta/Stable releaseId，以及
`waiting_for_beta|building_beta|waiting_for_smoke|promoting_stable|published|failed` 状态、
delivery、Factory/smoke run URL 和 Marketplace revision（如有）。已标记 `published` 的
状态必须能回溯到 adoption 与不可变 publication evidence，且必须有 `stableReleaseId ==
betaReleaseId`、两端 source SHA、`xSecDesktop` smoke run URL 与 Marketplace revision。Factory 会把
这五项精确值追加到同一份已经由 KMS JWS 签名的 `official-publications/<id>.json` smoke outcome；source
gate 会逐项把状态与该 outcome、Beta/Stable source event 对齐。仅填写 SHA 形状、GitHub URL 或手工
revision 的普通 PR 因没有匹配的 KMS proof 而失败，adoption 也不能单独宣称已 smoke/published。
当 `reconcile-smoke` 接受 Desktop 的 Beta smoke 成功回调并触发可重建的 Stable
推广时，会把该回调的精确 Factory revision 和 Desktop Actions URL 带入 Stable 生成
PR；只有该 PR 的指针/证据校验通过后，状态才成为终态 `published`。重复 Beta delivery
使用 `git status --porcelain --untracked-files=all` 检查 Factory 目录，未跟踪的
provenance/status 文件绝不会被错误地当作可跳过的空操作。受控的手动 Stable recovery 只会记录
`promoting_stable`，并保留既有 `betaSha` 以便随后合法的 smoke callback 仍能完成；它不会生成
smoke outcome 或终态状态。即使 Stable 指针已经等于该 Beta（例如 adoption 后的可重建历史
release），publisher 也会幂等写入/保留该 Stable source event；这样每个 terminal smoke outcome
都有精确的 Beta 与 Stable provenance 可绑定。同一 release/source tuple 的晚到 Desktop sweep 会
复用最早的 KMS-signed smoke outcome（包含 URL 与 Factory revision），不会把一个尚未签名的新
revision 写入 `published` status。source gate 对 source provenance 与 smoke outcome 各自执行
受信基线的 append-only continuity；一旦基线已有 `published` status，普通 PR 也不能删除或把
同一 Beta release/source tuple 的 Desktop 终态降级。随后一个**不同**的 Beta release 或 source SHA
会在其精确 `(releaseId, source SHA)` 已作为新的 Beta provenance event 追加到受信基线之后，合法开始新的
`waiting_for_smoke` 周期；仅改 status 文件不能伪造该转换，旧 terminal smoke outcome 仍保留在 append-only
证据中。
若该新 Beta 的生成 PR 已合并而 Desktop dispatch 因临时网络错误失败，完全相同的重复 delivery 不会
重新签名或修改 Factory；它只会在 status 仍精确为该 SHA 的 `waiting_for_smoke` 时，重新 dispatch 当前
受保护 main 的 Marketplace revision。其他状态、过期 SHA 或已完成 `published` 均不会触发 replay。
