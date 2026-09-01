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
发布新源码。它先由受保护的 `stage-first-party-adoption.yml` 创建**仅含 unsigned
adoption assertion** 的 PR；审查并合入受保护 `main` 后，
`adopt-first-party.yml` 才会在精确来源分支头仍匹配时请求 KMS proof，并创建另一个只包含
sidecar 与 `pending-adoption → active` 的 activation PR。KMS 因而只会对已合入、可由
Cloud 精确读取的 bytes 签名。`external` 永远不能使用该状态。

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

`status: "disabled"` 的第一方插件保留 adoption assertion 与 KMS sidecar 以保持历史可审计，但它们
不进入 active Marketplace signature batch；因此一次合法下架不会阻塞其他插件的发布、reconcile 或 smoke。

两阶段的受保护工作流调用：第一阶段传入仍是远端当前头的来源 SHA；第二阶段**只传入
`plugin_id`**，从已审查、已合入的 staging assertion 中读取来源 SHA，再重新核验远端分支头。

```text
# 1. 创建 unsigned staging PR；它不会签名、激活、发布或移动 channel。
stage-first-party-adoption.yml

# 2. staging PR 合并后，仅指定插件；workflow 从 main 上的 exact assertion
#    读取并复验 source beta/main SHA，再创建 signed activation PR。
adopt-first-party.yml
```

第二阶段会从 assertion 内保留的 `legacy.factoryRevision` materialize 受保护 Factory baseline，
要求该 revision 仍是当前 protected main 的祖先，并重新生成完全相同的 assertion bytes；所以 staging
PR 因随后 main 更新而 rebase/squash merge 时仍绑定其原始审查 baseline，不能改为 merge parent。
第二阶段随后请求 KMS sidecar；不能在本地或普通 PR 中伪造该证明。两个 PR 都必须经 source
gate、`@coderabbitai review` 和 Finalizer。未来 Beta 发布可追加 history，
但 adoption 中的历史 prefix 永远不能改写。只要 split source 首次记录 post-adoption Beta/Stable
provenance（即使新 source SHA 生成的 artifact 与 adoption release 完全相同，未增加 releaseId），
`.xsec-factory/official-publications/<plugin-id>.json` 与其 KMS proof 就成为
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
`.xsec-factory/snapshots/<plugin-id>`，再重写为源码仓库的
`plugins/<plugin-id>`，并在每个历史 commit 的 index 中移除 `.xsec-market`、
`.xsec-plugin` 和 `.sig.jws.json`。生成后会删除 filter 的 original refs、过期 reflog
并执行 GC；两条最终分支再次断言没有 Marketplace metadata、artifact 或 signature。
候选 Git 仓库用私有空 `--template` 初始化，持久及逐命令强制 `core.hooksPath` 指向 null device，
并屏蔽 global/system Git config，所以 operator 的 `init.templateDir`、模板 hook 或 hook path 不能在
checkout/filter/commit 时改写源码。每个最终 branch 在推送前还逐文件比对为“已签名 artifact + 固定
README/CI”精确树，任何模板残留或本地篡改都会拒绝。它不执行插件代码、不会写 adoption/proof，也不会改 Registry。

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

若需要使用本机凭据，`--credential-helper` 只允许固定的平台 Git installation 所提供的
`manager`、`manager-core` 或 `osxkeychain`。materializer 的**所有** Git 子进程均使用该受信的绝对
Git executable，不通过调用者 `PATH` 解析；它会验证 helper 的 resolved target 仍在同一可信 installation
中，但以其固定的绝对 helper 路径调用，从而保留 Git
multi-call symlink 的 basename dispatch。它刻意不允许 `cache`：该 helper 的默认 socket 会由
`XDG_CACHE_HOME` / `HOME` 选择，不能让调用者环境决定认证请求的接收端；也不允许 `libsecret`，因为
其 D-Bus session 由 `DBUS_SESSION_BUS_ADDRESS` 选择。无论是否使用 helper，sealed HTTPS transport
都清除 Git/curl/GCM trace、GCM store/cache 选择器、non-interactive shell startup、.NET/CoreCLR startup-hook、
profiler 与 diagnostic-port 注入变量，并显式关闭 .NET diagnostic IPC、
代理、CA override 及 `SSLKEYLOGFILE`，不会把认证头或 TLS session key 写入调用者指定的位置。候选
仓库的所有本地 `credential.*` 配置（包括 URL-scoped `credentialStore` / `cacheOptions`）也会在远程
预检前被拒绝。

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

Factory 再读 protected Registry、固定 HTTPS 查询当前分支头并拒绝过期 SHA。`beta` 调度
`publish.yml`；`main` 会重新读取同一 Registry 行的**当前 beta head**并调度同一个 Beta
reconcile，而不是直接推广 Stable。Publisher 在取得全局 publication slot 后还会重新拉取注册
分支，并要求 `source_sha` 仍是该分支**精确 head**（不能只是不早于 head 的 ancestor）；因此晚到
或排队的旧 Beta 永远不能覆盖较新的 Beta。

每个 Beta reconcile 都从只读 Source App 的同一固定 HTTPS fetch 中 materialize 当前注册的
`main`，并确定性重建当前 Beta releaseId。若两者不一致，Factory 只把已 KMS 绑定到该 Beta
provenance 的可读状态置为 `waiting_for_beta`：它不会请求 Desktop smoke、调用 Stable publisher、
追加 Stable/smoke evidence 或移动任何频道指针。后续 `main` source event 会重跑上述比较；只有
main 已精确重建该 Beta 时才转回 `waiting_for_smoke` 并请求一个**新的** Desktop Beta smoke。
这使 beta 领先 main 是正常的等待状态，而不是一次失败的 Stable 发布。

生成 Factory PR 通过 source gate 后仍占用发布语义上的队列：所有会调用 KMS 的发布、
Stable、sidecar repair 和 adoption 工作流都先拒绝任何尚未合并的
`xsec-marketplace/*` PR，避免两个候选基于同一 main 签名。PR 审查期间来源 `beta`/`main`
继续前进时，`Verify generated Marketplace publication merge` 会失败；但该 PR check 通过后
来源仍可能继续前进，所以不能把它当作最终合并授权。

`arm-generated-marketplace-final-merge.yml` 使用 `pull_request_target`，只读取可信的默认分支
workflow 和 GitHub 注入的 PR metadata，**从不 checkout 或执行 PR head**。它为同仓、受允许
`xsec-marketplace/*` Factory 分支（包括 `adopt-first-party-*` 和
`refresh-retained-sidecar-*`）写入 pending 的 `factory-final-merge-gate`；其他 main PR 写入
success/not-applicable，故所需的 Factory context 不会卡住普通产品、文档或 fork PR。完成
source gate、CodeRabbit audit 且所有 CodeRabbit thread resolve 后，受保护 `production` 环境中的
maintainer 必须手工运行 `final-merge-generated-marketplace-pr.yml`。该 workflow 重新读取 live
PR 的 head/base，使用精确 head SHA，验证 release diff、全部 KMS sidecar、注册来源当前 ref、
source gate 与跨 REST pages 的精确 head CodeRabbit audit、分页后的全部 reviewThreads。审查必须由官方
`coderabbitai` 在最后一个可信 OWNER 的 `@coderabbitai review` 请求之后更新，包含精确 full head 与
无 actionable comments 的审查总结；普通 bot 评论、运行中状态、限额消息或不匹配 head 都不能作为通过依据。Factory
candidate 的 `factory-final-merge-gate` 始终由 arm workflow 保持 `pending`：final workflow
绝不写 success，也不依赖 EXIT/SIGTERM trap 恢复状态。全部检查通过后，它临时创建独立、仓库
范围受限的 `XSEC_MARKETPLACE_FINALIZER_APP_ID` /
`XSEC_MARKETPLACE_FINALIZER_APP_PRIVATE_KEY` GitHub App token，并且只用该 token 调用一次
exact-head squash merge API。Finalizer App 不能复用 Publisher token；它仅有
`contents: write`，并是规则/保护配置中唯一允许绕过 pending
Factory gate 的身份。缺少任一配置、取消、runner 异常或 merge 拒绝时，PR 仍然 pending，必须
重新受保护 revalidation，不能通过写 green status 恢复。first-party adoption 也走同一个门禁：它只能激活一个
`pending-adoption` Registry 行，并在合并前后两次重新读取该 proof 绑定的外部 `beta` 与 `main`
分支头。任一检查或 merge 失败都不会让 stale PR 合入，也不会把 pending Factory gate 变为
可复用的 green status。
retained sidecar repair 同样走此门禁：diff 必须严格只修改一个现有
`.xsec-factory/snapshots/<plugin-id>/.xsec-market/releases.json.sig.jws.json`，并在 exact head 上重新进行
KMS/JWS 验签、source gate 与 CodeRabbit audit；它不改变 release history 或 channel pointer。
唯一允许的 no-pointer 例外是当前 Stable 已选中当前 Beta 的 registered external Stable completion：
它必须只包含严格形状的已签名 provenance/status 更新，重新校验外部 `main` ref 后才可合并，且不会
再次触发 Desktop smoke。
另一条独立的 no-pointer 形状是 `beta-smoke-ready`：仅当既有等待状态的不可变 Beta
release/source SHA 未变、注册 `main` 出现一个新的精确头时才允许重绑该 Beta 的可重建性；结果只能是
`waiting_for_beta` 或 `waiting_for_smoke`。只有后者才会请求新的 Desktop smoke；前者会使已经排队的旧
smoke callback 失效。它必须重签 Marketplace/release/provenance sidecar，并同时携带该次比较的精确
`mainGateSha`；release history、Beta/Stable 指针和 Beta evidence 均不得改变。finalizer 在
protected merge 前用只读 Source App 同时复验记录的 `beta` 与 `main` 分支头，任一推进便拒绝该
候选，因而旧的可重建决定绝不会触发 Desktop smoke。

`enforce-factory-main-protection.yml` 是唯一的保护配置自动化，须在 protected `main` 的
production 环境中手工运行，且需要仓库管理权限的
`XSEC_MARKETPLACE_ADMIN_TOKEN`。它将 `source-gate` 和
`factory-final-merge-gate` 分别置于两个边界：它先创建并严格验证只覆盖 `main` 的
`xsec-marketplace-final-exact-head` Ruleset；该 Ruleset 唯一要求固定 GitHub Actions app 的
strict final gate，并且唯一 `pull_request` bypass 是配置的 Finalizer App。成功后才把 classic
branch protection 收敛为严格的 `source-gate`、`enforce_admins` 和 conversation resolution，
同时保留现有无关 checks/review 设置。final merge
不用 Publisher token；它仅在全部 revalidation 后短暂创建独立、仓库范围受限的 Finalizer App
token，并且只用它合入精确 PR。该 App 只有 `contents: write`，是唯一
允许绕过持续 pending Factory gate 的 Ruleset 身份。缺失 production 环境策略或 Finalizer 配置时的安全回退是
PR 保持 pending 并修复/re-run gate，绝不临时降低保护或手工绕过。合并后的 protected-main dispatcher 再次验证相同 head、KMS
sidecar、source gate、CodeRabbit audit/已解决 threads。对于带已注册外部来源的
Stable completion，dispatcher 还会在当前受 KMS 认证的 status 中核对 `published`、相同的 Stable source/release、Desktop
smoke URL 与 Factory revision；只有这份精确 Beta callback 证据存在时才不重复发送 Desktop 矩阵。旧内置插件的人工 Stable
推广/回滚，以及没有终态 callback 证据的受控外部 Stable recovery，都会发送独立的 Stable smoke。
它从 release diff 推导频道，不信任可编辑的 PR title 或 merge subject；任意普通 main push、
adoption 或 sidecar-only repair 都不能触发 smoke。

smoke callback payload：

```json
{"trigger_kind":"smoke_callback","delivery_key":"...","plugin_id":"","source_repository":"","source_ref":"","source_sha":"","marketplace_revision":"40-hex","channel":"beta|stable","smoke_workflow_run_id":"positive decimal","smoke_workflow_run_attempt":"positive decimal"}
```

Factory 要求 smoke revision 是当前 protected main 的祖先。仅 `beta` smoke 会读取该精确
revision 的 Beta pointer；只有 smoke revision 和当前 Factory status 都仍为同一个
`waiting_for_smoke` Beta releaseId/source SHA，才读取每个注册来源的当前 `main` SHA 并调度
`publish.yml` Stable。若较新的 main reconcile 已将相同 Beta 改为 `waiting_for_beta`，旧的保留
smoke callback 会被忽略，绝不能绕过这一门禁。Stable publisher 仍会在有只读 GitHub App token 的
publish slot 中重新读取当前 Beta pointer，并证明 main 可达性与可重建同一个当前 `releaseId`。
因此即使两个 commit 生成相同 artifact，任何在排队期间合入的更晚 Beta、未知仓库、错误 ref、
过期 SHA 或非专用 App 调度都不会移动 Stable。

`publish.yml` 会将前端状态写到
`.xsec-factory/official-status/<plugin-id>.json`：schema 1，包含 `trustTier`、来源
repository/path/refs/betaSha/stableSha/mainGateSha、当前 Beta/Stable releaseId，以及
`waiting_for_beta|building_beta|waiting_for_smoke|promoting_stable|published|failed` 状态、
delivery、Factory/smoke run URL 和 Marketplace revision（如有）。已标记 `published` 的
状态必须能回溯到 adoption 与不可变 publication evidence，且必须有 `stableReleaseId ==
betaReleaseId`、两端 source SHA、`xSecDesktop` smoke run URL 与 Marketplace revision。Factory 会把
这五项精确值追加到同一份已经由 KMS JWS 签名的 `official-publications/<id>.json` smoke outcome；source
gate 会逐项把状态与该 outcome、Beta/Stable source event 对齐。仅填写 SHA 形状、GitHub URL 或手工
revision 的普通 PR 因没有匹配的 KMS proof 而失败，adoption 也不能单独宣称已 smoke/published。
即使此前从未写过 status，`waiting_for_beta`、`waiting_for_smoke` 与 `promoting_stable` 也必须同时带有
当前 Beta releaseId/source SHA，并精确匹配已 KMS 签名的 Beta provenance event；不能仅靠首次创建可读
status 文件伪造一个 Desktop 可见的 in-flight 发布周期。两个 waiting 状态的 `stableSha`、smoke URL 和 Marketplace
revision 必须为 `null`；`promoting_stable` 必须再带精确匹配 KMS Stable event 的 Stable releaseId/source
SHA，并且其 Stable releaseId 必须等于当前 Beta releaseId，且仍不得声称 smoke/revision。
`mainGateSha` 是最近一次决定 Beta 是否可进入 smoke 的受保护来源 `main` 精确头，不是 Stable
promotion 证据；每个生成的 registered Beta PR 和 `beta-smoke-ready` PR 都会把它作为第二个 source
proof，在最终 merge 时与 `betaSha` 一并重新读取。
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
同一 Beta release/source tuple 的 Desktop 终态降级，或改回任何较早、虽有效但并非基线后新增的 smoke
outcome。终态 sidecar 必须原样保留，或精确匹配基线之后追加的 KMS-signed outcome。随后一个**不同**的 Beta release 或 source SHA
会在其精确 `(releaseId, source SHA)` 已作为新的 Beta provenance event 追加到受信基线之后，合法开始新的
`waiting_for_smoke` 周期；仅改 status 文件不能伪造该转换，旧 terminal smoke outcome 仍保留在 append-only
证据中。
若该新 Beta 的生成 PR 已合并而 Desktop dispatch 因临时网络错误失败，完全相同的重复 delivery 不会
重新签名或修改 Factory；它只会在 status 仍精确为该 SHA 的 `waiting_for_smoke` 时，重新 dispatch 当前
受保护 main 的 Marketplace revision。其他状态、过期 SHA 或已完成 `published` 均不会触发 replay。
受信基线中的 `waiting_for_beta`、`waiting_for_smoke` 与 `promoting_stable` 也是不可丢失的 in-flight 绑定：
普通 PR 不能删除它们或改成无关状态，否则仍在飞行的 Desktop callback 会失去其 Beta source/release 证据。
同一 Beta 只允许在两个 waiting 状态间随注册 main 的可重建性转换，随后从 `waiting_for_smoke` 前进到
`promoting_stable`，完成为已验证的 `published`，或由带有基线后新增 Beta provenance 的精确新 Beta 周期取代；
不能从 `promoting_stable` 回退为任一 waiting 状态。
