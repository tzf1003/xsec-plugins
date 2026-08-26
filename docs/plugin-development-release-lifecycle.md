# 插件开发与发布生命周期（开发者与 Agent）

本规范定义 XSEC 插件从本地调试到官方 Marketplace 发布、Beta 验证、Stable
推广和回滚的边界。它同时适用于人工开发者和代表开发者执行操作的 Agent。
其中每一步的可信来源不同：本地开发目录不属于云端发布物；云端 Marketplace
也绝不能将未发布的本地目录当作候选更新。

## 两条彼此隔离的链路

| 场景 | 身份 | 同一 `plugin.json.version` 能否变更代码 | 会不会上传或改动云端 |
| --- | --- | --- | --- |
| 本地 Desktop 开发者模式 | `dev_revision`（私有开发快照的修订） | 可以；用于本地热重载 | 不会 |
| 官方 Marketplace 发布 | 不可变 `releaseId` 和 artifact SHA-256 | 不可以；不同内容必须提高版本 | 仅通过受保护工作流发布 |

`dev_revision` 不是云端版本号，也不是 `releaseId` 的替代品。它只标识当前
本机经用户检查并授权的开发目录快照。开发者可在不提高 `plugin.json.version`
的前提下反复保存、刷新并验证本地插件；这些修改不得写入
`.xsec-market/releases.json`，不得产生可安装的 Marketplace artifact，也不得
上传到 Marketplace 或任何云端 preview。

本地调试完成并准备分享时，才进入云端链路。Desktop 开发者模式的目录授权、
私有快照和 sidecar 的重新授权规则以 Desktop 仓库的开发者文档为准；本仓库
只记录其与正式发布之间不可混用的版本和信任规则。

插件主界面、设置页、设置 RPC、敏感配置和生效时机的开发规范见
[插件设置规范](plugin-settings.md)。修改设置页面或其前端能力声明同样会改变
发布包内容，必须遵守本文件的版本和不可变发布规则。

## 官方外部源码 Factory

当插件的开发源码位于独立 Git 仓库时，`xsec-plugins` 充当**官方签名的
Factory/收录库**，而不是第二个开发仓库。外部仓库仍是代码唯一开发权威；
Factory 只保存经过审批的发布快照、不可变 artifact、release history 和可审计的
来源证据。因此不要在 `xsec-plugins/plugins/<id>/` 直接开发或把它当作应同步回
外部仓库的源码目录。

先在 `.xsec-factory/official-registry.json` 提交经审查的 allowlist 条目。条目固定：

- 插件 ID、GitHub `owner/repository` 和可选的仓库内插件路径；
- `beta` 只能是 `refs/heads/beta`，`stable` 只能是 `refs/heads/main`；
- `AVAILABLE` + `ON_INSTALL`。外部条目不能变成 `INSTALLED_BY_DEFAULT`；
- `active` 或 `disabled` 状态。`disabled` 仅从市场索引隐藏已发布插件，仍必须
  留存生成快照、release history、KMS release sidecar 和来源证据，且拒绝新的发布；
  从未发布的授权可直接从 allowlist 移除。

外部 Factory 包也不是 Desktop 内置包的替身：不得占用已编译的 Desktop package
ID，或官方保留的 workspace contribution、Agent/MCP tool（包括 host 的 `xsec_`
和 `browser_` 名称空间）。这项检查发生在打包前，独立于插件是否默认安装。
又因为 Desktop 会对 `OfficialMarketplace` 自动签发其已声明 capability 的运行时
grant，外部包只允许保守的 browser-sandbox 能力集合：只读 workspace/session、
plugin 自己的数据和 secret、workspace 跳转、网络请求、通知、非保留 Agent tool
注册。`process.spawn`、`terminal.shell`、`native.execute`、workspace 写入、browser/
clipboard 控制、MCP server 注册等高权限不会因 registry 或源码提交而自动获得；需要
先完成独立的 Desktop 信任模型/API 变更和安全审查。

Desktop 开发者工具在发布时固定向官方 Factory 的受保护 `main` 分支调度
`publish.yml`，而不是把 token 或 KMS 密钥交给外部仓库。请求字段严格为：

```text
channel: beta | stable
plugin_id: 已注册的外部插件 ID
source_sha: 已推送的、40 位小写外部 commit SHA
release_id: 仅 stable；已存在的 Beta releaseId
```

外部插件 ID 不得使用 `com.xsec` 或 `com.xsec.*`：该完整命名空间属于 Desktop 的
内置/内部开发插件，开发者工具也会将其按内部功能处理。外部开发者应使用自己的反向
域名空间，例如 `com.acme.discovery`。

外部源码的待打包文件路径也必须满足 Desktop 的跨平台 archive 规则：仅 ASCII，不能有
大小写或文件/目录别名，也不能使用 Windows 的尾随点/空格、NTFS stream、禁止字符或
设备名。Factory 在复制快照和写 ZIP 前限制文件数、单文件大小及总大小，因此不会签发
Desktop 无法安装的 artifact，也不会因未受限源码树耗尽受保护发布 runner。

发布触发以这个显式请求为准；单纯向外部仓库 push 不会自动取得官方发布凭据。这样
开发者可先在 Desktop 开发者模式中反复调试，再选择确切提交发版，而不必向 Desktop
暴露外部仓库写权限或 KMS 私钥。

Beta 请求先读取 Factory `main` 中的 allowlist，再使用仅有 `Contents: Read` 和
`Metadata: Read` 权限的 GitHub App 临时 token 检出**精确 SHA**。工作流必须证明该
SHA 仍可从注册的 `beta` 分支到达，清除 checkout 凭据，并且只静态读取/复制/确定性
打包：不会执行插件代码、Git hook、`npm`/`pnpm` 脚本或外部 build script。Factory
随后将快照放入 `plugins/<id>/`，由原有不可变发布器构建并记录 Beta 来源证据。

外部源码可达性校验的 Git transport 也有独立信任边界：checkout 固定为
`https://github.com`，先拒绝非规范/明文 HTTP `origin`、`insteadOf` URL 重写、remote
helper、proxy 与 include 覆盖；再只由 allowlist 的 `owner/repository` 组装 HTTPS
fetch URL，忽略 system/global Git config、禁止重定向和非 HTTPS 协议，并写入本地
verified ref。工作流绝不会用外部 checkout 的 `origin` URL 或 remote alias 访问网络；
这只防止临时只读 token 被 Git transport 重定向，绝不表示外部插件代码可被执行或信任。

Stable 请求同样只接受可从外部 `main` 到达的精确 SHA。它重新确定性打包并要求得到
的 `releaseId` 与指定的已有 Beta `releaseId` 完全一致；通过后只移动
`channels.stable.releaseId`，并追加对应 main 证据。它不重传、不替换 artifact。若
Stable 指针已经选择该 release，则仅验证既有证据，不请求 KMS、不创建 PR，也不触发
Desktop smoke。

外部读取 App 的 production secrets 是
`XSEC_MARKETPLACE_SOURCE_APP_ID` 和
`XSEC_MARKETPLACE_SOURCE_APP_PRIVATE_KEY`；它与 Factory 的发布 token 分离。Cloud
broker 目前只允许受保护的 `xsec-plugins/.github/workflows/publish.yml@main` 请求
KMS，因此签名 envelope 的 `source_revision` 始终是 Factory 在发布队列中取得槽位后
检出的受保护 `main` SHA，绝不是外部 SHA。外部 SHA 位于
`.xsec-factory/official-publications/<id>.json` 的证据中。Desktop 的 smoke dispatch
同样只携带 Factory revision，继续使用既有的官方签名和信任链。

## 云端不可变发布规则

每个插件的 `.xsec-market/releases.json` 使用 schema v2。`releases` 是只能
追加的历史记录；`channels.beta.releaseId` 是必需的 Beta 指针，
`channels.stable` 要么是带 `releaseId` 的指针，要么为 `null`。一个 release record 包含：

- `plugin.json.version`；
- Desktop engine 范围；
- 每个 OS/架构 artifact 的 SHA-256，以及其交付 URL。

目前 engine 对象固定为 `{"xsec": "...", "pluginApi": "..."}`：两个值都必须是
非空字符串，不能增加私有键。这个限制不是为了压缩 manifest，而是为了让发布器与
Desktop 使用同一份可重算的 `releaseId` 契约；需要增加 engine 语义时，应先发布双方
都支持的新 schema，而不是在现有记录中附加字段。

发布器会以规范 JSON 重新计算 `releaseId`。计算输入是版本、engine 范围和按
`os`、`arch`、`sha256` 排序后的 artifact 描述符；URL 不参与 ID 计算，以便
同一已验证 artifact 在交付 URL 变化时仍保持同一身份。结果必须是
`sha256-<64 个小写十六进制字符>`。校验器会拒绝任何不能由当前 release record
重新计算得到的 `releaseId`；不要手工保留、修改或伪造它。

同一个插件的一个 `plugin.json.version`（SemVer）只能对应一个不可变 release
record 和一组 artifact。也就是说，已经存在 `1.2.0` 的云端记录时，不能再以
`1.2.0` 发布任何不同内容，即使变化只在某一平台 artifact、engine 范围或
artifact SHA-256。必须先提高 `plugin.json.version`，再发布新内容。已发布的
artifact、历史 release record 和 `stable` 指针都不可由常规 Beta 构建修改。

这项限制使更新、审计和回滚具有单一含义：版本路径不会解析到两个不同包，
而每个 `releaseId` 与下载后校验的 artifact SHA-256 都可追溯。

## 开发者发布清单

1. 在本地开发者模式完成调试。可反复使用相同的 `plugin.json.version` 和新的
   `dev_revision`；不要把本地快照或调试产物提交为 Marketplace release。
2. 准备发布时，检查上一次云端 release 的 `plugin.json.version`。若要发布的
   内容、engine 范围或任一 artifact 会变化，先将 `plugin.json.version` 提高到
   新 SemVer。
3. 在临时输出目录执行构建和校验，确认将要写入的 releaseId 与 artifact
   SHA-256 是由当前源代码确定性生成的。打包器会将指定的 UTF-8 源码文本扩展名
   （如 `.json`、`.js`、`.md`）中的 CRLF 规范成 LF（例如 Windows 工作区），其他
   任意二进制成员保持原字节；因此本地校验的
   artifact SHA-256 与云端 Linux 发布器一致：

   ```powershell
   $temporary = Join-Path $env:TEMP xsec-marketplace-build
   New-Item -ItemType Directory -Path $temporary
   python scripts\build_market.py --clean --output-root $temporary
   python scripts\validate_market.py source --source-root . --built-root $temporary
   ```

4. 将源代码和版本号合入受保护的 `main`。受保护的
   `Publish immutable marketplace beta release` 工作流会重新构建、规范重算
   `releaseId`、只追加新 release（如有）并只移动 `beta` 指针。它签名后才会
   向 Desktop 发送 Beta smoke 请求。若工作流曾在发布队列等待，它在取得队列槽位后
   会重新检出当时的受保护 `main`，而不是使用排队时捕获的旧 commit；因此后续构建和
    发送给 Desktop 的 `source_sha` 始终对应实际参与发布的源代码。
5. Beta 验证通过后，由人工在受保护 `main` 上运行
   `Promote immutable marketplace release to stable`，并传入已经存在的
   `plugin_id` 和 `release_id`。该操作只移动 `stable` 指针，不重新打包、不
   改 artifact SHA-256，也不修改 release record。它与 Beta 发布共用同一队列，并在
   获得槽位后重新检出当前 `main`；因此可推广刚刚由前一轮 Beta 发布写入的 release，
   不会因为人工操作排队而使用过期 release index。

新插件的首次自动发布仅进入 Beta：`channels.stable` 为 `null`（不得写成
`{"releaseId": null}`）。只有
独立的人工推广才能使它成为 Stable。

对于上述外部源码插件，第 4、5 步分别替换为外部 Factory 的显式 `publish.yml`
Beta/Stable 请求。不要使用旧的 `Promote immutable marketplace release to stable`
直接推广已注册的外部插件；该旧工作流只保留给内置源码，且会拒绝外部 registry ID，
以免绕过外部 `main` 的可达性和内容一致性证明。

## 回滚和 Agent 操作边界

Stable 回滚不是重新构建旧版本，也不是复制或编辑旧 artifact。人工推广工作流
将 `channels.stable` 指回同一插件已有的历史 `releaseId`，并复用该
记录绑定的 artifact SHA-256。Beta 指针和所有 release records 保持不变。

Agent 必须执行以下规则：

- 在本地调试任务中，只操作开发目录和 `dev_revision`；不得声称本地保存已经
  发布，或将其作为 Desktop 的云端更新来源。
- 在云端发布任务中，先比较目标内容与已有 release 的版本。内容不同而版本未
  提高时，停止发布并要求提高 `plugin.json.version`；不得通过手工编辑
  `releaseId`、重用文件名或覆盖 artifact 绕过限制。
- 不得编辑既有 release record 或历史 artifact；不得让普通 Beta 发布移动
  `stable` 指针。
- 推广或回滚时，只选择同一插件现有的 `releaseId`；不要要求重新生成包。
- 不得把排队工作流的事件 commit 当作最终发布证明，也不得因该 commit 未单独出现
  在 Beta 中而手工重跑或编辑索引。“发布队列”取得槽位后的实际 checkout 才是
  `source_sha`；验收时读取工作流输出的 `source_sha`、`marketplace_revision` 和
  `channel`。同一个实际发布可合并排队期间进入受保护 `main` 的多个变更。

远程 Desktop smoke 的通道载荷和验收要求见
[Desktop remote marketplace smoke-test contract](desktop-remote-marketplace-smoke-contract.md)。
