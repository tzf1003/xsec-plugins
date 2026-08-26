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
