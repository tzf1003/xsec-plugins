# Desktop 按需 Marketplace 验收

日常插件开发、更新和发布默认不触发或等待跨平台 Desktop Host Smoke。插件持续兼容
Windows、macOS、Linux；完整目标包括 Windows x64、Linux x64、macOS arm64 与
macOS x86_64，共三平台、四个 OS/架构组合。

需要验证 sandbox frontend 包安装生命周期时，在 Desktop `main` 手动运行
`marketplace-plugin-smoke.yml`，提供已发布的 `marketplace_revision` 和 `plugin_id`。
完整输入、覆盖范围与报告要求以
[Desktop Smoke 契约](https://github.com/tzf1003/xSecDesktop/blob/main/docs/plugins/official-marketplace-smoke.md)
为准。它校验下载、digest、安装、frontend 入口及启停持久化，不启动 WebView，也不覆盖 native MCP。

Factory 交付以不可变 release、artifact digest、来源证明和已合并 revision 为依据。
Smoke run 和具体 OS/架构结果单独记录；源码 CI 或未启动的 runner 不能记为 Host 验收成功。

旧 `repository_dispatch`、`official-marketplace-smoke.yml` 和 Cloud smoke callback
属于保留的历史渠道协议。接收端存在不代表新发布需要回调晋级；当前验收以实际执行报告为准。
