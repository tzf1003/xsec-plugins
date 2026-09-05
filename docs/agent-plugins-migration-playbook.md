# Agent Plugins v1 迁移工作手册

本手册用于将一个现有第一方插件接入 XSec 的 Agent Plugins v1 运行时。开始实现前，
先保留工作树中的现有改动，并阅读运行时合约与该插件当前的 manifest、frontend、Host RPC、
agentTools、存储和真实测试。

## 先交付能力分类矩阵

每个现有能力必须有一行：

| 能力/当前入口 | 目标所有者 | 数据所有者 | 所需可信上下文 | 权限/UI | 真实验收 |
| --- | --- | --- | --- | --- | --- |
| 例：领域查询 | 插件 MCP | `PLUGIN_DATA` | 无或任务 scope | 可选 workspace binding | real `tools/list/call` |

分类规则：

- 只依赖 `PLUGIN_ROOT`、`PLUGIN_DATA`、领域输入或声明远程服务的逻辑属于插件 MCP。
- 操作方法、工作流和多 MCP 编排属于 Skill。
- assignment/project/session 身份、浏览器、代理、证据、报告、终端、审计和 Secret Vault
  属于 XSec Host API。
- 导航、侧边栏、设置、权限和 renderer mapping 属于 `com.xsec.desktop`。

不能用“现有代码在哪个仓库”替代这份分类。特别是受保护 Host 操作不能因为插件迁移而
变成 portable MCP Tool。

## 实施顺序

1. 添加 root `plugin.json`、`skills/<name>/SKILL.md` 和 `mcp.json`；可选 Desktop
   extension 使用 schema v2。
2. 将领域实现放入真实 stdio 或 HTTPS MCP，并让其使用插件实例的 `PLUGIN_DATA`。
3. 以真实 `tools/list` 作为 schema 与描述来源；在 schema v2 中添加 MCP allowlist、
   permission、可选 `parent`/`sub` 角色和 frontend binding，不复制 Tool schema。
4. 按需要定义旧 Tool、旧存储和历史会话的有期限 projection。
5. 增加真实边界验收：SQLite、子进程、loopback MCP、OMP ACP 和 Tauri。
6. 更新源码 README、Factory 发布输入和平台 artifact 验收；再进入 Beta。

## 必须验证的行为

- 安装：纯 portable 包、有效/缺失/无效 XSec extension、无效 Skill、无效 MCP 文档和
  单 server 失败。
- 运行：`initialize`、`tools/list`、`tools/call`、Tool allowlist、任务隔离、更新产生的
  capability revision、unknown/incomplete 统计（含必需会话未连接/失败/契约冲突时门禁失败）、
  每个受支持 OMP 版本的最终合并 Tool 集合 wire-name 冲突和审批；Skill 重名还要覆盖全部
  实际启用来源。受限 probe 验收必须证明：专用非特权身份、只读 artifact 挂载、白名单可丢弃 `PLUGIN_DATA`、无继承环境/FD/IPC、默认拒绝网络/进程能力（仅契约窄例外），且失败探测不能触及活动 artifact/数据/指针。
- 生命周期：持久化 artifact/`PLUGIN_DATA` 引用、A→B→C 会话冻结、历史恢复重新鉴权（含撤销
  成员资格/策略变更/quarantine 后拒绝或降权）、普通更新、组件停用、quarantine、lease
  回收和 `PLUGIN_DATA` 跨升级。
- 数据：Host/Sidecar 操作幂等、在途写入栅栏、真实数据库候选迁移、双库无冲突合并、冲突
  停止切换、revision 核对、失败和重启恢复。
- 交付：对应平台的不可变 archive、签名、Factory Beta smoke 和 Stable 指针提升。

交付报告必须列出最终矩阵、portable/embedded 数据流、manifest/MCP/Skill/Host binding、
迁移与兼容窗口、已执行的真实测试，以及尚未满足的外部平台门禁。
