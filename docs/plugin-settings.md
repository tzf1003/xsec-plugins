# XSEC 插件设置规范

本规范是 XSEC Desktop Marketplace 插件的设置界面和设置 RPC 的权威约定。它
适用于官方插件和第三方插件；插件包中的 `plugin.json` 是可安装能力的唯一
声明来源。

## 设置页与主界面的边界

- 插件 **MUST** 把账户级、持久化且与当前任务无关的配置放到
  `设置 → 插件 → <插件名>`。这包括默认值、路径、端点、凭据配置状态、轮询/
  性能、诊断和保留策略。
- 插件 **MUST NOT** 在主界面和设置页重复编辑同一项配置。
- 主界面 **SHOULD** 只保留当前任务的主要操作、当前任务筛选、即时状态、结果、
  校验和故障恢复。搜索词、选中项、缩放和标签页等任务临时状态不应写为账户设置。
- 项目、会话、实体和重放请求的参数仍属于当前工作，不迁入插件设置。
- 缺少运行所需配置时，主界面 **SHOULD** 显示简洁的阻塞状态，并调用
  `xsec.plugin.settings.open` 打开调用方自己的设置页；正常状态不应把设置入口
  常驻在任务工具栏中。

系统设置仍拥有跨插件或宿主的内容，例如出口代理、Agent 工作区、会话目录、
全局提示词和账户接入。不要把它们复制到某个插件设置页。

## 清单、隔离上下文与接口

在 `extensions.com.xsec.desktop.contributes.settingsPages` 中以稳定 ID 声明页面，并为每个页面声明
`onSettingsPage:<settings-page-id>` 激活事件：

```json
{
  "activationEvents": ["onSettingsPage:example"],
  "settingsPages": {
    "example": {
      "title": "示例插件",
      "group": "plugins",
      "page": "example",
      "icon": "settings",
      "order": 100
    }
  }
}
```

Desktop 仅在这个事件已声明时挂载对应页面的隔离前端，因此页面的 `export activate(host)` 会在首次打开时运行。
设置页激活不授予项目、会话、工作目录或实体上下文，前端仍仅接收下述隔离 context。

宿主会将 Marketplace 插件统一放在“插件”组；`group` 是兼容字段，不能用来把
第三方设置插入宿主的其他分组。启用的插件才显示其设置页；禁用或卸载后入口会
消失。一个插件有多个页面时，每一页都必须有独立、永不复用的贡献 ID。

设置页沿用插件声明的隔离前端模块，`host.context` 为：

```json
{
  "kind": "settings-page",
  "settings": { "id": "example", "page": "example" }
}
```

设置页默认没有项目、会话、工作目录或实体上下文。使用设置页时，前端应当检测
`host.context.kind === "settings-page"` 并呈现字段化设置 UI。

普通、非敏感配置可通过宿主提供的插件命名空间接口读写：

```ts
xsec.plugin.config.get({ key })
xsec.plugin.config.set({ key, value })
xsec.plugin.config.delete({ key })
xsec.plugin.settings.open({ pageId? })
```

调用 `xsec.plugin.settings.open` 时也必须在 `frontendApi.methods` 中显式声明它；它是一个插件绑定的读权限操作：

```json
{
  "xsec.plugin.config.get": { "capability": "pluginData.read", "binding": "plugin" },
  "xsec.plugin.config.set": { "capability": "pluginData.write", "binding": "plugin" },
  "xsec.plugin.config.delete": { "capability": "pluginData.write", "binding": "plugin" },
  "xsec.plugin.settings.open": { "capability": "pluginData.read", "binding": "plugin" }
}
```

`get`、`set` 和 `delete` 只处理 JSON 值。key 最长 128 字节；单项序列化值上限
64 KiB，单插件总量上限 1 MiB。每个调用均由宿主绑定调用方的活动插件制品和账户，
插件不得传入、推测或访问其他插件 ID。实现专用设置 API 时，`frontendApi.methods`
中的读取方法必须声明 `pluginData.read` 和 `binding: "plugin"`，写入方法必须
声明 `pluginData.write` 和 `binding: "plugin"`；不得为设置页使用 `session` 或
`context` 绑定。

设备发现、系统证书或其他非 KV 领域设置可以声明插件专用 RPC，例如
`xsec.terminal.settings.get/set`。专用 RPC 同样必须由宿主按插件 ID、制品和能力
白名单校验，不能成为调用任意原生命令的通道。

需要保存凭据的受支持插件应声明独立的 `credentials.set({ kind, value })` 与
`credentials.clear({ kind })` 写入 RPC；两者使用 `pluginData.write` 和 `binding: "plugin"`。
设置页用密码输入框提交后必须立即清空输入，`settings.get` 只能返回已配置布尔值，不能返回密钥内容。秘密由 Host
写入系统密钥库，不得进入 `xsec.plugin.config.*`、插件日志、错误提示或设置页初始值。

## 数据、安全与生效时机

配置按“当前账户 + 插件 ID”隔离，且只保存在本机；禁用和升级保留数据，卸载删除
普通插件配置。密钥、令牌、密码和证书私钥 **MUST NOT** 通过通用配置 API 以明文
保存或回传。插件设置页至多展示“已配置”状态；实际写入/清除敏感凭据必须走宿主
安全凭据能力或经过审查的专用后端。

每个设置页 **MUST** 标明生效时间：立即生效、仅后续新实例生效或需要重启。例如，
系统终端配置只影响新的 PTY；Chrome 路径只影响重新启动后的浏览器会话；流量默认
过滤只在新打开的流量工作台初始化；审批权限和被动规则保存后立即生效。

提交前至少验证：清单有 `settingsPages`、所有设置 RPC 使用 `binding: "plugin"`、
前端不会从设置上下文读取项目/会话、敏感值不回显、首次 `settings.get` 成功前禁用
所有可能依据 DOM 默认值产生持久化写入的操作（包括凭据写入/清除）、缺少必需配置
可恢复、禁用/卸载后的入口与数据生命周期正确，以及主界面没有重复设置控件。

## 官方插件审查基线

| 官方插件 | 账户级插件设置 | 主界面保留 |
| --- | --- | --- |
| 资产发现 | 数据源、API Host、Skill 路径和凭据状态 | 收集运行、资产、搜索和未配置恢复 |
| 项目工作区 | 默认项目根目录 | 当前项目的数据和操作 |
| 系统终端 | 默认终端配置 | PTY 内容和真实错误恢复 |
| 审批记录 | 默认策略、模型、阈值和超时 | 当前会话审批记录和筛选 |
| 浏览器会话 | Chrome 路径 | 会话、标签页和导航 |
| 抓包流量 | 默认过滤、MITM CA、被动规则 | 当前会话流量、详情和重放记录 |
| 攻击路径 | 无账户级持久配置；不创建空设置页 | 图、缩放和平移 |
| 对话树 | 无账户级持久配置；不创建空设置页 | 路径、节点筛选和视图控制 |
| 项目文件 | 无账户级持久配置；不创建空设置页 | 文件浏览和选择 |
| 项目成果 | 无账户级持久配置；不创建空设置页 | 成果筛选、详情和引用 |
| 子 Agent | 无账户级持久配置；不创建空设置页 | 运行状态、时间线和诊断 |

这张表是每次官方插件 UI 审查的基线；没有账户级设置不是创建空页面的理由。
