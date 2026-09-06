# 抓包流量插件恢复方案

## 目标与边界

本方案把插件化前的抓包流量页面作为产品规格，在
`com.xsec.workspace.traffic` 的沙箱前端中恢复其信息架构、交互和功能。
旧 React 工作台不重新注册、不参与运行，也不是插件的构建依赖。

职责边界如下：

| 所有者 | 职责 |
| --- | --- |
| 抓包流量插件 | 流量列表、筛选、请求/响应查看、独立详情、重放编辑器、设置页和全部页面状态 |
| XSEC Desktop | capability 校验、当前会话绑定、流量/重放存储 RPC、持久化事件和工作区工具导航 |
| 既有后端 | mitmproxy 抓取、SQLite 入库、重放执行、MITM CA 与被动规则 |
| 旧 React 工作台 | 仅作对照规格，不进入运行链路 |

## 旧版规格研究

恢复以旧版 `traffic-workbench` 组件、格式器和样式为基准，逐项核对：

- 工具栏：组合搜索、完整筛选、会话 ID、当前页计数、游标分页和刷新。
- 流量表：方法、主机、URL、参数、状态、响应类型、扩展名、来源、范围、耗时、
  大小和时间；窄侧栏采用旧版七列紧凑表。
- 报文区：请求/响应同屏，支持 Raw、Headers、Body、Pretty，列表高度可拖动。
- 独立详情：从选中流量打开实体级工具，不复制或绕过宿主数据边界。
- 重放器：原始请求可编辑、目标连接可设置、历史可切换；跨 Host 携带
  `Cookie` 或 `Authorization` 时要求显式二次确认。
- 设置：默认过滤、MITM CA 状态/导入/轮换、被动检测规则维护。
- 状态：加载、空数据和真实错误均在对应功能边界直接显示。

## 插件实现

插件前端使用 Preact + TypeScript，由 esbuild 生成清单声明的单文件 ESM。插件通过
Host RPC 读取当前会话数据，监听 `xsec.traffic.persisted` 后刷新当前页或提示有新流量。

恢复后的 Host RPC 包括：

- `xsec.traffic.list`、`xsec.traffic.get`
- `xsec.traffic.replay-attempts`、`xsec.traffic.replay`
- `xsec.traffic.reference.add`、`xsec.workspace.tool.open`
- `xsec.traffic.settings.get`、`xsec.traffic.settings.set`
- `xsec.traffic.ca.status`、`xsec.traffic.ca.import`、`xsec.traffic.ca.rotate`
- `xsec.traffic.passive-rules.list` 及规则增删改状态方法

重放原始请求沿用 2 MiB 后端上限。宿主只为官方抓包插件的重放方法开放精确的大报文
信封额度，并继续执行 capability、会话、协议、端口、字段和消息大小校验。

## 设置行为

“设置 → 插件 → 抓包流量”包含三部分：

- 默认过滤只影响之后新打开的工作台，不暗中覆盖正在编辑的筛选。
- MITM CA 操作直接返回真实状态或错误，不自动重试、不伪造成功。
- 被动规则保存后立即生效；规则 ID、严重级别、表达式和启用状态都可见。

## 视觉还原台账

| 核对项 | 恢复结果 |
| --- | --- |
| 文案 | 表格使用“文本 / JSON”“代理 / 重放”、`.js`、`KiB` 和 `HH:mm:ss`；详情保留“代理捕获 / 重放结果” |
| 布局 | 工具栏、流量列表、拖动分隔条、详情工具栏、双栏报文按旧版顺序恢复 |
| 表格密度 | 表头与数据行均为 32 px，桌面列宽和窄侧栏七列结构按旧版对齐 |
| 颜色 | 所有组件只消费宿主 light/dark 语义主题令牌，选中、状态和边框语义一致 |
| 报文容器 | `REQUEST / RESPONSE` 标题、模式切换、等宽正文和双栏分隔按旧版恢复 |
| 响应式 | 880 px 使用紧凑表；560 px 页面无横向溢出，表格在自己的滚动容器内横向滚动，报文改为上下排列 |
| 图标 | 搜索、筛选、刷新、分页、详情、重放和引用使用统一 SVG 图标，不使用临时字符图标 |

## 验证与证据边界

- `pnpm verify` 覆盖 TypeScript、生产构建、清单/激活契约、格式器、筛选和报文辅助逻辑。
- 浏览器预览用于 1440、880、560 px 及 light/dark 的视觉和交互回归；它不是 Tauri
  iframe IPC 端到端证据。
- Desktop Vitest 和 Plugin SDK 测试覆盖宿主 RPC、消息大小、会话隔离和清单契约。
- Rust 测试覆盖解析、Host 校验、SQLite 游标/重放历史；显式启用的真实链路测试覆盖
  `Chrome → mitmdump → HTTP → SQLite / passive finding`。
- 实际 Tauri iframe 冒烟使用 Plugin API 1.4 Desktop Host；`workspace.composer.write` 能力要求
  前端声明最低为 `^1.4.0`。Stable 晋升还必须通过 Factory 调度的四平台 Desktop Beta 制品安装、激活与持久化
  冒烟；该制品门禁不替代 iframe 页面交互证据。
