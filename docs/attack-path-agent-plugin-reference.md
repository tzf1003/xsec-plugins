# Attack-path Agent Plugins v1 参考迁移

`com.xsec.attack-path` 是第一份 Agent Plugins v1 参考包。它将攻击路径树和发现
数据迁入 portable Rust MCP，同时保留 XSec workspace UI 作为可选 extension。

## 包和运行时数据

```text
com.xsec.attack-path/
├── plugin.json
├── skills/attack-path/SKILL.md
├── mcp.json
├── bin/attack-path-mcp                 # release artifact only
└── com.xsec.desktop/frontend/index.js

Desktop-managed PLUGIN_DATA/
└── store.sqlite
```

artifact root 一经安装即不可变。`PLUGIN_DATA` 由 Desktop 按安装实例拥有并跨升级保留；
它不是源码或签名 artifact 的一部分。release source tree 不得提交本机编译出的 sidecar。

## 能力分类

| 能力 | 目标所有者 | 数据与上下文 |
| --- | --- | --- |
| 节点 CRUD、查询、revision | attack-path stdio MCP | `PLUGIN_DATA/store.sqlite`、任务 scope |
| 共享 finding 写入与查询 | attack-path stdio MCP | `PLUGIN_DATA/store.sqlite`、任务 scope |
| 操作顺序、去重、Host Tool 编排 | attack-path Skill | OMP session 和 Fabric 可见 Tool |
| 侧边栏、导航、Host RPC 映射 | `com.xsec.desktop` | renderer context |
| browser/proxy/evidence/report/terminal/audit | XSec Host API | 受保护的 host context |

portable Tool 名为 `attack_path_*`。其 schema、描述和执行契约必须由 sidecar 的
`tools/list` 提供；schema v2 `agentTools` 只提供 allowlist 和授权绑定。

## 嵌入式数据流

```text
OMP
  -> com.xsec.attack-path:attack-path virtual endpoint
  -> XSec MCP Fabric
  -> attack-path sidecar
  -> PLUGIN_DATA/store.sqlite
  -> resources/updated
  -> Host sidebar rereads attack_path_list
```

Fabric 只接受 Bearer task capability，并在调用边界重建 opaque context handle。模型传入
的参数只能是业务字段；assignment、project、session、role、authorization 和 context
字段不属于 Tool 输入。

每次领域写入必须在一个 SQLite 事务中提交、递增 scope revision，并在成功提交后发出
`resources/updated`。侧边栏收到事件后按 revision 重新读取，不以 renderer 的乐观状态
作为权威结果。

## 数据迁移与兼容

旧 store 切换到 sidecar 时按下列顺序执行：

1. 禁止旧 handler 新写入并 checkpoint WAL。
2. 建立只读备份和候选 `store.sqlite`。
3. 用真实 sidecar 运行迁移、读取和计数校验。
4. 在写 fence 内原子切换数据库和 capability revision，再发布新 Tool Registry。
5. 任意步骤失败时保留旧 handler 和旧数据库；候选数据仅在未发布时可丢弃。

历史会话经 compatibility projection 继续使用 `xsec_tree_*`；新会话只看到
`attack_path_*`。兼容投影至少覆盖两个稳定版本和所有仍可恢复的 session snapshot。这个
窗口必须有明确版本界限和可执行验收，不能依赖未说明的 legacy alias。

## Factory Beta 检查表

- Windows x64、Linux x64、macOS arm64/x64 各自打包并运行 sidecar；release record 不能使用 `any/any`。
- archive 必须包含 `plugin.json`、`mcp.json`、Skill、frontend 与平台 sidecar。
- 独立 OMP 18.0.9 和嵌入式 OMP ACP 都发现相同的逻辑 server 名及 raw Tool。
- 两个真实 assignment 复用 Broker 时保持数据隔离；伪造参数与 `_meta` 不得越权。
- 真实 Tauri 边界验证 Agent 写入后的事件、侧边栏重新读取、升级/回滚/重启和
  `PLUGIN_DATA` 保留。

通过 Beta 后，Stable 只提升同一 immutable release；它不重新编译 sidecar，也不替换
已有 artifact 字节。
