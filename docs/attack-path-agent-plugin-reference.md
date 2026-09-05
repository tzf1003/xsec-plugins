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

节点绑定、完成、释放和 scope 清理由隐藏的 `xsec/attack-path/control` 处理。该请求不进入
Agent Tool 清单，只接受 Host 签发的短时受限 context handle。handle 必须签名绑定
Sidecar/control audience、单一 action、assignment、lease generation、session、operation ID、
预期 revision、到期时间和 nonce；写操作 nonce 只能成功消费一次。Sidecar 在每次调用时
校验签名、audience、action、scope、到期、nonce 和当前撤销/quarantine 状态。Host 先持久化
操作 ID、同一 scope 上的预期 revision，以及非敏感业务字段与状态；明确排除 Bearer
token、`context handle` 和 Secret。Sidecar 必须把操作 ID 绑定到同一 scope，并在单个原子事务中用
operation ID 和 canonical request digest 先查询已存结果：同 digest 直接返回已提交 outcome，不再做
revision 校验；同 ID 不同 digest 显式拒绝。只有新操作才使用 compare-and-set 校验当前
revision 与预期 revision，并在同一事务内提交领域写入、revision 递增和 outcome。revision
过期时显式失败。Host 确认结果后再提交调度状态。重启后 `pending` 操作保持可见、阻断报告终结并
由用户显式恢复；已失败且事务未提交的操作保留诊断，不计为在途写入。恢复时重新建立并验证
授权，且列出和恢复都必须匹配调用方当前 assignment，不能复用持久化 context handle 或只凭
operation ID 跨任务重放。

旧 handler、Fabric 和 Host 写入共用一个持久、线性化的准入门。每个写入在任何预检或
领域修改前原子获取并注册 permit，事务提交或回滚后才释放；安装栅栏与关闭准入在同一
顺序点完成，然后等待全部已注册 permit 排空。报告终结与清理按 assignment 建立栅栏，
等待在途事务完成，再核对 Sidecar revision、
节点、子 Agent 和 Host 操作。清理接管报告栅栏时必须携带精确 fence revision，并将其原子
转换为持久的 cleanup fence；不匹配或未知栅栏拒绝清理。栅栏后的迟到写入显式失败。

## 数据迁移与兼容

旧 store 切换到 sidecar 时按下列顺序执行：

1. 在共用准入门上原子安装迁移栅栏并关闭新 permit，等待旧 handler、Fabric 和 Host
   的全部已注册 permit 提交或回滚，确认没有活动写入者；随后再 checkpoint WAL。
2. 分别备份旧库与已有 2.0.1 `PLUGIN_DATA`，再建立候选 `store.sqlite`。
3. 按 scope 与记录 ID 合并不冲突数据；任何冲突停止切换并输出明细。
4. 用真实 sidecar 核对数据、关联、数量和 revision。
5. 先写入 `prepared` generation，它包含 artifact SHA、数据库位置、capability revision、Tool
   Registry 摘要和 live projection 摘要，候选仍不可见。全部核对通过后在写入栅栏内原子将该
   generation 标记为 `committed`；这条 generation 记录是数据库、artifact、Tool Registry 和会话投影
   的唯一权威选择源，消费者不维护独立可写指针。
6. 进程重启时先按 generation 记录幂等对齐所有消费者：`prepared` 一律回滚并继续使用
   上一个 `committed` generation；`committed` 一律完成切换，不回退到旧指针。栅栏保持到提交持久
   且本地消费者对齐；不兼容升级等待旧 backend lease 释放。

历史会话经 compatibility projection 继续使用 `xsec_tree_*`；新会话只看到
`attack_path_*`。兼容投影只有在至少两个稳定版本已经发布，并且全部引用旧契约的历史
snapshot 已结束保留后才能退出。

## Factory Beta 检查表

- Windows x64、Linux x64、macOS arm64/x64 各自打包并运行 sidecar；release record 不能使用 `any/any`。
- archive 必须包含 `plugin.json`、`mcp.json`、Skill、frontend 与平台 sidecar。
- 独立 OMP 18.0.9 和嵌入式 OMP ACP 都发现相同的逻辑 server 名及 raw Tool。
- 两个真实 assignment 复用 Broker 时保持数据隔离；伪造参数与 `_meta` 不得越权。
- 真实 Tauri 边界验证 Agent 写入后的事件、侧边栏重新读取、升级/回滚/重启和
  `PLUGIN_DATA` 保留。

通过 Beta 后，Stable 只提升同一 immutable release；它不重新编译 sidecar，也不替换
已有 artifact 字节。
