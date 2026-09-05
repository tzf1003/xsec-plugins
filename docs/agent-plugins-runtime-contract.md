# XSec × OMP × Agent Plugins v1 Factory 合约

本文件定义第一方插件从源码仓库进入 Factory、Desktop 和独立 OMP 的共同交付
边界。它补充而不替代 Desktop 运行时实现；Factory 负责可验证、不可变的 artifact，
Desktop 负责安装、信任、权限、更新和嵌入式 MCP mediation。

## 一份 artifact，两种运行方式

每个迁移到 Agent Plugins v1 的包以根目录的 portable core 为准：

```text
plugin root
├── plugin.json
├── skills/<skill-name>/SKILL.md
├── mcp.json
├── bin/<platform MCP sidecar>        # 仅 release artifact
└── com.xsec.desktop/                 # 可选 XSec extension
    └── frontend/
```

`plugin.json`、`skills/` 与 `mcp.json` 是唯一 portable 输入。独立 OMP 18.0.9 以
`--plugin-dir <artifact-root>` 读取这些文件并拥有自己的 `PLUGIN_DATA`。缺少
`com.xsec.desktop` 的包仍可作为 Skills/MCP 使用；该扩展无效时，Factory 不得把
portable core 伪装为无效，Desktop 只停用 UI 和 Host binding。

在嵌入式场景，Desktop 为每个逻辑 server 建立独立 Fabric endpoint：

```text
<plugin-id>:<mcp.json server key>
```

OMP 读取冻结的 Skill 投影，MCP 连接始终经过 Fabric。Factory 不得把 assignment、
project、session、role、token 或 secret 写进 manifest、Skill、`mcp.json` 或 archive。

Desktop 会话快照持久保存 artifact SHA、`PLUGIN_DATA` 映射、Skill roots、Tool 契约、
allowlist、角色和 capability revision。活动 lease、保留历史与回滚指针共同保护这些
artifact；恢复时先核对快照归属和精确 artifact，再对照当前 project/session 成员资格、Host
策略、插件 quarantine/disablement 与已撤销授权做重新鉴权。只有当前策略仍允许时才签发新
凭据；否则拒绝恢复或以最小权限拒绝过期投影。Bearer token 与 context handle 不进入快照。

## schemaVersion 2

`extensions.com.xsec.desktop` 是可选扩展。新 MCP 迁移使用
`schemaVersion: 2`，其中：

- `agentTools` 仅绑定 `mcpServer`、`mcpTool`、权限和可选 UI 归属；Tool schema、简介
  与执行契约来自 server 的真实 `tools/list`。
- `agentTools.roles` 可声明 `parent`、`sub`，省略时仅允许主 Agent。子会话能力是父投影、
  插件声明和 Host 授权的交集；攻击路径的节点范围由服务端强制执行。
- `frontendApi` 可绑定同一 MCP Tool；Desktop 在调用时注入 renderer context。
- credential slot 只声明名称与注入位置；值由 XSec Secret Vault 保存。
- 旧 schema v1 仅可通过 Desktop 的 `LegacyHostToolAdapter` 保留历史会话，不能声明新
  的 MCP Tool binding。

组件启停是 Desktop 本地 overlay，键为 plugin/component kind/component id。它不能修改
签名 artifact；插件总开关只遮罩组件选择，并在重新启用时保留选择。

## Factory artifact 要求

发布器必须为同一版本的每个受支持平台生成一个不可变 artifact。当前 native MCP 包和
平台目标为：

| 插件 | Rust package | artifact 内 entrypoint | 支持 Rust target |
| --- | --- | --- | --- |
| `com.xsec.attack-path` | `xsec-attack-path-mcp` | `bin/attack-path-mcp` | `aarch64-apple-darwin`、`x86_64-apple-darwin`、`x86_64-unknown-linux-gnu`、`x86_64-pc-windows-msvc` |
| `com.xsec.asset-discovery` | `xsec-asset-discovery-mcp` | `bin/asset-discovery-mcp` | `aarch64-apple-darwin`、`x86_64-apple-darwin`、`x86_64-unknown-linux-gnu`、`x86_64-pc-windows-msvc` |

资产发现的一个 binary 精确承载三个 logical server：`asset-normalize` 无参数运行；
`asset-hunter` 使用 `--provider hunter` 与声明的 Hunter API 地址；`asset-fofa` 使用
`--provider fofa` 与声明的 FOFA API 地址。它们全部以 `${PLUGIN_DATA}` 为 cwd。Factory
必须逐项校验 command、args、cwd 与 env，不能让 artifact 自行扩展 provider 模式或环境变量。

Factory 的通用打包器不能把 `any/any` source ZIP 当作含 native sidecar 的发布物。平台
构建必须使用受保护、显式 allowlist 的构建 recipe；它要记录输入源码 revision、Rust
target、二进制 SHA-256 和最终 artifact SHA-256。不得执行任意第三方插件的 build script。

受保护 runner 在完成 allowlist 中指定的交叉编译后，必须为每个 native 插件显式传递四个
普通文件，不能从插件目录发现或执行构建命令。例如，面向一次性输出目录的调用为：

```sh
python3 scripts/build_market.py --clean --output-root "$FACTORY_OUTPUT" \
  --native-sidecar-source-revision "$DESKTOP_MAIN_SHA" \
  --native-sidecar-input "com.xsec.attack-path@aarch64-apple-darwin=$RUNNER_BINARIES/attack-path-mcp-aarch64-apple-darwin" \
  --native-sidecar-input "com.xsec.attack-path@x86_64-apple-darwin=$RUNNER_BINARIES/attack-path-mcp-x86_64-apple-darwin" \
  --native-sidecar-input "com.xsec.attack-path@x86_64-unknown-linux-gnu=$RUNNER_BINARIES/attack-path-mcp-x86_64-unknown-linux-gnu" \
  --native-sidecar-input "com.xsec.attack-path@x86_64-pc-windows-msvc=$RUNNER_BINARIES/attack-path-mcp-x86_64-pc-windows-msvc" \
  --native-sidecar-input "com.xsec.asset-discovery@aarch64-apple-darwin=$RUNNER_BINARIES/asset-discovery-mcp-aarch64-apple-darwin" \
  --native-sidecar-input "com.xsec.asset-discovery@x86_64-apple-darwin=$RUNNER_BINARIES/asset-discovery-mcp-x86_64-apple-darwin" \
  --native-sidecar-input "com.xsec.asset-discovery@x86_64-unknown-linux-gnu=$RUNNER_BINARIES/asset-discovery-mcp-x86_64-unknown-linux-gnu" \
  --native-sidecar-input "com.xsec.asset-discovery@x86_64-pc-windows-msvc=$RUNNER_BINARIES/asset-discovery-mcp-x86_64-pc-windows-msvc"
```

`DESKTOP_MAIN_SHA` 是受保护 Desktop `main` 的当前 40 位提交 SHA，而不是 Factory
checkout、分支名或可变 tag。受保护 workflow 使用专用只读 GitHub App 取得该精确
revision，复核 checkout 的 `HEAD` 与 Desktop `main` 一致后才在各目标 runner 编译。该
App 只读 Desktop 内容，不能发布、签名或修改任一仓库。

runner 的发布证明必须把 Desktop source revision、每个 Rust target、每个输入二进制的
SHA-256、以及每个生成 artifact 的 SHA-256 关联到同一次构建。`build_market.py` 会拒绝
缺失、重复、空文件、符号链接、超出大小上限或不在静态 allowlist 中的输入；它不会代替
runner 编译、签名、发布或推广 release。

每个候选 artifact 必须通过以下检查后，才可进入 Beta：

1. archive 包含 portable core、可选 frontend 和对应的普通 sidecar 文件；无 symlink、
   路径逃逸或平台不兼容路径。
2. `mcp.json` 的 stdio command 精确指向 archive 内的 sidecar；`cwd` 只能使用
   `PLUGIN_ROOT` 或 `PLUGIN_DATA`。
3. `plugin.json`、MCP 文档、Skills、schema v2 binding 和 platform file digest 均有效。
4. release record 为每个平台保存独立 SHA-256；Stable 只移动已经验证的 Beta
   `releaseId`，不重建或替换 artifact。

安装只执行静态验证。启用和更新必须针对候选 artifact 完成真实 `initialize`、
`tools/list`、binding 与名称冲突预检；数据升级使用真实数据库副本。这些探测必须在受限
probe 环境中执行：不得使用生产凭据，只使用隔离可丢弃的数据副本，并施加明确的文件/
进程/网络限制；失败的探测不得修改活动 artifact、活动数据或活动指针。overlay revision
只用于组件编辑并发控制，capability revision 标识一次发布的运行时投影。最终 Tool 合集的
wire name 必须对每个受支持的嵌入式 OMP 版本（当前为 16.4.8 与 18.0.9）分别按该版本的
实际命名函数检查，覆盖插件、独立、产品、Host 与 OMP 内置来源，并持久化/验收各版本的
结果 registry。

## 发布与运行时验收

Beta 前的本地/CI 门禁至少包括：真实 archive 验证、独立 OMP 18.0.9 `--plugin-dir`、
嵌入式 OMP 16.4.8 与 18.0.9 ACP 到 Fabric、真实 stdio/loopback MCP 的
`initialize`、`tools/list` 和 `tools/call`。native sidecar 的验收还必须在对应平台实际运行。

Desktop 的只读 `_xsec/session/capabilities` 回读必须能逐项核对最终启用 Tool 的来源、
schema 与 annotations。未连接、失败或不同活动会话返回冲突契约时，当前统计为
`unknown/incomplete`；历史数量不得进入当前合计。必需会话出现上述任一失败条件时，Beta
与 Stable 门禁必须失败，不得被成功会话汇总掩盖。

Desktop Beta smoke 必须证明安装的 Factory artifact，而不是源码目录或临时 binary。它
至少核验：平台/架构选择、签名和 SHA-256、sidecar 可执行路径、`PLUGIN_DATA` 跨更新
保留，以及会话投影的任务隔离。

Factory 对每次 Beta 和 Stable 都保留 immutable source provenance、release index、KMS
sidecar 和 smoke 结果。发布、签名、推广和回滚仍只可由既有受保护工作流执行。

## 所有权边界

插件领域数据写入其 `PLUGIN_DATA`。Skills 负责编排方法和 Tool 选择；插件 MCP 负责
可独立运行的领域逻辑。assignment/project/session 身份、浏览器、代理、证据、报告、
终端、审计和 Secret Vault 均属于 XSec Host API。项目管理是 Desktop host-owned 页面，
不得通过 `com.xsec.project-workspace` 的 artifact 恢复为插件页面。
