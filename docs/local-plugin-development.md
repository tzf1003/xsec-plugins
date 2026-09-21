# 本地插件开发准备

工厂 `plugins/<id>/` 下的每个目录是独立的插件源码仓库，开发工作台直接接入该目录。
资产发现和攻击路径通过 Rust stdio MCP 提供服务；源码仓库保留 `mcp.json`，平台二进制由构建生成。

首次接入或修改 MCP Rust 源码后，在工厂根目录执行：

```sh
python3 scripts/prepare_development.py --desktop-source ../desktop
```

`--desktop-source` 指向你信任的本地 xSecDesktop Rust workspace。准备命令使用本机 Rust target，
通过 `cargo build --locked` 构建 `xsec-asset-discovery-mcp` 和 `xsec-attack-path-mcp`，
从 Cargo 返回的实际产物路径读取文件，分别写入：

- `plugins/com.xsec.asset-discovery/bin/asset-discovery-mcp`
- `plugins/com.xsec.attack-path/bin/attack-path-mcp`

命令支持 Factory 已声明的 macOS 和 Linux 本机架构。每次执行都会调用 Cargo 增量构建；
编译失败即终止。两个产物均构建成功后才开始写入，每个文件以原子替换方式更新，并回读 SHA-256。
若写入阶段失败，命令会明确失败；修复报错后重新执行准备命令，确保两个文件均已准备完成。
生成路径加入各插件的本地 `.git/info/exclude`，保持平台产物在源码版本控制之外。

完成后回到“一键接入开发”点击“重新检查”。全部插件检查通过后，审核合并展示的权限并确认接入。
Desktop 将权限和本机执行授权绑定到检查得到的源码快照；已经接入的插件更新二进制后，需要重新检查授权，
并按开发工作台提示手动重启服务。

资产发现前端另由该插件的 `pnpm build` 构建。MCP 准备命令仅负责上面的两个本机入口；
全部插件最终是否可接入，以 Desktop 的检查结果为准。

若出现 `read development stdio MCP command ... No such file or directory`，
先运行准备命令，确认对应 `bin/` 文件生成成功，再重新检查。授权检查要求普通文件；
不要使用指向 Cargo target 目录的符号链接。

正式 Marketplace 发布继续由受保护的 Factory 流水线按固定 Desktop revision 构建各平台产物，
本地准备命令只更新开发源码目录。
