# Official plugin bridge

This package owns the signed plugin manifest, permissions, sandboxed frontend
and release lifecycle. XSEC Desktop loads the package frontend only after the
package is installed, enabled and validated; package state is therefore the
source of truth.

## 运行边界

- 插件源码在仓库 `src/`，构建结果是清单声明的单文件 ESM
  `com.xsec.desktop/frontend/index.js`。
- 流量列表、完整筛选、请求/响应详情、独立详情、重放编辑器与设置页均由插件前端
  渲染；旧版 Desktop React 工作台不参与运行。
- Desktop 只提供带 capability 和会话绑定校验的 Host RPC：读取当前会话流量、
  读取重放历史、执行重放、添加会话引用、打开插件工作区工具，以及插件设置数据。
- `xsec.traffic.persisted` 仅转发当前宿主绑定会话的入库事件；前端据此刷新当前页或
  提示查看最新流量。
- 重放报文沿用后端 2 MiB 原始请求上限。仅官方抓包插件的
  `xsec.traffic.replay` 获得相应的精确消息大小额度，其余 RPC 保持默认额度。

修改前端后运行 `pnpm verify`，并提交更新后的生成制品。Desktop 桥接变更还需要
运行相关 Vitest、Plugin SDK 校验、Desktop typecheck 和 Rust 重放边界测试。

## 设置审查

默认流量过滤、MITM CA 和被动检测规则位于“设置 → 插件 → 抓包流量”。默认过滤
仅初始化之后新打开的流量工作台；CA 和被动规则保存后立即生效。当前会话流量、
搜索、详情和重放记录保留在主界面。详见仓库的
[恢复方案与设置边界](../../docs/restoration-plan.md)。
