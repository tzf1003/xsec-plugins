# Plugin-owned official frontend

This signed package owns its manifest, permissions, release lifecycle, frontend UI state and interaction logic. XSEC Desktop loads `com.xsec.desktop/frontend/index.js` in the sandbox and exposes only the capability-checked Host RPC methods declared by `plugin.json`; bootstrap must never replace it with a compatibility renderer or placeholder.

## 设置审查

子 Agent 当前没有账户级持久化配置，因此不创建空的插件设置页。运行列表、时间线、
任务诊断和恢复均是当前工作上下文，保留在主界面。详见仓库的
[插件设置规范](../../docs/plugin-settings.md)。
