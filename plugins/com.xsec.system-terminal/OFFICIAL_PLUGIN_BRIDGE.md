# Official plugin bridge

This package owns the signed plugin manifest, permissions and release lifecycle. XSEC Desktop currently binds its compatible built-in renderer only after this package is installed and enabled. The bridge is intentionally explicit so package state, rather than the application installer, is the source of truth.

## 设置审查

默认终端配置位于“设置 → 插件 → 系统终端”，仅影响后续新建的 PTY；失效选择会
安全回退到系统默认终端。终端主界面仅显示 PTY 内容、真实错误和恢复入口，不再
提供配置下拉框、重启或清屏工具栏。详见仓库的
[插件设置规范](../../docs/plugin-settings.md)。
