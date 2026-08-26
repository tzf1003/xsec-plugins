# Official plugin bridge

This package owns the signed plugin manifest, permissions and release lifecycle. XSEC Desktop currently binds its compatible built-in renderer only after this package is installed and enabled. The bridge is intentionally explicit so package state, rather than the application installer, is the source of truth.

## 设置审查

Chrome 可执行文件路径位于“设置 → 插件 → 浏览器会话”，重新启动浏览器会话后
生效。会话、标签页、导航和当前工作恢复保留在主界面。详见仓库的
[插件设置规范](../../docs/plugin-settings.md)。
