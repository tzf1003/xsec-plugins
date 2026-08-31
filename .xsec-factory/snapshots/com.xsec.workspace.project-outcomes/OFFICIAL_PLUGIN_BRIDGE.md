# Official plugin bridge

This package owns the signed plugin manifest, permissions and release lifecycle. XSEC Desktop currently binds its compatible built-in renderer only after this package is installed and enabled. The bridge is intentionally explicit so package state, rather than the application installer, is the source of truth.

## 设置审查

项目成果当前没有账户级持久化配置，因此不创建空的插件设置页。成果筛选、详情、
引用和导出是当前项目操作，保留在主界面。详见仓库的
[插件设置规范](../../docs/plugin-settings.md)。
