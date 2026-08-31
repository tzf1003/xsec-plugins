# Official plugin bridge

This package owns the signed plugin manifest, permissions and release lifecycle. XSEC Desktop currently binds its compatible built-in renderer only after this package is installed and enabled. The bridge is intentionally explicit so package state, rather than the application installer, is the source of truth.

## 设置审查

默认项目根目录位于“设置 → 插件 → 项目工作区”，仅影响后续创建的项目。当前
项目的文件、资产、成果和任务参数属于项目实体，保留在主界面。详见仓库的
[插件设置规范](../../docs/plugin-settings.md)。
