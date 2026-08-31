# Official plugin bridge

This package owns the signed plugin manifest, permissions and release lifecycle.
XSEC Desktop binds its compatible renderer only after the package is installed
and enabled; package state is therefore the source of truth.

## 设置审查

默认流量过滤、MITM CA 和被动检测规则位于“设置 → 插件 → 抓包流量”。默认过滤
仅初始化之后新打开的流量工作台；CA 和被动规则保存后立即生效。当前会话流量、
搜索、详情和重放记录保留在主界面。详见仓库的
[插件设置规范](../../docs/plugin-settings.md)。
