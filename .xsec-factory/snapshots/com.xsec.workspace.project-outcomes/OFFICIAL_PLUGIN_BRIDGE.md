# Official plugin bridge

This package owns the signed plugin manifest, permissions and release lifecycle. Its workspace tools render from the package frontend after the package is installed and enabled. Desktop supplies only the capability-checked Host RPC bridge, current workspace binding, theme tokens, and workspace navigation.

## 设置审查

项目成果当前没有账户级持久化配置，因此不创建空的插件设置页。成果筛选、详情、
引用和来源跳转是当前项目操作，保留在主界面；当前安装包的 manifest 也不声明
设置贡献点。
