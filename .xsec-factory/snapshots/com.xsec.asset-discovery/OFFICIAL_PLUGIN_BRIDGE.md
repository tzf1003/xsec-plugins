# Official plugin bridge

This package owns the signed plugin manifest, permissions, release lifecycle and isolated frontend. XSEC Desktop mounts the package frontend only after the package is installed and enabled, so the package state remains the source of truth for the complete asset-discovery surface.

## 设置审查

账户级默认数据源、API Host、Skill 路径和凭据配置状态位于“设置 → 插件 →
资产发现”。密钥本身由宿主安全存储管理，前端只会看到配置状态；采集运行、资产
搜索、导入和当前任务筛选仍属于主界面。详见[插件设置规范](docs/plugin-settings.md)。
