# Official plugin bridge

This package owns the signed plugin manifest, permissions and release lifecycle. XSEC Desktop currently binds its compatible built-in renderer only after this package is installed and enabled. The bridge is intentionally explicit so package state, rather than the application installer, is the source of truth.

## 设置审查

默认终端配置位于“设置 → 插件 → 系统终端”，仅影响后续新建的 PTY。Windows
提供 CMD、Windows PowerShell 和 PowerShell 7 中已安装的选项；macOS 与 Linux
使用当前帐户的登录 Shell。终端主界面显示 PTY 内容和真实错误。界面与设置区均跟随
XSEC Desktop 的深色或浅色外观。详见
[插件设置规范](https://github.com/tzf1003/xsec-plugins/blob/main/docs/plugin-settings.md)。
