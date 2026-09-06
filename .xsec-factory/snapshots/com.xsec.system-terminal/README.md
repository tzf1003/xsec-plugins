# com.xsec.system-terminal

This is the public source repository for `com.xsec.system-terminal`. It was materialized from
the immutable signed XSEC Marketplace release during the first-party source
migration. Develop on `beta`; merge reviewed, tested changes to `main` for the
Stable source line.

Marketplace artifacts, release indexes, signatures, and Factory adoption proof
remain in [tzf1003/xsec-plugins](https://github.com/tzf1003/xsec-plugins).
This source repository never stores Factory credentials or KMS material.

Source repository: <https://github.com/tzf1003/xsec-plugin-system-terminal>

## 系统终端行为

- 终端工作区跟随 XSEC Desktop 的深色或浅色外观，并在启动、读取、写入或调整
  尺寸失败时显示实际错误。
- Windows 设置页提供 CMD、Windows PowerShell 和 PowerShell 7 中当前可用的
  Shell；macOS 与 Linux 使用当前帐户的登录 Shell。
- 设置读取失败时保留实际错误，并提供页内重试；读取恢复后继续使用同一设置与保存流程。
