# com.xsec.workspace.sub-agent

This is the public source repository for `com.xsec.workspace.sub-agent`. It was materialized from
the immutable signed XSEC Marketplace release during the first-party source
migration. Develop on `beta`; merge reviewed, tested changes to `main` for the
Stable source line.

Marketplace artifacts, release indexes, signatures, and Factory adoption proof
remain in [tzf1003/xsec-plugins](https://github.com/tzf1003/xsec-plugins).
This source repository never stores Factory credentials or KMS material.

Source repository: <https://github.com/tzf1003/xsec-plugin-sub-agent>

## Factory delivery verification

The `beta` branch is a protected release-input branch. A successful push is
received by the Marketplace Source Reader, reconciled by the Factory, and is
allowed to reuse an existing immutable artifact only when its plugin source
tree and release bytes are unchanged.
