# com.xsec.workspace.conversation-tree

This is the public source repository for `com.xsec.workspace.conversation-tree`. It was materialized from
the immutable signed XSEC Marketplace release during the first-party source
migration. Develop on `beta`; merge reviewed, tested changes to `main` for the
Stable source line.

Marketplace artifacts, release indexes, signatures, and Factory adoption proof
remain in [tzf1003/xsec-plugins](https://github.com/tzf1003/xsec-plugins).
This source repository never stores Factory credentials or KMS material.

Source repository: <https://github.com/tzf1003/xsec-plugin-conversation-tree>

## Development

The readable frontend source is under `src/`; the manifest entrypoint is a
committed, bundled `single-esm` artifact because Factory does not build plugin
frontends during adoption.

```sh
npm ci
npm run check
npm run build
```

See
[`OFFICIAL_PLUGIN_BRIDGE.md`](OFFICIAL_PLUGIN_BRIDGE.md)
for the restored behavior and the current Desktop host boundary.
