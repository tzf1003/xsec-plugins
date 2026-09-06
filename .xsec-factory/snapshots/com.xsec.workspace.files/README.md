# com.xsec.workspace.files

This is the public source repository for `com.xsec.workspace.files`. It was materialized from
the immutable signed XSEC Marketplace release during the first-party source
migration. Develop on `beta`; merge reviewed, tested changes to `main` for the
Stable source line.

Marketplace artifacts, release indexes, signatures, and Factory adoption proof
remain in [tzf1003/xsec-plugins](https://github.com/tzf1003/xsec-plugins).
This source repository never stores Factory credentials or KMS material.

Source repository: <https://github.com/tzf1003/xsec-plugin-files>

## Development

Desktop loads the signed `single-esm` entrypoint at
`com.xsec.desktop/frontend/index.js`. The readable source lives in
`frontend-src/`; it restores the project-file tree, text preview, Composer
path references and line comments. The Factory packages this repository root
directly.

Run `pnpm install` followed by `pnpm run check` before publishing. The check
bundles the frontend, verifies the manifest RPC contract and keeps the checked-in
frontend artifact current. Version `1.3.4` requires Desktop Plugin API `1.4.0`.
