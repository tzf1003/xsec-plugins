# XSEC official plugin marketplace

This public repository is the canonical marketplace for the XSEC Desktop
business plugins. It follows the portable Agent Plugins marketplace contract:

- `.agents/plugins/marketplace.json` is the discovery index.
- Every `plugins/<id>/` directory carries `plugin.json` for XSEC and
  `.codex-plugin/plugin.json` for Codex-compatible discovery.
- `.xsec-market/releases.json` is a signed release index. Schema v2 keeps an
  append-only `releases` list and exposes independent `beta` and `stable`
  channel pointers.

## Trust and releases

Desktop pins the public Vercel KMS issuer for this marketplace. Every official
`marketplace.json` and release index has an adjacent `.sig.jws.json` sidecar
whose JWS binds the exact document SHA-256, canonical document path,
and GitHub workflow commit. Vercel KMS also emits its issuer URL in the
protected `iss` header; publication and Desktop require it to match the
pinned marketplace issuer. The marketplace repository and GitHub Actions do
not contain a private marketplace signing key.

Credential ownership, minimum permissions, rotation, and revocation (including
the protected publisher and Desktop-dispatch credentials) are governed by the
[XSEC key, certificate, and credential registry](https://github.com/tzf1003/xsec-cloud/blob/main/docs/security/signing-key-registry.md).
That registry is the authoritative non-sensitive record; do not duplicate
credential values or create a competing inventory here.

## Release channels

Release records are immutable and content addressed. A record contains its
version, engine range, artifact URL(s) and SHA-256; its `releaseId` is derived
from the version, engine range, artifact targets and SHA-256 values. Artifact
filenames include a digest prefix, so a source change without a version bump
cannot overwrite an existing package.

The protected `Publish signed marketplace` workflow runs after a normal main
change. It preserves every existing record and artifact, appends a new record
only when the current deterministic package is new, and moves **only** the
`beta` pointer. It then requests sidecars from the production Cloud KMS broker
using a short-lived GitHub OIDC token, validates every broker response, and
publishes the generated metadata through a protected PR. The broker accepts
only the protected `xsec-plugins` production workflow; it calculates the
document digest itself.

`Promote immutable marketplace release to stable` is a separate protected,
manual workflow. Give it a plugin ID and an existing `releaseId` to promote or
roll back. It changes only `channels.stable.releaseId`, never rebuilds an
archive and never changes an artifact SHA-256. A fresh KMS sidecar is produced
for the edited index and the update is again merged through a protected PR.

Both workflows dispatch the resulting immutable revision to Desktop with an
explicit `channel` (`beta` or `stable`). Desktop defaults to stable; opting
into beta must be an explicit Desktop setting. Desktop automatically installs
the default official plugins on its first successful online launch, then
stages official updates; custom sources remain confirmation-driven and
continue to use their own user-pinned raw-signature protocol.

## Local validation

Node.js 24 is required as well as Python 3.13. Marketplace validation invokes
`node --check` only against a temporary `.mjs` copy to parse the approvals
frontend; it does not import or execute plugin code.

```powershell
$temporary = Join-Path $env:TEMP xsec-marketplace-build
New-Item -ItemType Directory -Path $temporary
python scripts\build_market.py --clean --output-root $temporary
python scripts\validate_market.py source --source-root . --built-root $temporary
python -m unittest discover -s tests -p "test_*.py" -v
```

`--clean` removes stale sidecars only. It deliberately does **not** remove
release history or artifacts, because either channel may still point at any
earlier immutable release. Local builds intentionally contain no official
sidecars. Official sidecars can only be created in the protected production
workflow, where the Cloud broker accepts GitHub Actions OIDC and signs through
the non-exportable Vercel KMS key. A missing or invalid sidecar is rejected by
the pinned official Desktop source.

See [the remote Desktop smoke-test contract](docs/desktop-remote-marketplace-smoke-contract.md)
for the cross-platform release hand-off.
