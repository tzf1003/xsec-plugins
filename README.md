# XSEC official plugin marketplace

This public repository is the canonical marketplace for the XSEC Desktop
business plugins. It follows the portable Agent Plugins marketplace contract:

- `.agents/plugins/marketplace.json` is the discovery index.
- Every `plugins/<id>/` directory carries `plugin.json` for XSEC and
  `.codex-plugin/plugin.json` for Codex-compatible discovery.
- `.xsec-market/releases.json` selects immutable `.xsec-plugin` artifacts.

## Trust and releases

Desktop pins the public Vercel KMS issuer for this marketplace. Every official
`marketplace.json` and release index has an adjacent `.sig.jws.json` sidecar
whose JWS binds the exact document SHA-256, canonical document path,
and GitHub workflow commit. Vercel KMS also emits its issuer URL in the
protected `iss` header; publication and Desktop require it to match the
pinned marketplace issuer. The marketplace repository and GitHub Actions do
not contain a private marketplace signing key.

The `Publish signed marketplace` workflow rebuilds deterministic archives,
requests sidecars from the production Cloud KMS broker using a short-lived
GitHub OIDC token, validates every broker response before it is written, and
commits changed output to `main`. The broker accepts only the protected
`xsec-plugins` production workflow; it calculates the document digest itself.
After publication the workflow dispatches the immutable marketplace revision
to the Desktop smoke gate. Desktop automatically installs the default official
plugins on its first successful online launch, then stages official updates;
custom sources remain confirmation-driven and continue to use their own
user-pinned raw-signature protocol.

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

Local builds intentionally contain no official sidecars. Official sidecars can
only be created in the protected production workflow, where the Cloud broker
accepts GitHub Actions OIDC and signs through the non-exportable Vercel KMS
key. A missing or invalid sidecar is rejected by the pinned official Desktop
source.

See [the remote Desktop smoke-test contract](docs/desktop-remote-marketplace-smoke-contract.md)
for the cross-platform release hand-off.
