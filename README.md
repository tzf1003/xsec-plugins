# XSEC official plugin marketplace

This public repository is the canonical marketplace for the XSEC Desktop
business plugins. It follows the portable Agent Plugins marketplace contract:

- `.agents/plugins/marketplace.json` is the discovery index.
- Every `plugins/<id>/` directory carries `plugin.json` for XSEC and
  `.codex-plugin/plugin.json` for Codex-compatible discovery.
- `.xsec-market/releases.json` selects immutable `.xsec-plugin` artifacts.

## Trust and releases

Desktop pins an Ed25519 public key for this marketplace. `marketplace.json`
and every release index are signed by the CI-only
`XSEC_MARKETPLACE_SIGNING_KEY_B64` GitHub Actions secret. The private key is
not stored in this repository or in a Desktop installation.

The `Publish signed marketplace` workflow first proves that its signing seed
derives to Desktop's pinned public key. It then rebuilds deterministic archives,
updates SHA-256 digests, signs the index metadata, validates every signature and
package, and only then commits changed release output to `main`. Desktop
automatically installs the default official plugins on its first successful
online launch, then stages official updates; custom sources remain
confirmation-driven.

## Local validation

```powershell
$temporary = Join-Path $env:TEMP xsec-marketplace-build
New-Item -ItemType Directory -Path $temporary
python scripts\build_market.py --allow-unsigned --clean --output-root $temporary
python scripts\validate_market.py source --source-root . --built-root $temporary
python -m unittest discover -s tests -p "test_*.py" -v
```

Unsigned output is only for local validation. It is rejected by the pinned
official Desktop source. `python scripts\validate_market.py published` is a
fail-closed verification for a signed release tree; it requires the public key
pinned by Desktop and is intentionally run only after CI signing.

See [the remote Desktop smoke-test contract](docs/desktop-remote-marketplace-smoke-contract.md)
for the cross-platform release hand-off.
