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

The `Publish signed marketplace` workflow rebuilds deterministic archives,
updates SHA-256 digests, signs the index metadata, and commits any changed
release output to `main`. Desktop automatically installs the default official
plugins on its first successful online launch, then stages official updates;
custom sources remain confirmation-driven.

## Local validation

```powershell
python scripts\build_market.py --allow-unsigned --clean
python -m json.tool .agents\plugins\marketplace.json > $null
```

Unsigned output is only for local validation. It is rejected by the pinned
official Desktop source.
