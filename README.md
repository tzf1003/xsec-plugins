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
from the version, engine range, each artifact's OS/architecture target, and
SHA-256. It deliberately excludes the delivery URL so an existing package can
retain its identity if its URL moves; the signed release record still binds the
URL itself. Artifact filenames include a digest prefix, so a source change
without a version bump cannot overwrite an existing package.

The detailed developer and Agent operating rules are in the Chinese
[plugin development and release lifecycle](docs/plugin-development-release-lifecycle.md).
The authoritative UI, sandbox RPC, security, and lifecycle rules for plugin
configuration are in the Chinese [plugin settings specification](docs/plugin-settings.md).
In particular, a marketplace publication canonically recomputes `releaseId`;
one plugin `plugin.json.version` (SemVer) can name exactly one immutable
release record and its artifact set. Different packaged content, engines, or
artifact SHA-256 values require a version bump before publication. A local
Desktop `dev_revision` is intentionally separate: it permits same-version hot
reload while debugging a private workspace, but never creates a marketplace
release, artifact, channel update, or cloud upload.

The protected `Publish immutable marketplace beta release` workflow runs after a normal main
change. It preserves every existing record and artifact, appends a new record
only when the current deterministic package is new, and moves **only** the
`beta` pointer. This includes a newly added plugin: its first Beta release
leaves `channels.stable` as `null`, so it cannot reach Stable without
an explicit promotion. It then requests sidecars from the production Cloud KMS broker
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

## Publication queue and Agent evidence

Beta publication and Stable promotion share one serialized publication slot.
When a run waited in that queue, it checks out the protected `main` tip after
obtaining the slot; it does not rebuild the historical GitHub event SHA that
originally queued it. The resulting `source_sha` therefore identifies the
actual source that built and KMS-signed the documents, and may include more
than one previously queued `main` change. Agents must use the workflow's
`source_sha`, `marketplace_revision`, and `channel` as publication evidence;
they must not rerun an old event or hand-edit an index merely because that old
event SHA has no standalone Beta artifact. Bot-generated metadata pushes are
skip/no-op runs in a separate concurrency group, so they cannot replace a
pending Stable promotion.

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

The package builder canonicalizes CRLF to LF before hashing only for explicitly
textual UTF-8 source suffixes (including `.json`, `.js`, and `.md`); arbitrary
binary members remain byte-for-byte intact. A Windows developer can therefore
verify the same artifact SHA-256 that the Linux publisher will sign; an
unchanged local package never needs a cloud upload just to discover a
line-ending mismatch.

See [the remote Desktop smoke-test contract](docs/desktop-remote-marketplace-smoke-contract.md)
for the cross-platform release hand-off.
