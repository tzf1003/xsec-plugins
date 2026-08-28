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

## Official external-source Factory

`xsec-plugins` is also the **official signed Marketplace Factory** for an
approved external plugin repository. It is not the external plugin's active
development repository. The external repository owns its code and uses its
protected `beta` branch for a candidate and protected `main` branch for the
same candidate promoted to Stable. This Factory retains only a reviewed,
publishable snapshot in `plugins/<plugin-id>/`, its immutable artifacts and
release history, and source provenance in
`.xsec-factory/official-publications/<plugin-id>.json`.

The Factory now has Registry v2 trust tiers.  Ordinary `external` packages
retain the restrictive optional-package rules; the exact reviewed
`first-party` source mapping is the only path that may retain a `com.xsec.*`
identity, existing Desktop capabilities and `INSTALLED_BY_DEFAULT`.  The
split/migration contract, KMS adoption proof and Cloud reconciliation payloads
are documented in [first-party-plugin-factory.md](docs/first-party-plugin-factory.md).

An administrator first reviews an allowlist entry in
`.xsec-factory/official-registry.json`. An entry fixes a GitHub
`owner/repository`, an optional repository-relative plugin path, and exactly
`refs/heads/beta` / `refs/heads/main`; it can grant only `AVAILABLE` and
`ON_INSTALL`, never default-install privilege. External source packages also
cannot use the Desktop-owned `com.xsec` namespace (including any future
internal package IDs) or reserved official workspace/MCP routes.
Once an external package has a Factory snapshot or marketplace entry, its
registry ownership is sticky: do not delete its registry/evidence files to
reclassify it as a local official plugin. Use `status: "disabled"` to withdraw
it while retaining the ownership record, generated snapshot, every immutable
release artifact and release-history record, publication evidence, and KMS
release sidecar. The Factory re-packages the retained snapshot against the
selected Beta digest and re-hashes every retained artifact during validation.
It also fetches the pinned Vercel KMS issuer JWKS and cryptographically verifies
the retained EdDSA sidecar, so a structurally valid but forged historical
signature cannot make a withdrawn release pass validation.
The protected source gate additionally materializes the trusted pre-change
Factory revision: after publication, deleting the registry entry together with
its snapshot and evidence is rejected rather than being mistaken for a
never-published authorization.
Each retained publication-evidence event is also append-only in its original
order: its source SHA, artifact binding, and recorded publisher cannot be
rewritten or reordered in a later PR.
The immutable release record list follows the same original-order append-only
rule, preventing historical release chronology from being rewritten.
A never-published authorization can instead be removed from the registry.
Their archive member paths must also meet Desktop's portable Windows/macOS
rules: ASCII only; no case-fold, file/directory, trailing-dot/space, NTFS
stream, forbidden-character, or device-name alias. Source file count and sizes
are bounded before snapshotting, so a signed Factory artifact is installable
without making the protected runner process an unbounded tree.
Because Desktop grants an official-marketplace package's declared capabilities
without the normal third-party confirmation flow, external Factory packages are
also limited to a conservative browser-sandbox capability set (read-only
workspace/session access, plugin-owned data/secrets, workspace navigation,
network requests, notifications, and non-reserved agent-tool registration).
They cannot add shell/process/native execution, workspace writes, browser or
clipboard control, MCP server registration, or any other high-privilege
capability merely by changing external source or registry metadata.

Desktop developer tools explicitly dispatch the existing protected
`publish.yml` at this repository's `main` branch; pushing arbitrary source code
does not itself acquire publication credentials. Its only external-source
inputs are:

```text
channel=beta|stable
plugin_id=<registered ID>
source_sha=<exact lowercase external commit SHA>
release_id=<existing Beta releaseId; Stable only>
```

For Beta, the workflow validates the registry *before* source access, creates
a read-only GitHub App token, checks out exactly `source_sha` into an isolated
directory, and proves it is reachable from the registered `beta` branch. It
then statically snapshots and deterministically packages the source without
running plugin code, hooks, package-manager scripts, or build scripts. For
Stable, it proves reachability from registered `main`, rebuilds the exact
selected Beta `releaseId`, and changes only `channels.stable.releaseId` plus
auditable main-source evidence. A different byte at the same SemVer fails; a
byte-identical Stable retry makes no KMS request, PR, or Desktop dispatch.

The external reachability fetch has its own transport boundary. The checkout
is pinned to `https://github.com`; the workflow rejects a non-canonical or
plain-HTTP `origin` and local Git URL rewrites (`insteadOf`), remote helper
settings, proxy settings, and config includes. It then derives the only fetch
URL from the allowlisted `owner/repository`, disables system/global Git config
and redirects, permits HTTPS only, and writes a local verified ref. It never
uses an external checkout's `origin` URL or remote alias to contact the
source repository. This protects the short-lived reader token from Git
transport redirection; it does not make external source code trusted or
executable.

Configure the read-only source App only in the protected production
environment as `XSEC_MARKETPLACE_SOURCE_APP_ID` and
`XSEC_MARKETPLACE_SOURCE_APP_PRIVATE_KEY`. It needs source repository metadata
and contents read access only. It is distinct from the Factory publisher token
and from the non-exportable KMS key. The Cloud broker allowlists the existing
protected `publish.yml` on `xsec-plugins/main`; therefore the KMS
`source_revision` remains the checked-out protected Factory `main` SHA, while
the external SHA lives only in immutable Factory provenance. The later Desktop
smoke dispatch likewise identifies the Factory revision, not an untrusted
external source revision.

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
It remains the legacy built-in path: a registered external plugin must use the
external Stable request to `publish.yml`, so its source-main proof cannot be
bypassed.

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

## User Marketplace Factory template

The official KMS-signed marketplace above is intentionally separate from the
user-owned Factory template in [`factory-template/`](factory-template/). A
Factory keeps third-party plugin source in its own Git repositories, generates
Desktop-compatible metadata snapshots under `plugins/<id>/`, and publishes
confirmation-driven Beta/Stable releases from exact Git commits. It never
inherits the official signing key, trusted-source status, or default-install
privileges, and it is not an alternative way to approve an official source
repository. Its write-capable release jobs require a reviewer-gated
`production` GitHub Environment in addition to protected `main`; a protected
ref alone does not authorize a workflow dispatcher. See [the Factory template
contract](docs/marketplace-factory-template.md).
