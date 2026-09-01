# XSEC official plugin marketplace

This public repository is the canonical marketplace for the XSEC Desktop
business plugins. It follows the portable Agent Plugins marketplace contract:

- `.agents/plugins/marketplace.json` is the discovery index.
- Every `plugins/<id>/` directory is an independent Git source project. Its
  package may be at the project root or under `plugins/<id>/`.
- `.xsec-factory/snapshots/<id>/` retains the immutable package input,
  including `plugin.json` and `.codex-plugin/plugin.json`, used for releases.
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
same candidate promoted to Stable. This Factory retains only a validated,
publishable snapshot in `.xsec-factory/snapshots/<plugin-id>/`, its immutable artifacts and
release history, and source provenance in
`.xsec-factory/official-publications/<plugin-id>.json`.

The Factory now has Registry v2 trust tiers.  Ordinary `external` packages
retain the restrictive optional-package rules; the exact validated
`first-party` source mapping is the only path that may retain a `com.xsec.*`
identity, existing Desktop capabilities and `INSTALLED_BY_DEFAULT`.  The
split/migration contract, KMS adoption proof and Cloud reconciliation payloads
are documented in [first-party-plugin-factory.md](docs/first-party-plugin-factory.md).
That document also defines the default-dry-run materializer that derives the
eleven split source repositories from retained immutable artifacts without
moving a channel or activating a Registry record.

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
opens the generated metadata as a protected PR. It waits for `validate.yml` and
intentionally never merges or dispatches Desktop smoke itself; the validated PR
must be merged through protected `main`. The broker accepts
only the protected `xsec-plugins` production workflow; it calculates the
document digest itself.

`Promote immutable marketplace release to stable` is a separate protected,
manual workflow. Give it a plugin ID and an existing `releaseId` to promote or
roll back. It changes only `channels.stable.releaseId`, never rebuilds an
archive and never changes an artifact SHA-256. A fresh KMS sidecar is produced
for the edited index and the update is again opened as a protected PR. It
requires the source gate and a protected final merge before Desktop smoke can run.
It remains the legacy built-in path: a registered external plugin must use the
external Stable request to `publish.yml`, so its source-main proof cannot be
bypassed.

### Retained KMS sidecar repair

`Refresh retained immutable Marketplace sidecar` is the only recovery path for
a release sidecar whose KMS envelope no longer matches the *unchanged* retained
`releases.json` bytes. It is a manual `workflow_dispatch` that accepts one
current Marketplace plugin ID and is permitted only on protected `main`, in
the protected-branch-only `production` environment, with the Factory publisher token
and GitHub Actions OIDC. It shares the normal publication queue, re-reads
current protected `main`, validates the immutable release records, artifacts
and deterministic source build before signing, and asks the Cloud broker to
sign only `.xsec-factory/snapshots/<plugin-id>/.xsec-market/releases.json`.

The workflow validates that exact new KMS sidecar, runs strict Factory
validation, and rejects its run unless the sole changed (including untracked)
path is that `.sig.jws.json` file. It cannot sign the mutable marketplace
index, choose an arbitrary document path, rebuild an artifact, edit release
history, move a Beta/Stable pointer, or modify Factory registry/evidence. It
opens a sidecar-only PR, waits for `validate.yml`, and intentionally **never merges**
the PR itself.

Before enabling it, the Cloud signing broker's OIDC policy must allow the
exact protected `refresh-retained-sidecars.yml` workflow ref in
`tzf1003/xsec-plugins`; absent that production policy change, the broker must
reject the request. This fail-closed prerequisite is separate from repository
source code and no KMS secret is stored here.

`dispatch-reviewed-marketplace-smoke.yml` is the only Desktop hand-off. It
runs after a protected `main` merge, derives `beta` or `stable` from the exact
release-index delta (not a PR title or merge subject), cryptographically
verifies every post-merge KMS sidecar, and checks the merged generated PR's
successful source gate.
For a registered plugin it also re-reads the exact `beta`/`main` source branch
head recorded in newly appended provenance with a new, read-only Source App
token scoped to that candidate's exact source repositories; a branch that
advanced before merge is rejected and must be regenerated. The companion
`verify-generated-marketplace-publication.yml` check proves a publicly readable
candidate source head before merge; it deliberately defers a private source
instead of exposing the protected Source App to untrusted PR code. The final
protected gate proves every source head with its separately scoped Source App
token, so a generated Factory PR is not merged by
a normal PR button: the trusted-base
`arm-generated-marketplace-final-merge.yml` workflow posts the required
`factory-final-merge-gate` status as **pending** without checking out or
executing PR code. It posts **success / not applicable** for every ordinary
main PR, so a Factory-only context cannot block product or documentation work.

For a registered Beta, `.xsec-factory/official-status/<plugin-id>.json` is
also a fixed-purpose KMS document. Its proof lives only at
`.xsec-factory/official-status-proofs/<plugin-id>.json` and binds the exact
`betaSha`, `mainGateSha`, release pointer and lifecycle state. The dispatcher
therefore never treats an unsigned `waiting_for_smoke` UI/status edit as a
Desktop smoke authorization. Deploy the paired `xsec-cloud` broker allowlist
for `xsec.plugin-marketplace.official-status` and that exact status subject
namespace before enabling this Factory change; until then the broker rejects
the request fail-closed.

A protected maintainer runs `final-merge-generated-marketplace-pr.yml` with the
source-gated PR number.
It re-reads the live PR head and base, revalidates the exact release diff,
every KMS sidecar and every registered external ref. The arm workflow, not the
final workflow, owns the candidate's required status and keeps it **pending**
for the complete lifetime of the PR. After revalidation, the final workflow
creates an isolated Finalizer GitHub App token and uses it only for GitHub's
exact-head squash-merge API. Source-head rechecks instead use the separate
read-only Source App and never expose the Finalizer token outside this
repository. If the head, base, source ref, Finalizer setup, or
merge operation changes/fails, the candidate remains pending; it never releases
a stale candidate or pretends a failed merge succeeded. This is the merge-time rejection boundary on personal
repositories too; it does not rely on merge queue availability. The protected
post-merge dispatcher is a fail-closed second boundary and never auto-rolls
back a pointer. The one deliberate no-pointer exception is a registered
external Stable completion where Stable already selects the current Beta: its
strictly shaped signed provenance/status update is revalidated against the
current external `main` ref and may merge, but it never dispatches a second
Desktop smoke.

Run `enforce-factory-main-protection.yml` once from protected `main` after
installing this code and whenever protection is audited. Its protected-branch-only
`production` job needs the repository-scoped administration secret
`XSEC_MARKETPLACE_ADMIN_TOKEN` and `XSEC_MARKETPLACE_FINALIZER_APP_ID`; it sets strict, GitHub-Actions-app-pinned
`source-gate` in classic protection, enforces that check for administrators,
preserves unrelated checks and branch restrictions, removes pull-request approval
requirements, and requires resolved conversations.
Before it changes classic protection, it creates and verifies the separate
`xsec-marketplace-final-exact-head` Ruleset: that Ruleset alone requires the
strict GitHub-Actions `factory-final-merge-gate` and permits only the configured
Finalizer App to bypass it through a pull request. The final merge workflow uses
no Publisher credential. It creates a short-lived, repository-scoped
`XSEC_MARKETPLACE_FINALIZER_APP_ID` /
`XSEC_MARKETPLACE_FINALIZER_APP_PRIVATE_KEY` token only after revalidation and
only for the exact-head merge API request. The Finalizer App is distinct from
the Publisher, has only `contents: write`, and is
the sole protected-main Ruleset bypass identity for this operation. Missing
production policy, Finalizer configuration, or a rejected merge leaves the
generated PR pending; repair and re-run the gate—never loosen protection or
merge it manually.
Before either the protection or final-merge workflow can proceed, `production`
must accept protected branches only, have no required reviewers, and disallow
administrator bypass; both workflows query this server-side and fail closed if
that policy differs.
The protection workflow normalizes GET-only user/team/app response objects to
the REST PUT request shape before updating, so existing branch restrictions are
preserved rather than causing a failed protection update.

The resulting Desktop dispatch has an explicit `channel` (`beta` or `stable`).
Desktop defaults to stable; opting into beta must be an explicit Desktop
setting. Desktop automatically installs the default official plugins on its
first successful online launch, then stages official updates; custom sources
remain confirmation-driven and continue to use their own user-pinned raw-
signature protocol.

## Publication queue and Agent evidence

Beta publication, Stable promotion, retained-sidecar repair, and first-party
adoption share one serialized publication slot. Before any of them calls KMS,
it refuses to sign if an `xsec-marketplace/*` generated PR is still open.
This makes the open-PR interval part of the queue: a second candidate cannot be
signed against the same Factory base, then become stale or conflict when the
first PR merges. After merge, the diff/sidecar classifier makes that generated
transition a no-op for `publish.yml`, independent of the merge subject.

If a registered source `main` event arrives after its same-plugin Beta PR was
generated, the protected Cloud Dispatcher re-reads the exact Registry source,
current Beta head/release/provenance, candidate branch identity and KMS-bound
status tuple. Only when the candidate's `mainGateSha` is older does it add an
auditable delivery comment, close that candidate, and request a replacement.
The replacement is still a new source-gated PR requiring a protected final
merge; a matching current candidate is retained as an
idempotent no-op and unrelated plugin candidates are never closed.

When a run waited in that queue, it checks out the protected `main` tip after
obtaining the slot; it does not rebuild the historical GitHub event SHA that
originally queued it. The resulting `source_sha` therefore identifies the
actual source that built and KMS-signed the documents, and may include more
than one previously queued `main` change. Agents must use the workflow's
`source_sha`, `marketplace_revision`, and `channel` as publication evidence;
they must not rerun an old event or hand-edit an index merely because that old
event SHA has no standalone Beta artifact. A generated sidecar-only repair is
classified as maintenance and cannot dispatch Desktop smoke.

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
Factory keeps third-party plugin source in independent Git subprojects under
`plugins/<id>/`, generates Desktop-compatible metadata snapshots under
`.xsec-factory/snapshots/<id>/`, and publishes
confirmation-driven Beta/Stable releases from exact Git commits. It never
inherits the official signing key, trusted-source status, or default-install
privileges, and it is not an alternative way to approve an official source
repository. Its write-capable release jobs require a reviewer-gated
`production` GitHub Environment in addition to protected `main`; a protected
ref alone does not authorize a workflow dispatcher. See [the Factory template
contract](docs/marketplace-factory-template.md).
