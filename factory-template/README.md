# XSEC Marketplace Factory template

This directory is copied as the root of a user-owned public GitHub repository.
It is deliberately separate from the official `xsec-plugins` marketplace: it
does **not** contain an XSEC signing key, cannot become an official trusted
source, and Desktop treats it as a confirmation-driven custom marketplace.

## What lives where

- Each plugin stays in its own Git repository. Its `beta` branch is the Beta
  candidate branch and its `main` branch is the Stable candidate branch.
- `.xsec-factory/registry.json` is the auditable allowlist of source GitHub
  repositories. Adding a registry entry authorizes a repository; it does not
  publish any source code or make a plugin visible in Desktop.
- `plugins/<plugin-id>/` is the generated, complete package-input snapshot;
  `plugin.json` plus every archived source file are retained alongside
  `plugins/<plugin-id>/.xsec-market/releases.json`. The Factory rebuilds this
  snapshot and compares it to the selected immutable artifact digest during
  validation. Its local path intentionally matches the Desktop marketplace
  discovery contract. Do not hand-edit it.
- GitHub Release assets hold immutable `.xsec-plugin` archives. Release records
  bind their SHA-256 and URL; a `releaseId` binds the version, engine range,
  target and SHA-256.

## One-time setup

1. Create a public GitHub repository from this directory and protect `main`.
   Both release workflows fail closed unless GitHub reports
   `github.ref_protected == true`. Then create a GitHub Environment named
   `production` with **required reviewers limited to release maintainers**.
   Enable the Environment's “prevent self-review” setting where available.
   The write-capable Beta and Stable jobs are explicitly bound to that
   Environment: anyone may request a dispatch, but no source token, Release
   asset, or generated metadata write is available until a designated releaser
   approves it. Do not treat protected-branch status as dispatcher
   authorization. The Factory workflows need a narrowly scoped bypass to
   commit their approved generated metadata to `main`; configure that bypass
   only for the repository's GitHub Actions bot, or replace the final commit
   step with your reviewed generated-PR policy. Do not remove protection or
   Environment review just to make a release run succeed.
2. Create a GitHub App with only **Contents: Read** and **Metadata: Read**.
   Install it only on source repositories already authorized in the registry.
   Store its ID and private key as the Factory repository secrets
   `FACTORY_GITHUB_APP_ID` and `FACTORY_GITHUB_APP_PRIVATE_KEY`.
3. Let XSEC Desktop create/import the registry entry, or submit a reviewed PR
   that uses the exact schema below. The App's repository permissions remain
   the team authorization source; the registry is the Factory's publication
   allowlist.

```json
{
  "schemaVersion": 1,
  "marketplace": {
    "name": "acme-security",
    "displayName": "Acme Security Plugins"
  },
  "plugins": [
    {
      "pluginId": "com.acme.discovery",
      "source": {
        "repository": "acme/xsec-plugin-discovery",
        "path": ".",
        "refs": {
          "beta": "refs/heads/beta",
          "stable": "refs/heads/main"
        }
      },
      "policy": {
        "installation": "AVAILABLE",
        "authentication": "ON_INSTALL"
      },
      "category": "Security",
      "status": "active"
    }
  ]
}
```

`path` may name a plugin directory inside a monorepo. The Factory accepts only
the exact `beta` and `main` mappings above. `disabled` blocks new publication
and hides an already published plugin from the generated marketplace index, but
must retain its complete package snapshot, release history, and publication
evidence. The included protected validation workflow compares against a trusted
pre-change checkout, so deleting a published registry entry together with its
snapshot/evidence is rejected; retain it as `disabled`. Remove a never-published
authorization instead. Individual publication-evidence events are append-only
in their original order: their source SHA, artifact binding, and publisher
cannot be rewritten or reordered. The immutable release list uses the same
original-order append-only rule. A merely authorized, unpublished plugin must
not have a publication-evidence file; the Factory creates that provenance only
with its first deterministic Beta release. User Factories are
intentionally limited to `AVAILABLE` installation; registry changes cannot
silently install a plugin on every Desktop.
`pluginId` must match Desktop's lowercase catalog grammar: 1–64 ASCII
lowercase letters/digits/dots/hyphens, no leading/trailing separator, and no
`..` or `--`. This keeps the generated artifact ID portable and avoids
case-colliding packages. `com.xsec` and `com.xsec.*` are reserved for Desktop
internal development; use your own reverse-domain namespace such as
`com.acme.discovery`.
Package file paths must match Desktop's portable installer rules: ASCII only;
no case-fold or file/directory collision; no trailing dot/space, NTFS stream,
Windows-forbidden character, or reserved device-name alias. The Factory bounds
the source tree, individual files, and total package content before ZIP work.

## Release lifecycle

Desktop's developer tool is the normal trigger; pushing arbitrary code alone
does not publish. This avoids turning a source repository push into a
credentialed Factory build. A developer chooses the exact already-pushed SHA
in Desktop, which dispatches the corresponding Factory workflow from the
protected Factory `main` branch. The request pauses at the required-reviewer
`production` Environment before it receives the write-capable workflow token;
an authorized release maintainer must approve it after checking the plugin,
SHA, and requested channel.

1. Develop locally in Desktop developer mode. Local `dev_revision` snapshots
   are private and never enter this Factory.
2. Commit and push an exact commit to the plugin repository's `beta` branch.
   Desktop dispatches **Publish Marketplace Factory beta** with `plugin_id`
   and that 40-character SHA.
3. The workflow reads the registry before requesting a short-lived GitHub App
   token, checks the SHA is reachable from `beta`, checks out that exact
   commit, and deterministically builds without running `npm`, `pnpm`, build
   scripts, hooks, or plugin code. It uploads an immutable GitHub Release
   asset, appends/selects the Beta release, and commits only generated Factory
   metadata. The temporary source-reader token is removed before packaging.
4. Install/test the Beta from Desktop. Once the same source is merged or
   fast-forwarded to the plugin repository's `main`, dispatch
   **Promote Marketplace Factory beta to stable** with its `plugin_id`, exact
   `main` SHA, and the verified `beta_release_id`.
5. The Stable workflow proves the SHA remains reachable from `main`, rebuilds
   it deterministically, and succeeds only if the result is exactly the chosen
   Beta `releaseId`. Before committing the pointer, it downloads the selected
   immutable GitHub Release asset and verifies its SHA-256 against the Beta
   record. It changes only `channels.stable.releaseId`; it does not upload,
   replace, or rebuild a production artifact.

An unchanged retry is idempotent. Different bytes at an already published
`plugin.json.version` fail closed: increase the plugin version and dispatch a
new Beta. Stable rollback is a manual, reviewed release-index pointer change;
this template does not expose an automatic rollback command.

Every generated release must retain Beta source evidence (registered
repository, path, branch, exact SHA, publisher, artifact URL and SHA-256).
Promoting Stable adds corresponding `main` evidence. Factory validation rebuilds
the complete generated snapshot and rejects any snapshot whose package bytes no
longer match its immutable Beta artifact, as well as metadata that lacks the
required provenance.

## Verification and trust boundary

Run locally after registry edits or generated metadata changes:

```powershell
python scripts\factory_validate.py --root .
python -m unittest discover -s tests -p "test_*.py" -v
```

The Factory is an allowlist, packaging, provenance, and distribution service.
It is not an execution environment for plugins. The source checkout is read
only; symbolic links, path escapes, malformed manifests, oversized packages,
and duplicate immutable versions are rejected. The private GitHub App key is
available only to the Factory workflow and only yields source-read tokens; the
default `GITHUB_TOKEN` writes only this Factory's generated metadata and
Release assets.

For that source-reader token, the workflow accepts GitHub.com only. It pins
the checkout to `https://github.com`, rejects a non-canonical or plain-HTTP
`origin` plus local `insteadOf`, remote-helper, proxy, and include overrides,
then fetches a URL derived solely from the reviewed registry slug. The fetch
ignores system/global Git configuration, follows no redirects, permits HTTPS
only, and records a local verified ref rather than using the checkout's remote
alias. These controls prevent Git transport redirection; they do not execute
or otherwise trust the checked-out plugin code.

Desktop still verifies the package SHA-256 and asks the user to trust/install
custom marketplace content. An unsigned Factory must never be presented as the
official KMS-signed XSEC marketplace or as a default-install source.
