# XSEC plugin marketplace

XSEC Marketplace Factory registers plugin source repositories and publishes deterministic,
immutable `.xsec-plugin` artifacts. Plugin development lives in independent source
repositories; Factory keeps reviewed registration, package snapshots, release indexes
and source provenance.

## Current release contract

Each SemVer identifies one immutable release. Desktop selects the highest compatible
version using the Host/API requirements and the current OS/architecture, verifies the
artifact SHA-256, and asks the user to confirm its permissions. Official and external
plugins use the same permission-confirmation model. Registry membership does not grant
runtime permissions.

Marketplace KMS/JWS signing was retired on 2026-09-20. Publication uses protected
Factory workflows, exact source revisions, immutable release records and artifact hashes.
Historical `beta`/`stable` fields remain in some schemas; they do not define a current
promotion requirement. Desktop installer/updater and Managed Skill signing have their
own contracts.

Plugins must support Windows, macOS and Linux. The native target matrix contains four
OS/architecture combinations: Windows x64, Linux x64, macOS arm64 and macOS x86_64.
Routine development, updates and publication do not require cross-platform Desktop Host
Smoke by default. Run source/package checks and verification appropriate to the change.
Optional Host acceptance is recorded separately from publication.

## Documentation

- [Development and publication](docs/plugin-development-release-lifecycle.md): current steps and evidence.
- [Registration and source ownership](docs/first-party-plugin-factory.md): Registry v2, package roots and retained history.
- [Local plugin development](docs/local-plugin-development.md): prepare local MCP binaries before Desktop development checks.
- [Agent Plugins runtime contract](docs/agent-plugins-runtime-contract.md): portable packages, native artifacts and runtime boundaries.
- [Migration playbook](docs/agent-plugins-migration-playbook.md) and [attack-path reference](docs/attack-path-agent-plugin-reference.md).
- [Plugin settings](docs/plugin-settings.md): settings schema, UI and data boundaries.
- [Finalizer ruleset](docs/factory-finalizer-ruleset-policy.md): exact-head merge and credential separation.
- [Optional Desktop Smoke](docs/desktop-remote-marketplace-smoke-contract.md): scope and reporting.
- [Custom Factory template](docs/marketplace-factory-template.md): separately versioned template and its compatibility constraints.

## Repository layout

- `.xsec-factory/official-registry.json`: reviewed source allowlist.
- `plugins/<id>/`: independent source checkouts for local development.
- `.xsec-factory/snapshots/<id>/`: generated package snapshots and release indexes.
- `.agents/plugins/marketplace.json`: Desktop discovery index.
- `.xsec-factory/official-publications/`: retained source provenance.
- `.github/workflows/`: protected publication, source validation and finalization.

Use the workflow definitions at the exact Factory revision being published. Generated
artifacts and historical release records are append-only; documentation cleanup must
not rewrite their bytes. Superseded operating procedures are available in Git history.
