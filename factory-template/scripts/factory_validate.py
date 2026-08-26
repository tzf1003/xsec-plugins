#!/usr/bin/env python3
"""Fail-closed static validation for a user Marketplace Factory checkout."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import tempfile

from factory_core import (
    FactoryError,
    MAX_PUBLICATION_ATTESTATION_BYTES,
    MARKETPLACE_RELATIVE_PATH,
    PLUGIN_ROOT_RELATIVE_PATH,
    PUBLICATIONS_RELATIVE_PATH,
    REGISTRY_RELATIVE_PATH,
    artifact_url,
    is_link,
    load_registry,
    load_release_document,
    marketplace_document,
    publication_attestation_bytes,
    publication_attestation_name,
    plugin_snapshot_dir,
    publication_path,
    read_json,
    release_document_path,
    release_tag,
    require_object,
    safe_git_sha,
    safe_repository,
    sha256,
    source_engines,
    stable_json,
    write_zip,
)


ROOT = Path(__file__).resolve().parents[1]


def validate_publication_attestation(
    attestation_root: Path,
    registration,
    event: dict[str, object],
) -> tuple[str, bytes]:
    """Verify one locally materialized immutable GitHub Release asset."""

    name = publication_attestation_name(registration, event)
    expected = publication_attestation_bytes(registration, event)
    if len(expected) > MAX_PUBLICATION_ATTESTATION_BYTES:
        raise FactoryError("publication attestation exceeds the size limit")
    if is_link(attestation_root) or not attestation_root.is_dir():
        raise FactoryError("publication attestation root must be a regular directory")
    candidate = attestation_root / name
    if is_link(candidate) or not candidate.is_file():
        raise FactoryError(f"publication attestation for {registration.plugin_id} is unavailable")
    try:
        candidate.resolve(strict=True).relative_to(attestation_root.resolve(strict=True))
    except (OSError, ValueError) as error:
        raise FactoryError(f"publication attestation for {registration.plugin_id} escaped its root") from error
    if candidate.stat().st_size > MAX_PUBLICATION_ATTESTATION_BYTES:
        raise FactoryError(f"publication attestation for {registration.plugin_id} exceeds the size limit")
    actual = candidate.read_bytes()
    if sha256(actual) != sha256(expected) or actual != expected:
        raise FactoryError(f"publication attestation for {registration.plugin_id} does not match immutable evidence")
    return name, expected


def validate_publication_attestation_root(attestation_root: Path, expected: dict[str, bytes]) -> None:
    """Reject leftover files so a caller cannot substitute a partial proof set."""

    if is_link(attestation_root) or not attestation_root.is_dir():
        raise FactoryError("publication attestation root must be a regular directory")
    actual: dict[str, Path] = {}
    for candidate in attestation_root.iterdir():
        if is_link(candidate) or not candidate.is_file() or candidate.name in actual:
            raise FactoryError("publication attestation root contains an unsafe entry")
        actual[candidate.name] = candidate
    if set(actual) != set(expected):
        raise FactoryError("publication attestation root does not contain the exact immutable evidence set")


def validate_publication_evidence(
    root: Path,
    registration,
    records: dict[str, dict[str, object]],
    stable_release_id: str | None,
    *,
    attestation_root: Path | None = None,
    collect_attestations: bool = False,
) -> dict[str, bytes]:
    plugin_id = registration.plugin_id
    path = publication_path(root, plugin_id)
    if not path.exists():
        raise FactoryError(f"published plugin snapshot for {plugin_id} has no immutable publication evidence")
    document = read_json(path, f"publication evidence for {plugin_id}")
    if set(document) != {"schemaVersion", "pluginId", "events"} or document.get("schemaVersion") != 1 or document.get("pluginId") != plugin_id:
        raise FactoryError(f"publication evidence for {plugin_id} has an unsupported schema")
    events = document.get("events")
    if not isinstance(events, list):
        raise FactoryError(f"publication evidence for {plugin_id}.events must be a list")
    seen: set[tuple[str, str, str]] = set()
    beta_evidence: set[str] = set()
    stable_evidence: set[str] = set()
    attestations: dict[str, bytes] = {}
    for index, raw_event in enumerate(events):
        label = f"publication evidence for {plugin_id} event {index}"
        event = require_object(raw_event, label)
        channel = event.get("channel")
        if (
            set(event) != {"channel", "releaseId", "source", "artifact", "publisher"}
            or not isinstance(channel, str)
            or channel not in {"beta", "stable"}
        ):
            raise FactoryError(f"{label} has an unsupported schema")
        identifier = event.get("releaseId")
        if not isinstance(identifier, str) or identifier not in records:
            raise FactoryError(f"{label} references an unknown immutable release")
        source = require_object(event.get("source"), f"{label}.source")
        if set(source) != {"repository", "path", "ref", "sha"}:
            raise FactoryError(f"{label}.source has an unsupported schema")
        repository = safe_repository(source.get("repository"), f"{label}.source.repository")
        path_value = source.get("path")
        if not isinstance(path_value, str) or not path_value:
            raise FactoryError(f"{label}.source.path must be a non-empty path")
        sha = safe_git_sha(source.get("sha"), f"{label}.source.sha")
        if (
            repository != registration.repository
            or path_value != registration.source_path.as_posix()
            or source.get("ref") != registration.branch_for_channel[channel]
        ):
            raise FactoryError(f"{label}.source does not match the registered source")
        artifact = require_object(event.get("artifact"), f"{label}.artifact")
        if set(artifact) != {"sha256", "url"}:
            raise FactoryError(f"{label}.artifact has an unsupported schema")
        digest, url = artifact.get("sha256"), artifact.get("url")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest) or not isinstance(url, str):
            raise FactoryError(f"{label}.artifact has invalid values")
        record_artifacts = records[identifier].get("artifacts")
        if not isinstance(record_artifacts, list) or not any(
            isinstance(record_artifact, dict)
            and record_artifact.get("sha256") == digest
            and record_artifact.get("url") == url
            for record_artifact in record_artifacts
        ):
            raise FactoryError(f"{label}.artifact does not match its immutable release record")
        publisher = event.get("publisher")
        if not isinstance(publisher, str) or not publisher or len(publisher) > 128 or "\x00" in publisher:
            raise FactoryError(f"{label}.publisher must be a bounded identity")
        key = (str(identifier), channel, repository, sha)
        if key in seen:
            raise FactoryError(f"{label} duplicates an immutable publication event")
        seen.add(key)
        if collect_attestations:
            # Calculate the complete expected set even if the caller has not
            # supplied a local proof directory.  That lets strict validation
            # accept a truly fresh Factory while still failing closed as soon
            # as it finds an immutable published-evidence event.
            name = publication_attestation_name(registration, event)
            payload = publication_attestation_bytes(registration, event)
            if len(payload) > MAX_PUBLICATION_ATTESTATION_BYTES:
                raise FactoryError("publication attestation exceeds the size limit")
            if attestation_root is not None:
                name, payload = validate_publication_attestation(attestation_root, registration, event)
            previous = attestations.get(name)
            if previous is not None and previous != payload:
                raise FactoryError("publication attestation filename collision")
            attestations[name] = payload
        if channel == "beta":
            beta_evidence.add(identifier)
        else:
            stable_evidence.add(identifier)
    missing_beta = set(records).difference(beta_evidence)
    if missing_beta:
        raise FactoryError(f"publication evidence for {plugin_id} is missing Beta source evidence")
    if stable_release_id is not None and stable_release_id not in stable_evidence:
        raise FactoryError(f"publication evidence for {plugin_id} is missing Stable promotion evidence")
    return attestations


def snapshot_artifact_digest(snapshot: Path) -> str:
    """Return the deterministic package bytes represented by a local snapshot."""

    with tempfile.TemporaryDirectory(prefix="xsec-factory-validate-snapshot-") as directory:
        candidate = Path(directory) / "candidate.xsec-plugin"
        write_zip(snapshot, candidate)
        return sha256(candidate)


def published_release_history(root: Path, registry, *, state_label: str) -> dict[str, tuple[str, ...]]:
    """Return ordered immutable release IDs present in one trusted Factory state."""

    histories: dict[str, tuple[str, ...]] = {}
    for registration in registry.plugins:
        path = release_document_path(root, registration.plugin_id)
        if is_link(path):
            raise FactoryError(f"{state_label} release metadata for {registration.plugin_id} must not use symbolic links")
        if not path.is_file():
            continue
        document = load_release_document(path, registration.plugin_id)
        releases = document.get("releases")
        if not isinstance(releases, list):
            raise FactoryError(f"{state_label} release metadata for {registration.plugin_id} has an invalid release list")
        identifiers = tuple(
            record.get("releaseId")
            for record in releases
            if isinstance(record, dict) and isinstance(record.get("releaseId"), str)
        )
        if len(set(identifiers)) != len(identifiers):
            raise FactoryError(f"{state_label} release metadata for {registration.plugin_id} duplicates an immutable release")
        if identifiers:
            histories[registration.plugin_id] = identifiers
    return histories


def publication_evidence_history(root: Path, registration, *, state_label: str) -> tuple[str, ...]:
    """Return ordered publication events whose source provenance is immutable."""

    path = publication_path(root, registration.plugin_id)
    if is_link(path) or not path.is_file():
        raise FactoryError(f"{state_label} publication evidence for {registration.plugin_id} is unavailable")
    evidence = read_json(path, f"{state_label} publication evidence for {registration.plugin_id}")
    if set(evidence) != {"schemaVersion", "pluginId", "events"} or evidence.get("schemaVersion") != 1:
        raise FactoryError(f"{state_label} publication evidence for {registration.plugin_id} has an unsupported schema")
    if evidence.get("pluginId") != registration.plugin_id:
        raise FactoryError(f"{state_label} publication evidence for {registration.plugin_id} has an invalid identity")
    events = evidence.get("events")
    if not isinstance(events, list):
        raise FactoryError(f"{state_label} publication evidence for {registration.plugin_id} has an invalid event list")
    canonical_events = tuple(
        json.dumps(
            require_object(event, f"{state_label} publication evidence event {index}"),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        for index, event in enumerate(events)
    )
    if len(set(canonical_events)) != len(canonical_events):
        raise FactoryError(f"{state_label} publication evidence for {registration.plugin_id} duplicates an immutable event")
    return canonical_events


def validate_trusted_baseline_continuity(root: Path, registry, baseline_root: Path | None) -> None:
    """Require published registry entries and release history to remain append-only.

    A checkout with all current references removed cannot distinguish an erased
    publication from a never-published authorization. The CI gate therefore
    passes a separately materialized protected base revision; a released
    package can only be withdrawn by retaining its registry entry as disabled.
    """

    if baseline_root is None:
        return
    try:
        baseline = baseline_root.resolve(strict=True)
        current = root.resolve(strict=True)
    except OSError as error:
        raise FactoryError("trusted Factory baseline is unavailable") from error
    if baseline == current or is_link(baseline) or not baseline.is_dir():
        raise FactoryError("trusted Factory baseline must be a distinct regular directory")

    baseline_registry_directory = baseline / REGISTRY_RELATIVE_PATH.parent
    baseline_registry_path = baseline / REGISTRY_RELATIVE_PATH
    if is_link(baseline_registry_directory):
        raise FactoryError("trusted Factory baseline registry directory must not be a symbolic link")
    if baseline_registry_directory.exists() and not baseline_registry_directory.is_dir():
        raise FactoryError("trusted Factory baseline registry directory must be a regular directory")
    if is_link(baseline_registry_path):
        raise FactoryError("trusted Factory baseline registry must not be a symbolic link")
    if not baseline_registry_path.exists():
        # A Factory can first be introduced relative to a protected revision
        # that predates this metadata. That state has no release history to
        # retain; once a registry exists, the checks below are append-only.
        return

    baseline_registry = load_registry(baseline)
    baseline_histories = published_release_history(
        baseline,
        baseline_registry,
        state_label="trusted Factory baseline",
    )
    if not baseline_histories:
        return

    current_by_id = {registration.plugin_id: registration for registration in registry.plugins}
    baseline_by_id = {registration.plugin_id: registration for registration in baseline_registry.plugins}
    current_histories = published_release_history(root, registry, state_label="current Factory")
    for plugin_id, baseline_ids in baseline_histories.items():
        registration = current_by_id.get(plugin_id)
        if registration is None:
            raise FactoryError(
                f"published plugin {plugin_id} cannot be removed from the registry; retain it with status=disabled"
            )
        baseline_registration = baseline_by_id[plugin_id]
        if (
            registration.repository != baseline_registration.repository
            or registration.source_path != baseline_registration.source_path
            or registration.beta_ref != baseline_registration.beta_ref
            or registration.stable_ref != baseline_registration.stable_ref
        ):
            raise FactoryError(
                f"published plugin {plugin_id} cannot change its registered source identity from the trusted baseline"
            )
        snapshot = plugin_snapshot_dir(root, plugin_id)
        evidence = publication_path(root, plugin_id)
        if is_link(snapshot) or not snapshot.is_dir() or is_link(evidence) or not evidence.is_file():
            raise FactoryError(
                f"published plugin {plugin_id} must retain its immutable snapshot, release history, "
                "and publication evidence recorded in the trusted baseline"
            )
        current_ids = current_histories.get(plugin_id, ())
        if current_ids[: len(baseline_ids)] != baseline_ids:
            raise FactoryError(
                f"published plugin {plugin_id} must retain every immutable release recorded in the trusted baseline "
                "in append-only order"
            )
        baseline_events = publication_evidence_history(
            baseline,
            baseline_registration,
            state_label="trusted Factory baseline",
        )
        current_events = publication_evidence_history(
            root,
            registration,
            state_label="current Factory",
        )
        if current_events[: len(baseline_events)] != baseline_events:
            raise FactoryError(
                f"published plugin {plugin_id} must retain every immutable publication evidence event "
                "recorded in the trusted baseline in append-only order"
            )


def validate_factory(
    root: Path,
    factory_repository: str | None = None,
    *,
    baseline_root: Path | None = None,
    publication_attestation_root: Path | None = None,
    require_publication_attestations: bool = False,
) -> None:
    registry = load_registry(root)
    validate_trusted_baseline_continuity(root, registry, baseline_root)
    if factory_repository is not None:
        factory_repository = safe_repository(factory_repository, "factory repository")
    if publication_attestation_root is not None:
        try:
            publication_attestation_root = publication_attestation_root.resolve(strict=True)
        except OSError as error:
            raise FactoryError("publication attestation root is unavailable") from error
        if is_link(publication_attestation_root) or not publication_attestation_root.is_dir():
            raise FactoryError("publication attestation root must be a regular directory")
    expected_attestations: dict[str, bytes] = {}
    snapshot_root = root / PLUGIN_ROOT_RELATIVE_PATH
    expected_ids = {entry.plugin_id for entry in registry.plugins}
    if snapshot_root.exists():
        if not snapshot_root.is_dir() or snapshot_root.is_symlink():
            raise FactoryError("plugins snapshot root must be a real directory")
        for candidate in snapshot_root.iterdir():
            if candidate.is_symlink() or not candidate.is_dir() or candidate.name not in expected_ids:
                raise FactoryError(f"plugins snapshot root contains an unregistered entry: {candidate.name}")

    publication_root = root / PUBLICATIONS_RELATIVE_PATH
    if publication_root.exists():
        if is_link(publication_root) or not publication_root.is_dir():
            raise FactoryError("Factory publication evidence directory must be a regular directory")
        expected_files = {f"{plugin_id}.json" for plugin_id in expected_ids}
        for candidate in publication_root.iterdir():
            if is_link(candidate) or not candidate.is_file() or candidate.name not in expected_files:
                raise FactoryError(f"Factory publication evidence directory has an unregistered entry: {candidate.name}")

    for registration in registry.plugins:
        snapshot = plugin_snapshot_dir(root, registration.plugin_id)
        manifest_path = snapshot / "plugin.json"
        release_path = snapshot / ".xsec-market" / "releases.json"
        evidence_path = publication_path(root, registration.plugin_id)
        if registration.status == "disabled":
            # Withdrawal removes discovery only. A published disabled package
            # must retain the package snapshot, release history and provenance
            # so re-enabling cannot publish new bytes under an old SemVer.
            if not manifest_path.is_file() or not release_path.is_file() or not evidence_path.is_file():
                raise FactoryError(
                    f"disabled plugin {registration.plugin_id} must retain its immutable snapshot, "
                    "release history, and publication evidence"
                )
        elif not manifest_path.exists() and not release_path.exists():
            # An authorization becomes published only after its deterministic
            # Beta snapshot and release metadata exist.  Do not allow a PR to
            # pre-seed provenance before that point: append_publication() may
            # treat a matching identity as an idempotent retry and retain the
            # forged event rather than replacing it during first publication.
            if evidence_path.exists() or is_link(evidence_path):
                raise FactoryError(f"unpublished plugin {registration.plugin_id} must not have publication evidence")
            continue
        if not manifest_path.is_file() or not release_path.is_file():
            raise FactoryError(f"published plugin snapshot for {registration.plugin_id} is incomplete")
        manifest = read_json(manifest_path, f"plugin snapshot manifest for {registration.plugin_id}")
        if manifest.get("name") != registration.plugin_id:
            raise FactoryError(f"plugin snapshot manifest for {registration.plugin_id} has the wrong name")
        release = load_release_document(release_path, registration.plugin_id)
        releases = release.get("releases")
        if not isinstance(releases, list) or not releases:
            raise FactoryError(f"published plugin snapshot for {registration.plugin_id} has no release history")
        records = {str(record["releaseId"]): record for record in releases if isinstance(record, dict)}
        beta = require_object(require_object(release.get("channels"), "release metadata channels").get("beta"), "release metadata beta pointer")
        beta_id = beta.get("releaseId")
        if not isinstance(beta_id, str) or beta_id not in records:
            raise FactoryError(f"published plugin snapshot for {registration.plugin_id} has no valid beta pointer")
        current = records[beta_id]
        if manifest.get("version") != current.get("version"):
            raise FactoryError(f"plugin snapshot manifest for {registration.plugin_id} does not describe its beta release")
        if source_engines(manifest) != current.get("engines"):
            raise FactoryError(
                f"plugin snapshot manifest for {registration.plugin_id} does not describe its beta release engines"
            )
        artifacts = current.get("artifacts")
        expected_snapshot_digest = (
            artifacts[0].get("sha256")
            if isinstance(artifacts, list)
            and len(artifacts) == 1
            and isinstance(artifacts[0], dict)
            and artifacts[0].get("os") == "any"
            and artifacts[0].get("arch") == "any"
            else None
        )
        if not isinstance(expected_snapshot_digest, str):
            raise FactoryError(f"published plugin snapshot for {registration.plugin_id} has an invalid beta artifact")
        if snapshot_artifact_digest(snapshot) != expected_snapshot_digest:
            raise FactoryError(
                f"plugin snapshot for {registration.plugin_id} does not reproduce its immutable beta release artifact"
            )
        if factory_repository is not None:
            for record in records.values():
                artifacts = record.get("artifacts")
                if not isinstance(artifacts, list):
                    raise AssertionError("validated record unexpectedly lacks artifacts")
                for artifact in artifacts:
                    if not isinstance(artifact, dict):
                        raise AssertionError("validated artifact unexpectedly has the wrong type")
                    url = artifact.get("url")
                    digest = artifact.get("sha256")
                    if not isinstance(url, str) or not isinstance(digest, str):
                        raise FactoryError(f"release artifact for {registration.plugin_id} has invalid values")
                    filename = f"{registration.plugin_id}-{record['version']}-sha256-{digest[:16]}-any-any.xsec-plugin"
                    expected_url = artifact_url(
                        factory_repository,
                        release_tag(registration.plugin_id, str(record["releaseId"])),
                        filename,
                    )
                    if url != expected_url:
                        raise FactoryError(f"release artifact for {registration.plugin_id} points outside this Factory repository")
        stable_pointer = require_object(release["channels"], "release metadata channels").get("stable")
        stable_release_id = stable_pointer.get("releaseId") if isinstance(stable_pointer, dict) else None
        for name, payload in validate_publication_evidence(
            root,
            registration,
            records,
            stable_release_id,
            attestation_root=publication_attestation_root if require_publication_attestations else None,
            collect_attestations=require_publication_attestations,
        ).items():
            previous = expected_attestations.get(name)
            if previous is not None and previous != payload:
                raise FactoryError("publication attestation filename collision")
            expected_attestations[name] = payload

    index_path = root / MARKETPLACE_RELATIVE_PATH
    if not index_path.is_file():
        raise FactoryError("generated marketplace index is unavailable")
    if index_path.read_bytes() != stable_json(marketplace_document(root, registry)):
        raise FactoryError("generated marketplace index does not match the Factory registry and published snapshots")
    if require_publication_attestations:
        if publication_attestation_root is None:
            if expected_attestations:
                raise FactoryError("publication attestation root is required for strict Factory validation")
        else:
            validate_publication_attestation_root(publication_attestation_root, expected_attestations)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--factory-repository", help="optional owner/repository URL binding")
    parser.add_argument(
        "--baseline-root",
        type=Path,
        help="trusted pre-change Factory checkout used to prevent publication-history deletion",
    )
    parser.add_argument(
        "--publication-attestation-root",
        type=Path,
        help="isolated directory of GitHub Release provenance assets materialized by the CI gate",
    )
    parser.add_argument(
        "--allow-unsigned-publication-attestations",
        action="store_true",
        help="only for the production publisher before it uploads immutable release assets",
    )
    args = parser.parse_args()
    try:
        validate_factory(
            args.root.resolve(),
            args.factory_repository,
            baseline_root=args.baseline_root.resolve() if args.baseline_root is not None else None,
            publication_attestation_root=(
                args.publication_attestation_root.resolve()
                if args.publication_attestation_root is not None
                else None
            ),
            require_publication_attestations=not args.allow_unsigned_publication_attestations,
        )
    except FactoryError as error:
        raise SystemExit(f"Factory validation failed: {error}") from error
    print("Marketplace Factory validation passed")


if __name__ == "__main__":
    main()
