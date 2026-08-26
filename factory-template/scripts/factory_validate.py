#!/usr/bin/env python3
"""Fail-closed static validation for a user Marketplace Factory checkout."""

from __future__ import annotations

import argparse
from pathlib import Path
import re

from factory_core import (
    FactoryError,
    MARKETPLACE_RELATIVE_PATH,
    PLUGIN_ROOT_RELATIVE_PATH,
    artifact_url,
    load_registry,
    load_release_document,
    marketplace_document,
    plugin_snapshot_dir,
    publication_path,
    read_json,
    release_tag,
    require_object,
    safe_git_sha,
    safe_repository,
    source_engines,
    stable_json,
)


ROOT = Path(__file__).resolve().parents[1]


def validate_publication_evidence(root: Path, registration, records: dict[str, dict[str, object]], stable_release_id: str | None) -> None:
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
        if channel == "beta":
            beta_evidence.add(identifier)
        else:
            stable_evidence.add(identifier)
    missing_beta = set(records).difference(beta_evidence)
    if missing_beta:
        raise FactoryError(f"publication evidence for {plugin_id} is missing Beta source evidence")
    if stable_release_id is not None and stable_release_id not in stable_evidence:
        raise FactoryError(f"publication evidence for {plugin_id} is missing Stable promotion evidence")


def validate_factory(root: Path, factory_repository: str | None = None) -> None:
    registry = load_registry(root)
    if factory_repository is not None:
        factory_repository = safe_repository(factory_repository, "factory repository")
    snapshot_root = root / PLUGIN_ROOT_RELATIVE_PATH
    expected_ids = {entry.plugin_id for entry in registry.plugins}
    if snapshot_root.exists():
        if not snapshot_root.is_dir() or snapshot_root.is_symlink():
            raise FactoryError("plugins snapshot root must be a real directory")
        for candidate in snapshot_root.iterdir():
            if candidate.is_symlink() or not candidate.is_dir() or candidate.name not in expected_ids:
                raise FactoryError(f"plugins snapshot root contains an unregistered entry: {candidate.name}")

    for registration in registry.plugins:
        snapshot = plugin_snapshot_dir(root, registration.plugin_id)
        manifest_path = snapshot / "plugin.json"
        release_path = snapshot / ".xsec-market" / "releases.json"
        if not manifest_path.exists() and not release_path.exists():
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
        validate_publication_evidence(root, registration, records, stable_release_id)

    index_path = root / MARKETPLACE_RELATIVE_PATH
    if not index_path.is_file():
        raise FactoryError("generated marketplace index is unavailable")
    if index_path.read_bytes() != stable_json(marketplace_document(root, registry)):
        raise FactoryError("generated marketplace index does not match the Factory registry and published snapshots")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--factory-repository", help="optional owner/repository URL binding")
    args = parser.parse_args()
    try:
        validate_factory(args.root.resolve(), args.factory_repository)
    except FactoryError as error:
        raise SystemExit(f"Factory validation failed: {error}") from error
    print("Marketplace Factory validation passed")


if __name__ == "__main__":
    main()
