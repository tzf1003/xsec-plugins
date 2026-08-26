#!/usr/bin/env python3
"""Build an external plugin commit into a user Marketplace Factory release.

The workflow performs Git reachability checks before invoking this command.
This command intentionally has no GitHub credentials and no package-manager
integration: it only consumes a pre-checked-out source tree and writes
deterministic artifacts/metadata for the caller to upload and commit.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import sys
import tempfile

from factory_core import (
    FactoryError,
    REGISTRY_RELATIVE_PATH,
    RELEASE_ID_PATTERN,
    append_publication,
    archive_bytes,
    atomic_write,
    candidate_release,
    load_registry,
    load_release_document,
    publication_path,
    read_source_plugin,
    registration_for,
    release_document_path,
    require_object,
    require_write_path_below,
    safe_git_sha,
    safe_repository,
    sha256,
    stable_json,
    write_marketplace_index,
    write_zip,
)


ROOT = Path(__file__).resolve().parents[1]


def write_github_outputs(values: dict[str, str], destination: Path | None) -> None:
    """Write bounded simple values to the Actions output file when requested."""

    if destination is None:
        return
    if destination.exists() and destination.is_dir():
        raise FactoryError("GitHub output destination must be a file")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("a", encoding="utf-8", newline="\n") as handle:
        for key, value in values.items():
            if not key.isidentifier() or "\n" in value or "\r" in value:
                raise FactoryError("refusing to write an unsafe GitHub Actions output")
            handle.write(f"{key}={value}\n")


def registry_prepare(root: Path, plugin_id: str, channel: str, source_sha: str) -> dict[str, str]:
    """Validate dispatch inputs before the workflow requests a GitHub App token."""

    if channel not in {"beta", "stable"}:
        raise FactoryError("channel must be beta or stable")
    registry = load_registry(root)
    registration = registration_for(registry, plugin_id)
    sha = safe_git_sha(source_sha)
    owner, repository = registration.repository.split("/", 1)
    return {
        "plugin_id": registration.plugin_id,
        "source_sha": sha,
        "source_repository": registration.repository,
        "source_owner": owner,
        "source_repo": repository,
        "source_path": registration.source_path.as_posix(),
        "source_ref": registration.branch_for_channel[channel],
        "registry_path": REGISTRY_RELATIVE_PATH.as_posix(),
    }


def artifact_destination(output: Path, filename: str) -> Path:
    if output.exists() and not output.is_dir():
        raise FactoryError("artifact output must be a directory")
    if output.is_symlink() or getattr(output, "is_junction", lambda: False)():
        raise FactoryError("artifact output must not be a symbolic link")
    output.mkdir(parents=True, exist_ok=True)
    destination = output / filename
    try:
        destination.resolve(strict=False).relative_to(output.resolve(strict=True))
    except ValueError as error:
        raise FactoryError("artifact destination escaped its output directory") from error
    return destination


def copy_or_verify_artifact(source: Path, destination: Path, digest: str) -> None:
    if destination.exists():
        if not destination.is_file() or sha256(destination) != digest:
            raise FactoryError("artifact output already contains different bytes")
        return
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    try:
        shutil.copyfile(source, temporary)
        if sha256(temporary) != digest:
            raise FactoryError("candidate artifact digest changed while writing")
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def record_for_release(document: dict[str, object], release_id: str) -> dict[str, object] | None:
    releases = document.get("releases")
    if not isinstance(releases, list):
        raise AssertionError("validated release document unexpectedly lacks releases")
    for record in releases:
        if isinstance(record, dict) and record.get("releaseId") == release_id:
            return record
    return None


def beta_publish(
    root: Path,
    plugin_id: str,
    source_root: Path,
    source_sha: str,
    factory_repository: str,
    artifact_output: Path,
    publisher: str = "local",
) -> dict[str, str]:
    """Build one exact beta source commit and append/select its immutable release."""

    factory_repository = safe_repository(factory_repository, "factory repository")
    registry = load_registry(root)
    registration = registration_for(registry, plugin_id)
    source_sha = safe_git_sha(source_sha)
    plugin_dir, manifest, _, _ = read_source_plugin(source_root, registration)

    with tempfile.TemporaryDirectory(prefix="xsec-factory-package-") as directory:
        candidate = Path(directory) / "candidate.xsec-plugin"
        write_zip(plugin_dir, candidate)
        digest = sha256(candidate)
        release, filename, tag = candidate_release(registration.plugin_id, manifest, digest, factory_repository)
        artifact = artifact_destination(artifact_output, filename)
        copy_or_verify_artifact(candidate, artifact, digest)

    release_path = release_document_path(root, registration.plugin_id)
    require_write_path_below(root, release_path, "release metadata")
    document = load_release_document(release_path, registration.plugin_id)
    existing = record_for_release(document, str(release["releaseId"]))
    if existing is not None:
        if existing != release:
            raise FactoryError("an immutable release ID already exists with different release metadata")
        selected = existing
    else:
        releases = document["releases"]
        if not isinstance(releases, list):
            raise AssertionError("validated release document unexpectedly lacks releases")
        if any(isinstance(record, dict) and record.get("version") == release["version"] for record in releases):
            raise FactoryError(
                f"plugin {registration.plugin_id} already published different content for version {release['version']}; bump plugin.json.version"
            )
        releases.append(release)
        selected = release
    channels = require_object(document.get("channels"), "release metadata channels")
    channels["beta"] = {"releaseId": selected["releaseId"]}

    snapshot_path = root / "plugins" / registration.plugin_id / "plugin.json"
    require_write_path_below(root, snapshot_path, "plugin snapshot")
    normalized_manifest = archive_bytes(plugin_dir / "plugin.json")
    if snapshot_path.exists() and str(selected["releaseId"]) == str(release["releaseId"]):
        # A retry never silently changes the discoverable snapshot. The
        # candidate ZIP has already proved its normalized manifest bytes.
        existing_snapshot = snapshot_path.read_bytes()
        if existing is not None and existing_snapshot != normalized_manifest:
            raise FactoryError("published plugin snapshot differs from the immutable source manifest")
    atomic_write(snapshot_path, normalized_manifest)
    atomic_write(release_path, stable_json(document))
    append_publication(root, registration, selected, source_sha, "beta", publisher)
    write_marketplace_index(root, registry)

    return {
        "plugin_id": registration.plugin_id,
        "release_id": str(selected["releaseId"]),
        "artifact_path": str(artifact.resolve()),
        "artifact_name": filename,
        "artifact_sha256": digest,
        "release_tag": tag,
        "source_sha": source_sha,
        "source_ref": registration.beta_ref,
        "publication_path": str(publication_path(root, registration.plugin_id).resolve()),
    }


def stable_promote(
    root: Path,
    plugin_id: str,
    source_root: Path,
    source_sha: str,
    beta_release_id: str,
    factory_repository: str,
    publisher: str = "local",
) -> dict[str, str]:
    """Rebuild a main commit and move stable only when it is the selected Beta."""

    factory_repository = safe_repository(factory_repository, "factory repository")
    registry = load_registry(root)
    registration = registration_for(registry, plugin_id)
    source_sha = safe_git_sha(source_sha)
    requested_release_id = beta_release_id
    if not isinstance(requested_release_id, str) or not RELEASE_ID_PATTERN.fullmatch(requested_release_id):
        raise FactoryError("beta release ID must be a canonical releaseId")
    plugin_dir, manifest, _, _ = read_source_plugin(source_root, registration)
    with tempfile.TemporaryDirectory(prefix="xsec-factory-promote-") as directory:
        candidate_path = Path(directory) / "candidate.xsec-plugin"
        write_zip(plugin_dir, candidate_path)
        candidate, _, _ = candidate_release(registration.plugin_id, manifest, sha256(candidate_path), factory_repository)

    release_path = release_document_path(root, registration.plugin_id)
    document = load_release_document(release_path, registration.plugin_id)
    selected = record_for_release(document, requested_release_id)
    if selected is None:
        raise FactoryError("stable promotion target is not an existing immutable Beta release")
    if candidate["releaseId"] != requested_release_id:
        raise FactoryError("main source does not rebuild to the selected Beta releaseId")
    # `releaseId` binds version, engines, target and digest. The URL is not
    # part of it; require the stored artifact set too, so an altered Factory
    # repository slug cannot make promotion mutate a record's delivery URL.
    if candidate != selected:
        raise FactoryError("main source release metadata differs from the selected immutable Beta release")
    channels = require_object(document.get("channels"), "release metadata channels")
    previous = channels.get("stable")
    channels["stable"] = {"releaseId": requested_release_id}
    if previous != channels["stable"]:
        require_write_path_below(root, release_path, "release metadata")
        atomic_write(release_path, stable_json(document))
        # An unchanged retry must leave the Factory worktree byte-for-byte
        # clean. The prior successful promotion already records its immutable
        # source evidence; appending a new uncommitted event here would be
        # silently discarded by the workflow's no-op path.
        append_publication(root, registration, selected, source_sha, "stable", publisher)
    return {
        "plugin_id": registration.plugin_id,
        "release_id": requested_release_id,
        "source_sha": source_sha,
        "source_ref": registration.stable_ref,
        "changed": "true" if previous != channels["stable"] else "false",
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--root", type=Path, default=ROOT, help="Factory repository root")
    result.add_argument(
        "--github-output",
        type=Path,
        default=Path(os.environ["GITHUB_OUTPUT"]) if os.environ.get("GITHUB_OUTPUT") else None,
        help="optional GitHub Actions output file",
    )
    commands = result.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare", help="validate a dispatch before acquiring a GitHub App token")
    prepare.add_argument("--plugin-id", required=True)
    prepare.add_argument("--channel", choices=("beta", "stable"), required=True)
    prepare.add_argument("--source-sha", required=True)
    beta = commands.add_parser("beta", help="build and select a Beta release")
    beta.add_argument("--plugin-id", required=True)
    beta.add_argument("--source-root", type=Path, required=True)
    beta.add_argument("--source-sha", required=True)
    beta.add_argument("--factory-repository", required=True)
    beta.add_argument("--artifact-output", type=Path, required=True)
    beta.add_argument("--publisher", default="local", help="auditable initiating identity")
    stable = commands.add_parser("stable", help="rebuild and promote an existing Beta release")
    stable.add_argument("--plugin-id", required=True)
    stable.add_argument("--source-root", type=Path, required=True)
    stable.add_argument("--source-sha", required=True)
    stable.add_argument("--beta-release-id", required=True)
    stable.add_argument("--factory-repository", required=True)
    stable.add_argument("--publisher", default="local", help="auditable initiating identity")
    return result


def main() -> None:
    arguments = parser().parse_args()
    root = arguments.root.resolve()
    try:
        if arguments.command == "prepare":
            outputs = registry_prepare(root, arguments.plugin_id, arguments.channel, arguments.source_sha)
        elif arguments.command == "beta":
            outputs = beta_publish(
                root,
                arguments.plugin_id,
                arguments.source_root,
                arguments.source_sha,
                arguments.factory_repository,
                arguments.artifact_output,
                arguments.publisher,
            )
        else:
            outputs = stable_promote(
                root,
                arguments.plugin_id,
                arguments.source_root,
                arguments.source_sha,
                arguments.beta_release_id,
                arguments.factory_repository,
                arguments.publisher,
            )
        write_github_outputs(outputs, arguments.github_output)
    except FactoryError as error:
        raise SystemExit(f"Factory publication failed: {error}") from error
    print(" ".join(f"{key}={value}" for key, value in outputs.items()))


if __name__ == "__main__":
    main()
