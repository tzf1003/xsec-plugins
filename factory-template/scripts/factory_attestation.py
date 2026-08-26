#!/usr/bin/env python3
"""Materialize and verify immutable GitHub Release provenance attestations.

The user Factory intentionally has no private signing key.  Instead, its
production-gated workflows upload one canonical attestation asset for every
external-source evidence event.  A pull request can edit the local evidence
JSON, but it cannot make GitHub's release asset have matching bytes without
the protected workflow's write capability.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from factory_core import (
    FactoryError,
    MAX_PUBLICATION_ATTESTATION_BYTES,
    RELEASE_ID_PATTERN,
    is_link,
    load_registry,
    publication_attestation_bytes,
    publication_attestation_name,
    publication_path,
    read_json,
    release_tag,
    require_object,
    safe_git_sha,
    safe_repository,
    sha256,
)


ROOT = Path(__file__).resolve().parents[1]
GH_TIMEOUT_SECONDS = 45


def write_github_outputs(values: dict[str, str], destination: Path | None) -> None:
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


def require_output_directory(path: Path, *, empty: bool) -> Path:
    if path.exists():
        if is_link(path) or not path.is_dir():
            raise FactoryError("publication attestation output must be a regular directory")
    else:
        path.mkdir(parents=True, exist_ok=False)
        if is_link(path) or not path.is_dir():
            raise FactoryError("publication attestation output must be a regular directory")
    resolved = path.resolve(strict=True)
    if empty and any(resolved.iterdir()):
        raise FactoryError("publication attestation download output must be empty")
    return resolved


def output_path(directory: Path, filename: str) -> Path:
    if not filename or "/" in filename or "\\" in filename:
        raise FactoryError("publication attestation filename is unsafe")
    candidate = directory / filename
    if is_link(candidate):
        raise FactoryError("publication attestation output must not be a symbolic link")
    try:
        candidate.resolve(strict=False).relative_to(directory.resolve(strict=True))
    except (OSError, ValueError) as error:
        raise FactoryError("publication attestation output escaped its directory") from error
    return candidate


def write_exact(path: Path, payload: bytes) -> None:
    if len(payload) > MAX_PUBLICATION_ATTESTATION_BYTES:
        raise FactoryError("publication attestation exceeds the size limit")
    if path.exists():
        if not path.is_file() or is_link(path):
            raise FactoryError("publication attestation output is unavailable")
        if path.read_bytes() != payload:
            raise FactoryError("publication attestation output already contains different bytes")
        return
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def event_fields(event: dict[str, object], label: str) -> tuple[str, str, str]:
    channel = event.get("channel")
    release_id = event.get("releaseId")
    source = require_object(event.get("source"), f"{label}.source")
    source_sha = safe_git_sha(source.get("sha"), f"{label}.source.sha")
    if channel not in {"beta", "stable"}:
        raise FactoryError(f"{label}.channel must be beta or stable")
    if not isinstance(release_id, str) or not RELEASE_ID_PATTERN.fullmatch(release_id):
        raise FactoryError(f"{label}.releaseId must be canonical")
    return channel, release_id, source_sha


def publication_events(root: Path) -> list[tuple[object, dict[str, object], str, str, str]]:
    """Read every registered evidence event without trusting a PR-provided URL."""

    registry = load_registry(root)
    result: list[tuple[object, dict[str, object], str, str, str]] = []
    for registration in sorted(registry.plugins, key=lambda item: item.plugin_id):
        path = publication_path(root, registration.plugin_id)
        if not path.exists():
            continue
        if is_link(path) or not path.is_file():
            raise FactoryError(f"publication evidence for {registration.plugin_id} is unavailable")
        document = read_json(path, f"publication evidence for {registration.plugin_id}")
        events = document.get("events")
        if not isinstance(events, list):
            raise FactoryError(f"publication evidence for {registration.plugin_id}.events must be a list")
        for index, raw_event in enumerate(events):
            event = require_object(raw_event, f"publication evidence for {registration.plugin_id} event {index}")
            channel, release_id, source_sha = event_fields(
                event,
                f"publication evidence for {registration.plugin_id} event {index}",
            )
            result.append((registration, event, channel, release_id, source_sha))
    return result


def attestation_spec(registration, event: dict[str, object]) -> tuple[str, str, bytes, str]:
    """Return tag, filename, bytes and SHA-256 for one exact evidence event."""

    _, release_id, _ = event_fields(event, f"publication evidence for {registration.plugin_id}")
    payload = publication_attestation_bytes(registration, event)
    if len(payload) > MAX_PUBLICATION_ATTESTATION_BYTES:
        raise FactoryError("publication attestation exceeds the size limit")
    return (
        release_tag(registration.plugin_id, release_id),
        publication_attestation_name(registration, event),
        payload,
        sha256(payload),
    )


def matching_event(root: Path, plugin_id: str, channel: str, release_id: str, source_sha: str):
    registry = load_registry(root)
    registration = next((item for item in registry.plugins if item.plugin_id == plugin_id), None)
    if registration is None:
        raise FactoryError(f"plugin {plugin_id} is not registered in this Marketplace Factory")
    source_sha = safe_git_sha(source_sha)
    if channel not in {"beta", "stable"}:
        raise FactoryError("publication channel must be beta or stable")
    if not RELEASE_ID_PATTERN.fullmatch(release_id):
        raise FactoryError("publication release ID must be canonical")
    path = publication_path(root, registration.plugin_id)
    document = read_json(path, f"publication evidence for {registration.plugin_id}")
    events = document.get("events")
    if not isinstance(events, list):
        raise FactoryError(f"publication evidence for {registration.plugin_id}.events must be a list")
    matches: list[dict[str, object]] = []
    for index, raw_event in enumerate(events):
        event = require_object(raw_event, f"publication evidence event {index}")
        event_channel, event_release_id, event_source_sha = event_fields(event, f"publication evidence event {index}")
        if (event_channel, event_release_id, event_source_sha) == (channel, release_id, source_sha):
            matches.append(event)
    if len(matches) != 1:
        raise FactoryError("requested immutable publication evidence event is unavailable or duplicated")
    return registration, matches[0]


def materialize(root: Path, plugin_id: str, channel: str, release_id: str, source_sha: str, output_directory: Path) -> dict[str, str]:
    registration, event = matching_event(root, plugin_id, channel, release_id, source_sha)
    tag, filename, payload, digest = attestation_spec(registration, event)
    destination = output_path(require_output_directory(output_directory, empty=False), filename)
    write_exact(destination, payload)
    return {
        "plugin_id": registration.plugin_id,
        "release_tag": tag,
        "attestation_name": filename,
        "attestation_path": str(destination),
        "attestation_sha256": digest,
    }


def gh_download(repository: str, release_tag_value: str, asset_name: str, directory: Path) -> None:
    """Download one fixed GitHub Release asset without consuming a PR URL.

    The GitHub CLI receives a fixed GitHub.com host, validated owner/repository,
    deterministic release tag and deterministic asset name. It never receives
    a browser/download URL from Factory metadata, and runs without a user GH
    config directory. The bytes still undergo an independent exact comparison
    below, so a redirected CDN response cannot authenticate different content.
    """

    gh = shutil.which("gh")
    if gh is None:
        raise FactoryError("GitHub CLI is required to fetch publication attestations")
    token = os.environ.get("GH_TOKEN")
    if not token:
        raise FactoryError("GH_TOKEN is required to fetch publication attestations")
    with tempfile.TemporaryDirectory(prefix="xsec-factory-gh-config-") as config_directory:
        environment = {
            key: value
            for key, value in os.environ.items()
            if key not in {"GH_HOST", "GH_REPO", "GH_CONFIG_DIR", "GITHUB_REPOSITORY"}
        }
        environment["GH_TOKEN"] = token
        environment["GH_HOST"] = "github.com"
        environment["GH_CONFIG_DIR"] = config_directory
        command = [
            gh,
            "release",
            "download",
            release_tag_value,
            "--repo",
            f"github.com/{repository}",
            "--pattern",
            asset_name,
            "--dir",
            str(directory),
        ]
        try:
            completed = subprocess.run(
                command,
                cwd=directory,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=GH_TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise FactoryError("immutable GitHub Release provenance asset is unavailable") from error
    if completed.returncode != 0:
        raise FactoryError("immutable GitHub Release provenance asset is unavailable")


def download_all(root: Path, factory_repository: str, output_directory: Path) -> dict[str, str]:
    repository = safe_repository(factory_repository, "factory repository")
    output = require_output_directory(output_directory, empty=True)
    expected: dict[str, bytes] = {}
    tags: dict[str, str] = {}
    for registration, event, _, _, _ in publication_events(root):
        tag, filename, payload, _ = attestation_spec(registration, event)
        existing = expected.get(filename)
        if existing is not None and existing != payload:
            raise FactoryError("publication attestation filename collision")
        expected[filename] = payload
        tags[filename] = tag
    for filename, payload in expected.items():
        gh_download(repository, tags[filename], filename, output)
        destination = output_path(output, filename)
        if is_link(destination) or not destination.is_file():
            raise FactoryError("immutable GitHub Release provenance asset is unavailable")
        if destination.stat().st_size > MAX_PUBLICATION_ATTESTATION_BYTES:
            raise FactoryError("immutable GitHub Release provenance asset exceeds the size limit")
        actual = destination.read_bytes()
        if sha256(actual) != sha256(payload) or actual != payload:
            raise FactoryError("immutable GitHub Release provenance asset does not match its Factory evidence")
    actual_names = {candidate.name for candidate in output.iterdir() if candidate.is_file() and not is_link(candidate)}
    if actual_names != set(expected) or any(is_link(candidate) or not candidate.is_file() for candidate in output.iterdir()):
        raise FactoryError("publication attestation download output contains unexpected files")
    return {"attestation_root": str(output), "attestation_count": str(len(expected))}


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--root", type=Path, default=ROOT)
    result.add_argument(
        "--github-output",
        type=Path,
        default=Path(os.environ["GITHUB_OUTPUT"]) if os.environ.get("GITHUB_OUTPUT") else None,
    )
    commands = result.add_subparsers(dest="command", required=True)
    materialize_parser = commands.add_parser("materialize", help="write the canonical asset for one recorded event")
    materialize_parser.add_argument("--plugin-id", required=True)
    materialize_parser.add_argument("--channel", choices=("beta", "stable"), required=True)
    materialize_parser.add_argument("--release-id", required=True)
    materialize_parser.add_argument("--source-sha", required=True)
    materialize_parser.add_argument("--output-directory", type=Path, required=True)
    download_parser = commands.add_parser("download", help="download and verify every current release attestation")
    download_parser.add_argument("--factory-repository", required=True)
    download_parser.add_argument("--output-directory", type=Path, required=True)
    return result


def main() -> None:
    arguments = parser().parse_args()
    root = arguments.root.resolve()
    try:
        if arguments.command == "materialize":
            outputs = materialize(
                root,
                arguments.plugin_id,
                arguments.channel,
                arguments.release_id,
                arguments.source_sha,
                arguments.output_directory.resolve(),
            )
        else:
            outputs = download_all(
                root,
                arguments.factory_repository,
                arguments.output_directory.resolve(),
            )
        write_github_outputs(outputs, arguments.github_output)
    except FactoryError as error:
        raise SystemExit(f"Factory publication attestation failed: {error}") from error
    print(" ".join(f"{key}={value}" for key, value in outputs.items()))


if __name__ == "__main__":
    main()
