#!/usr/bin/env python3
"""Build deterministic XSEC plugin artifacts and unsigned marketplace metadata.

The default output is the repository itself, for the protected publishing
workflow. Validation and pull-request jobs must instead supply ``--output-root``
to make a complete, disposable marketplace tree.  Existing immutable release
history is copied into that tree so output follows the same append-only rules
as protected publication.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import tempfile
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MARKETPLACE_RELATIVE_PATH = Path(".agents") / "plugins" / "marketplace.json"
MARKETPLACE = ROOT / MARKETPLACE_RELATIVE_PATH
PLUGIN_ROOT = ROOT / "plugins"
ARTIFACT_DIR_NAME = "artifacts"
EXCLUDED_PARTS = {"__pycache__", ".git", ".xsec-market"}
RELEASE_ID_PATTERN = re.compile(r"^sha256-[0-9a-f]{64}$")


def is_link(path: Path) -> bool:
    """Cover POSIX links and Windows directory junctions before filesystem writes."""

    return path.is_symlink() or getattr(path, "is_junction", lambda: False)()


def stable_json(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def canonical_json(value: object) -> bytes:
    """Bytes used to derive an immutable release identity."""

    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def sha256(value: bytes | Path) -> str:
    digest = hashlib.sha256()
    if isinstance(value, Path):
        with value.open("rb") as handle:
            for chunk in iter(lambda: handle.read(64 * 1024), b""):
                digest.update(chunk)
    else:
        digest.update(value)
    return digest.hexdigest()


def iter_plugin_files(plugin_dir: Path) -> list[Path]:
    """Return package files while refusing links that could escape the source tree."""

    if is_link(plugin_dir):
        raise ValueError(f"plugin directory must not be a symbolic link: {plugin_dir}")
    files: list[Path] = []
    for path in plugin_dir.rglob("*"):
        relative = path.relative_to(plugin_dir)
        if any(part in EXCLUDED_PARTS for part in relative.parts):
            continue
        if is_link(path):
            raise ValueError(f"plugin package must not contain symbolic links: {relative.as_posix()}")
        if path.is_file():
            files.append(path)
    return files


def require_link_free_tree(root: Path, label: str) -> None:
    """Reject a link anywhere in a tree before copytree can follow it."""

    if is_link(root):
        raise ValueError(f"{label} must not be a symbolic link: {root}")
    for path in root.rglob("*"):
        if is_link(path):
            raise ValueError(f"{label} must not contain symbolic links: {path}")


def release_id(version: str, engines: object, artifacts: list[dict[str, object]]) -> str:
    """Return a content-addressed ID that stays stable when artifact URLs move.

    The release record itself remains immutable.  Excluding the URL here lets
    the one-time v1 migration identify an existing legacy artifact instead of
    needlessly creating a second beta release with identical payload bytes.
    """

    descriptor = {
        "version": version,
        "engines": engines,
        "artifacts": sorted(
            [
                {
                    "os": artifact.get("os"),
                    "arch": artifact.get("arch"),
                    "sha256": artifact.get("sha256"),
                }
                for artifact in artifacts
            ],
            key=lambda artifact: (str(artifact["os"]), str(artifact["arch"]), str(artifact["sha256"])),
        ),
    }
    return f"sha256-{sha256(canonical_json(descriptor))}"


def require_release_id(value: object, label: str) -> str:
    if not isinstance(value, str) or not RELEASE_ID_PATTERN.fullmatch(value):
        raise ValueError(f"{label} must be a canonical content-addressed releaseId")
    return value


def require_release_artifacts(value: object, label: str) -> list[dict[str, object]]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{label}.artifacts must be a non-empty list")
    artifacts: list[dict[str, object]] = []
    seen_targets: set[tuple[str, str]] = set()
    for artifact in value:
        if not isinstance(artifact, dict) or not {"os", "arch", "url", "sha256"} <= set(artifact) or set(artifact) - {"os", "arch", "url", "sha256", "signature"}:
            raise ValueError(f"{label}.artifacts must contain objects")
        os_name, arch = artifact.get("os"), artifact.get("arch")
        digest, url = artifact.get("sha256"), artifact.get("url")
        if not isinstance(os_name, str) or not os_name or not isinstance(arch, str) or not arch:
            raise ValueError(f"{label}.artifacts must declare non-empty os and arch")
        if (os_name, arch) in seen_targets:
            raise ValueError(f"{label}.artifacts has duplicate {os_name}/{arch} target")
        seen_targets.add((os_name, arch))
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError(f"{label}.artifacts must contain canonical SHA-256 values")
        if not isinstance(url, str) or not url:
            raise ValueError(f"{label}.artifacts must contain non-empty URLs")
        normalized: dict[str, object] = {"os": os_name, "arch": arch, "url": url, "sha256": digest}
        if "signature" in artifact:
            signature = artifact["signature"]
            if not isinstance(signature, str) or not signature:
                raise ValueError(f"{label}.artifacts signature must be a non-empty string")
            normalized["signature"] = signature
        artifacts.append(normalized)
    return artifacts


def require_release_engines(value: object, label: str) -> dict[str, str]:
    """Accept the exact engine contract understood by every Desktop client.

    ``releaseId`` is recomputed by Desktop, so allowing publisher-only engine
    keys would make a signed release index that Desktop necessarily rejects.
    Keep the published schema deliberately small until both sides support an
    explicit schema evolution.
    """

    if not isinstance(value, dict) or set(value) != {"xsec", "pluginApi"}:
        raise ValueError(f"{label}.engines must contain only xsec and pluginApi")
    xsec, plugin_api = value.get("xsec"), value.get("pluginApi")
    if not isinstance(xsec, str) or not xsec or not isinstance(plugin_api, str) or not plugin_api:
        raise ValueError(f"{label}.engines must contain non-empty xsec and pluginApi strings")
    return {"xsec": xsec, "pluginApi": plugin_api}


def require_release_record(value: object, plugin_id: str, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != {"releaseId", "version", "engines", "artifacts"}:
        raise ValueError(f"{label} must contain only releaseId, version, engines and artifacts")
    version = safe_artifact_component(value.get("version"), f"{label}.version")
    engines = require_release_engines(value.get("engines"), label)
    artifacts = require_release_artifacts(value.get("artifacts"), label)
    calculated = release_id(version, engines, artifacts)
    supplied = require_release_id(value.get("releaseId"), label)
    if supplied != calculated:
        raise ValueError(f"{label}.releaseId does not match immutable release content")
    return {
        "releaseId": supplied,
        "version": version,
        "engines": engines,
        "artifacts": artifacts,
    }


def migrate_v1_release_document(value: dict[str, object], plugin_id: str) -> dict[str, object]:
    """Turn legacy per-channel release records into v2 immutable records."""

    if value.get("schemaVersion") != 1 or value.get("pluginId") != plugin_id:
        raise ValueError(f"release metadata for {plugin_id} has an invalid legacy schemaVersion or pluginId")
    legacy_releases = value.get("releases")
    if not isinstance(legacy_releases, list) or not legacy_releases:
        raise ValueError(f"release metadata for {plugin_id} must have at least one legacy release")
    releases: list[dict[str, object]] = []
    release_ids: set[str] = set()
    release_versions: dict[str, str] = {}
    channel_targets: dict[str, str] = {}
    for index, legacy in enumerate(legacy_releases):
        label = f"legacy release metadata for {plugin_id} at index {index}"
        if not isinstance(legacy, dict) or set(legacy) != {"version", "channel", "engines", "artifacts"}:
            raise ValueError(f"{label} has an unsupported schema")
        version = safe_artifact_component(legacy.get("version"), f"{label}.version")
        channel = legacy.get("channel")
        engines = legacy.get("engines")
        if not isinstance(channel, str) or channel not in {"beta", "stable"}:
            raise ValueError(f"{label}.channel must be beta or stable")
        engines = require_release_engines(engines, label)
        artifacts = require_release_artifacts(legacy.get("artifacts"), label)
        identifier = release_id(version, engines, artifacts)
        prior_release_id = release_versions.get(version)
        if prior_release_id is not None and prior_release_id != identifier:
            raise ValueError(
                f"legacy release metadata for {plugin_id} has multiple immutable releases for version {version}"
            )
        release_versions[version] = identifier
        if identifier not in release_ids:
            release_ids.add(identifier)
            releases.append(
                {
                    "releaseId": identifier,
                    "version": version,
                    "engines": engines,
                    "artifacts": artifacts,
                }
            )
        channel_targets[channel] = identifier
    stable = channel_targets.get("stable")
    if stable is None:
        raise ValueError(f"legacy release metadata for {plugin_id} must select a stable release")
    return {
        "schemaVersion": 2,
        "pluginId": plugin_id,
        "releases": releases,
        "channels": {
            "beta": {"releaseId": channel_targets.get("beta", stable)},
            "stable": {"releaseId": stable},
        },
    }


def load_release_document(release_path: Path, plugin_id: str) -> dict[str, object]:
    """Load v2, migrating a checked-in v1 document in memory when needed."""

    # Test links before exists(): a broken link reports non-existence on some
    # platforms and must not be mistaken for a fresh release document.
    if is_link(release_path) or is_link(release_path.parent):
        raise ValueError(f"release metadata for {plugin_id} must not use symbolic links")
    if not release_path.exists():
        return {
            "schemaVersion": 2,
            "pluginId": plugin_id,
            "releases": [],
            "channels": {"beta": {"releaseId": None}, "stable": None},
        }
    try:
        value = json.loads(release_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"release metadata for {plugin_id} cannot be read") from error
    if not isinstance(value, dict):
        raise ValueError(f"release metadata for {plugin_id} must be an object")
    if value.get("schemaVersion") == 1:
        return migrate_v1_release_document(value, plugin_id)
    if value.get("schemaVersion") != 2 or value.get("pluginId") != plugin_id:
        raise ValueError(f"release metadata for {plugin_id} has an invalid schemaVersion or pluginId")
    if set(value) != {"schemaVersion", "pluginId", "releases", "channels"}:
        raise ValueError(f"release metadata for {plugin_id} has an unsupported v2 schema")
    items = value.get("releases")
    if not isinstance(items, list):
        raise ValueError(f"release metadata for {plugin_id}.releases must be a list")
    releases = [require_release_record(item, plugin_id, f"release metadata for {plugin_id} at index {index}") for index, item in enumerate(items)]
    identifiers = [item["releaseId"] for item in releases]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError(f"release metadata for {plugin_id} contains duplicate releaseIds")
    versions = [item["version"] for item in releases]
    if len(versions) != len(set(versions)):
        raise ValueError(f"release metadata for {plugin_id} contains multiple immutable releases for one version")
    channels = value.get("channels")
    if not isinstance(channels, dict) or set(channels) != {"beta", "stable"}:
        raise ValueError(f"release metadata for {plugin_id}.channels must contain beta and stable pointers")
    normalized_channels: dict[str, object] = {}
    beta = channels.get("beta")
    if not isinstance(beta, dict) or set(beta) != {"releaseId"}:
        raise ValueError(f"release metadata for {plugin_id}.beta must contain only releaseId")
    beta_target = beta.get("releaseId")
    if beta_target is not None:
        beta_target = require_release_id(beta_target, f"release metadata for {plugin_id}.beta")
        if beta_target not in identifiers:
            raise ValueError(f"release metadata for {plugin_id}.beta points at an unknown release")
    normalized_channels["beta"] = {"releaseId": beta_target}

    stable = channels.get("stable")
    if stable is None:
        normalized_channels["stable"] = None
    else:
        pointer = stable
        if not isinstance(pointer, dict) or set(pointer) != {"releaseId"}:
            raise ValueError(f"release metadata for {plugin_id}.stable must be null or contain only releaseId")
        target = pointer.get("releaseId")
        if target is None:
            raise ValueError(f"release metadata for {plugin_id}.stable must use null, not a null releaseId object")
        target = require_release_id(target, f"release metadata for {plugin_id}.stable")
        if target not in identifiers:
            raise ValueError(f"release metadata for {plugin_id}.stable points at an unknown release")
        normalized_channels["stable"] = {"releaseId": target}
    return {"schemaVersion": 2, "pluginId": plugin_id, "releases": releases, "channels": normalized_channels}


def write_zip(plugin_dir: Path, destination: Path) -> None:
    files = iter_plugin_files(plugin_dir)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(files, key=lambda item: item.relative_to(plugin_dir).as_posix()):
            info = zipfile.ZipInfo(path.relative_to(plugin_dir).as_posix())
            info.date_time = (2024, 1, 1, 0, 0, 0)
            info.compress_type = zipfile.ZIP_DEFLATED
            # Do not inherit Windows/POSIX host defaults into an artifact whose
            # digest will be bound by a cross-platform KMS sidecar.
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, path.read_bytes())


def require_safe_marketplace_path() -> None:
    """Reject a linked marketplace file or an ancestor before it is read/copied."""

    current = MARKETPLACE
    for _ in MARKETPLACE_RELATIVE_PATH.parts:
        if is_link(current):
            raise ValueError(f"marketplace metadata path must not contain symbolic links: {current}")
        current = current.parent


def safe_artifact_component(value: object, label: str) -> str:
    """Return a manifest value only when it cannot alter an artifact pathname."""

    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or value.endswith((".", " "))
        or value in {".", ".."}
        or "\x00" in value
        or any(character in value for character in ("/", "\\", ":"))
    ):
        raise ValueError(f"{label} must be a non-empty safe filename component")
    return value


def path_below(directory: Path, filename: str, label: str) -> Path:
    """Defend the output boundary even if a future filename format changes."""

    candidate = directory / filename
    try:
        candidate.resolve(strict=False).relative_to(directory.resolve(strict=False))
    except ValueError as error:
        raise ValueError(f"{label} must remain below {directory}") from error
    return candidate


def marketplace_entries() -> list[dict[str, object]]:
    require_safe_marketplace_path()
    value = json.loads(MARKETPLACE.read_text(encoding="utf-8"))
    entries = value.get("plugins")
    if not isinstance(entries, list):
        raise ValueError("marketplace.json plugins must be a list")
    return entries


def copy_source_tree(output_root: Path) -> None:
    """Create a publishable source snapshot without copying generated output."""

    if is_link(PLUGIN_ROOT):
        raise ValueError(f"plugin root must not be a symbolic link: {PLUGIN_ROOT}")
    if not PLUGIN_ROOT.is_dir():
        raise ValueError(f"plugin root is unavailable: {PLUGIN_ROOT}")
    require_safe_marketplace_path()
    if output_root.exists() and any(output_root.iterdir()):
        raise ValueError("--output-root must be empty when it is not the repository root")
    output_root.mkdir(parents=True, exist_ok=True)
    destination_marketplace = output_root / MARKETPLACE_RELATIVE_PATH
    destination_marketplace.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(MARKETPLACE, destination_marketplace)
    for source_dir in PLUGIN_ROOT.iterdir():
        if not source_dir.is_dir():
            continue
        if is_link(source_dir):
            raise ValueError(f"plugin directory must not be a symbolic link: {source_dir}")
        # `copytree` follows directory links by default. Validate every nested
        # member before copying so a source-tree link cannot make the temporary
        # validation tree include files outside the plugin package.  Unlike the
        # package archive, a disposable publication must retain existing
        # immutable .xsec-market history and artifacts.
        require_link_free_tree(source_dir, "plugin source tree")
        shutil.copytree(
            source_dir,
            output_root / "plugins" / source_dir.name,
            ignore=shutil.ignore_patterns("__pycache__", ".git", "*.sig", "*.sig.jws.json"),
        )


def clean_generated_output(output_root: Path) -> None:
    """Remove stale signatures without deleting immutable releases or artifacts.

    Older versions removed every `.xsec-market` directory for `--clean`.  That
    made publishing a new version erase the only artifact a stable pointer
    could reference, so it is intentionally no longer a release-history clean.
    """
    output_plugins = output_root / "plugins"
    if is_link(output_plugins):
        raise ValueError(f"generated plugin root must not be a symbolic link: {output_plugins}")
    if not output_plugins.exists():
        return
    if not output_plugins.is_dir():
        raise ValueError(f"generated plugin root is unavailable: {output_plugins}")
    for plugin_dir in output_plugins.iterdir():
        if is_link(plugin_dir):
            raise ValueError(f"generated plugin directory must not be a symbolic link: {plugin_dir}")
        if not plugin_dir.is_dir():
            continue
        release_root = plugin_dir / ".xsec-market"
        if not release_root.exists():
            continue
        if is_link(release_root):
            raise ValueError(f"generated output path must not be a symbolic link: {release_root}")
        try:
            release_root.resolve(strict=True).relative_to(output_plugins.resolve(strict=True))
        except (OSError, ValueError) as error:
            raise ValueError(f"generated output path must remain below plugins/: {release_root}") from error
        for suffix in (".sig", ".sig.jws.json"):
            release_root.joinpath("releases.json").with_name("releases.json" + suffix).unlink(missing_ok=True)
    marketplace_path = output_root / MARKETPLACE_RELATIVE_PATH
    for suffix in (".sig", ".sig.jws.json"):
        marketplace_path.with_name(marketplace_path.name + suffix).unlink(missing_ok=True)


def build_plugin(source_plugin_dir: Path, output_plugin_dir: Path) -> None:
    manifest = json.loads((source_plugin_dir / "plugin.json").read_text(encoding="utf-8"))
    plugin_id = safe_artifact_component(manifest.get("name"), "plugin manifest name")
    version = safe_artifact_component(manifest.get("version"), "plugin manifest version")
    release_root = output_plugin_dir / ".xsec-market"
    artifact_dir = release_root / ARTIFACT_DIR_NAME
    release_path = release_root / "releases.json"
    release = load_release_document(release_path, plugin_id)
    engines = require_release_engines(
        manifest["extensions"]["com.xsec.desktop"]["engines"],
        f"plugin manifest {plugin_id}",
    )

    # Hash the deterministic archive before deriving the filename.  The digest
    # is part of the filename so two code revisions with the same manifest
    # version cannot overwrite each other.
    with tempfile.TemporaryDirectory(prefix="xsec-market-artifact-") as directory:
        candidate = Path(directory) / "candidate.xsec-plugin"
        write_zip(source_plugin_dir, candidate)
        candidate_digest = sha256(candidate)
        artifact_name = f"{plugin_id}-{version}-sha256-{candidate_digest[:16]}-any-any.xsec-plugin"
        artifact = path_below(artifact_dir, artifact_name, "artifact path")
        candidate_artifacts = [
            {
                "os": "any",
                "arch": "any",
                "url": f"{ARTIFACT_DIR_NAME}/{artifact_name}",
                "sha256": candidate_digest,
            }
        ]
        candidate_release_id = release_id(version, engines, candidate_artifacts)

        releases = release["releases"]
        if not isinstance(releases, list):  # guarded by load_release_document
            raise ValueError(f"release metadata for {plugin_id} has invalid releases")
        existing: dict[str, dict[str, object]] = {}
        for item in releases:
            if not isinstance(item, dict):
                raise ValueError(f"release metadata for {plugin_id} has an invalid release")
            existing[str(item["releaseId"])] = item
        target = existing.get(candidate_release_id)
        if target is None:
            if any(item.get("version") == version for item in existing.values()):
                raise ValueError(
                    f"release metadata for {plugin_id} already contains immutable content for version {version}; bump plugin.json before publishing different content"
                )
            artifact_dir.mkdir(parents=True, exist_ok=True)
            if artifact.exists():
                if sha256(artifact) != candidate_digest:
                    raise ValueError(f"immutable artifact path already contains different bytes: {artifact}")
            else:
                shutil.copyfile(candidate, artifact)
            target = {
                "releaseId": candidate_release_id,
                "version": version,
                "engines": engines,
                "artifacts": candidate_artifacts,
            }
            releases.append(target)

    channels = release["channels"]
    if not isinstance(channels, dict):  # guarded by load_release_document
        raise ValueError(f"release metadata for {plugin_id} has invalid channels")
    # Only the beta pointer moves during automatic main publication.  Stable
    # promotion uses scripts/promote_release.py and reuses this exact record.
    # In particular, a brand-new plugin begins as beta-only: publishing its
    # first artifact must not silently make it available on the stable channel.
    channels["beta"] = {"releaseId": target["releaseId"]}

    release_path.parent.mkdir(parents=True, exist_ok=True)
    release_path.write_bytes(stable_json(release))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--clean", action="store_true")
    parser.add_argument(
        "--output-root",
        type=Path,
        default=ROOT,
        help="destination marketplace root; use an empty temporary directory for validation",
    )
    args = parser.parse_args()

    output_root = args.output_root.resolve()
    root = ROOT.resolve()
    if output_root != root:
        try:
            output_root.relative_to(root)
        except ValueError:
            pass
        else:
            raise ValueError("--output-root must be outside the repository root")
        copy_source_tree(output_root)
    require_safe_marketplace_path()
    if args.clean:
        clean_generated_output(output_root)

    entries = marketplace_entries()
    for entry in entries:
        source = entry.get("source") if isinstance(entry, dict) else None
        relative_path = source.get("path") if isinstance(source, dict) else None
        if not isinstance(relative_path, str):
            raise ValueError("every marketplace entry needs source.path")
        source_candidate = ROOT / relative_path
        if is_link(source_candidate):
            raise ValueError(f"plugin source must not be a symbolic link: {relative_path}")
        source_plugin_dir = source_candidate.resolve()
        try:
            source_plugin_dir.relative_to(PLUGIN_ROOT.resolve())
        except ValueError as error:
            raise ValueError(f"plugin source must remain below plugins/: {relative_path}") from error
        output_plugin_dir = output_root / source_plugin_dir.relative_to(ROOT)
        build_plugin(source_plugin_dir, output_plugin_dir)


if __name__ == "__main__":
    main()
