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
import os
import re
import shutil
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

from native_sidecars import (
    RECIPES,
    NativeSidecarRecipe,
    parse_native_sidecar_inputs,
    provenance_for_inputs,
    recipe_for_source,
    require_inputs,
    staged_plugin,
    validate_provenance,
)


ROOT = Path(__file__).resolve().parents[1]
MARKETPLACE_RELATIVE_PATH = Path(".agents") / "plugins" / "marketplace.json"
MARKETPLACE = ROOT / MARKETPLACE_RELATIVE_PATH
SNAPSHOT_ROOT_RELATIVE_PATH = Path(".xsec-factory") / "snapshots"
PLUGIN_ROOT = ROOT / SNAPSHOT_ROOT_RELATIVE_PATH
ARTIFACT_DIR_NAME = "artifacts"
# Dependency installs are not a reproducible source input. The external
# Factory snapshot already excludes node_modules, so the shared deterministic
# packager must do the same when a Stable source checkout is hashed directly.
EXCLUDED_PARTS = {"__pycache__", ".git", ".xsec-market", "node_modules"}
RELEASE_ID_PATTERN = re.compile(r"^sha256-[0-9a-f]{64}$")
TEXT_ARCHIVE_SUFFIXES = frozenset({
    ".cjs", ".css", ".html", ".htm", ".js", ".json", ".jsx", ".md",
    ".mjs", ".ps1", ".sh", ".svg", ".toml", ".ts", ".tsx", ".txt",
    ".xml", ".yaml", ".yml",
})
MAX_PACKAGE_ENTRIES = 10_000
MAX_PACKAGE_FILE_BYTES = 64 * 1024 * 1024
MAX_PACKAGE_TOTAL_BYTES = 128 * 1024 * 1024
MAX_SOURCE_TREE_ENTRIES = MAX_PACKAGE_ENTRIES
# Keep this preflight in lockstep with Desktop's package installer. Source
# repositories are authored on many platforms, while the immutable artifact
# must extract unambiguously on Windows and macOS too.
WINDOWS_FORBIDDEN_COMPONENT_CHARACTERS = frozenset('<>"\\|?*')
WINDOWS_RESERVED_DEVICE_NAMES = frozenset({
    "con", "prn", "aux", "nul", "clock$", "conin$", "conout$",
    *(f"com{number}" for number in range(1, 10)),
    *(f"lpt{number}" for number in range(1, 10)),
})


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
    total_bytes = 0
    source_entries = 0
    # Prune ignored source trees before visiting their contents. A committed
    # node_modules/.git tree is deliberately not a package input and must not
    # turn preflight itself into a privileged runner DoS.
    for current, directories, names in os.walk(plugin_dir, topdown=True, followlinks=False):
        current_path = Path(current)
        retained_directories: list[str] = []
        for name in directories:
            path = current_path / name
            relative = path.relative_to(plugin_dir)
            if name in EXCLUDED_PARTS:
                continue
            if is_link(path):
                raise ValueError(f"plugin package must not contain symbolic links: {relative.as_posix()}")
            source_entries += 1
            if source_entries > MAX_SOURCE_TREE_ENTRIES:
                raise ValueError("plugin source tree contains too many files or directories")
            retained_directories.append(name)
        directories[:] = retained_directories
        for name in names:
            path = current_path / name
            relative = path.relative_to(plugin_dir)
            if any(part in EXCLUDED_PARTS for part in relative.parts):
                continue
            if is_link(path):
                raise ValueError(f"plugin package must not contain symbolic links: {relative.as_posix()}")
            source_entries += 1
            if source_entries > MAX_SOURCE_TREE_ENTRIES:
                raise ValueError("plugin source tree contains too many files or directories")
            if not path.is_file():
                continue
            if len(files) >= MAX_PACKAGE_ENTRIES:
                raise ValueError("plugin package contains too many files")
            size = path.stat().st_size
            if size > MAX_PACKAGE_FILE_BYTES:
                raise ValueError(f"plugin package file is too large: {relative.as_posix()}")
            total_bytes += size
            if total_bytes > MAX_PACKAGE_TOTAL_BYTES:
                raise ValueError("plugin package is too large")
            files.append(path)
    require_portable_package_paths(plugin_dir, files)
    return files


def portable_target_filesystem_path(relative: str) -> str:
    """Return Desktop's normalized target path or reject an unsafe member name."""

    if not relative.isascii():
        raise ValueError(f"plugin package path must use portable ASCII characters: {relative}")
    parts = relative.split("/")
    if not parts or any(not part or part in {".", ".."} for part in parts):
        raise ValueError(f"plugin package path is unsafe: {relative}")
    normalized_parts: list[str] = []
    for part in parts:
        if part.endswith((".", " ")):
            raise ValueError(f"plugin package path has a Windows trailing-dot or trailing-space alias: {relative}")
        if ":" in part:
            raise ValueError(f"plugin package path has a Windows NTFS stream alias: {relative}")
        if any(ord(character) <= 0x1F or character in WINDOWS_FORBIDDEN_COMPONENT_CHARACTERS for character in part):
            raise ValueError(f"plugin package path has a Windows-forbidden character: {relative}")
        device_name = part.split(".", 1)[0].lower()
        if device_name in WINDOWS_RESERVED_DEVICE_NAMES:
            raise ValueError(f"plugin package path has a Windows reserved device name: {relative}")
        normalized_parts.append(part.lower())
    return "/".join(normalized_parts)


def require_portable_package_paths(plugin_dir: Path, files: list[Path]) -> None:
    """Match Desktop's portable ZIP-name admission policy before signing bytes.

    Source files have no explicit ZIP directory entries, so every normalized
    member is a file. Detect both exact aliases and a file used as the
    case-folded ancestor of another member before any copy or ZIP work.
    """

    target_paths: dict[str, str] = {}
    for path in files:
        relative = path.relative_to(plugin_dir).as_posix()
        target = portable_target_filesystem_path(relative)
        existing = target_paths.get(target)
        if existing is not None:
            raise ValueError(
                "plugin package paths collide on case-insensitive filesystems: "
                f"{existing} and {relative}"
            )
        target_paths[target] = relative
    for target, relative in target_paths.items():
        parts = target.split("/")
        for length in range(1, len(parts)):
            ancestor = "/".join(parts[:length])
            existing = target_paths.get(ancestor)
            if existing is not None:
                raise ValueError(
                    "plugin package paths have a file/directory collision on case-insensitive filesystems: "
                    f"{existing} and {relative}"
                )


def archive_bytes(path: Path) -> bytes:
    """Return cross-platform-stable bytes for a package member.

    Git may check UTF-8 source files out with CRLF on Windows even though the
    protected Linux publisher sees LF.  Package text therefore needs one
    explicit line-ending representation; otherwise an unchanged source commit
    produces a different immutable artifact SHA-256 locally and in CI.

    Only an explicit set of source-text filename suffixes participates in this
    rule. Every other member is an arbitrary binary payload and remains
    byte-for-byte intact, even when it happens to be valid UTF-8 (for example,
    a PDF with CRLF line endings).
    """

    value = path.read_bytes()
    if path.suffix.lower() not in TEXT_ARCHIVE_SUFFIXES or b"\r\n" not in value:
        return value
    try:
        value.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"text package member must be UTF-8: {path}") from error
    return value.replace(b"\r\n", b"\n")


def require_link_free_tree(root: Path, label: str) -> None:
    """Reject a link anywhere in a tree before copytree can follow it."""

    if is_link(root):
        raise ValueError(f"{label} must not be a symbolic link: {root}")
    for path in root.rglob("*"):
        if is_link(path):
            raise ValueError(f"{label} must not contain symbolic links: {path}")


def release_id(
    version: str,
    engines: object,
    artifacts: list[dict[str, object]],
    native_sidecar_provenance: dict[str, object] | None = None,
) -> str:
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
    if native_sidecar_provenance is not None:
        descriptor["nativeSidecarProvenance"] = native_sidecar_provenance
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
    allowed = {"releaseId", "version", "engines", "artifacts", "nativeSidecarProvenance"}
    if not isinstance(value, dict) or not {"releaseId", "version", "engines", "artifacts"} <= set(value) or set(value) - allowed:
        raise ValueError(f"{label} must contain only releaseId, version, engines, artifacts and optional nativeSidecarProvenance")
    version = safe_artifact_component(value.get("version"), f"{label}.version")
    engines = require_release_engines(value.get("engines"), label)
    artifacts = require_release_artifacts(value.get("artifacts"), label)
    provenance = value.get("nativeSidecarProvenance")
    if provenance is not None and not isinstance(provenance, dict):
        raise ValueError(f"{label}.nativeSidecarProvenance must be an object")
    recipe = RECIPES.get(plugin_id)
    if provenance is not None:
        if recipe is None:
            raise ValueError(f"{label}.nativeSidecarProvenance is not allowed for {plugin_id}")
        provenance = validate_provenance(recipe, provenance)
    calculated = release_id(version, engines, artifacts, provenance)
    supplied = require_release_id(value.get("releaseId"), label)
    if supplied != calculated:
        raise ValueError(f"{label}.releaseId does not match immutable release content")
    record = {
        "releaseId": supplied,
        "version": version,
        "engines": engines,
        "artifacts": artifacts,
    }
    if provenance is not None:
        record["nativeSidecarProvenance"] = provenance
    return record


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
            mode = 0o100755 if path.stat().st_mode & 0o111 else 0o100644
            info.external_attr = mode << 16
            archive.writestr(info, archive_bytes(path))


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
            output_root / SNAPSHOT_ROOT_RELATIVE_PATH / source_dir.name,
            ignore=shutil.ignore_patterns("__pycache__", ".git", "*.sig", "*.sig.jws.json"),
        )


def active_marketplace_release_documents(output_root: Path) -> set[Path]:
    """Return release documents that the current marketplace will re-sign.

    Withdrawal removes a plugin from marketplace discovery but intentionally
    leaves its immutable snapshot in ``.xsec-factory/snapshots/``. Its KMS sidecar is bound to
    the retained historical release document and must therefore survive a later
    global ``--clean``. Parse only safe local snapshot source paths before
    deciding which sidecars are replaceable in this run.
    """

    marketplace_path = output_root / MARKETPLACE_RELATIVE_PATH
    current = marketplace_path
    for _ in MARKETPLACE_RELATIVE_PATH.parts:
        if is_link(current):
            raise ValueError(f"marketplace metadata path must not contain symbolic links: {current}")
        current = current.parent
    try:
        marketplace = json.loads(marketplace_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("marketplace.json cannot be read before sidecar cleanup") from error
    entries = marketplace.get("plugins") if isinstance(marketplace, dict) else None
    if not isinstance(entries, list):
        raise ValueError("marketplace.json plugins must be a list before sidecar cleanup")

    output_plugins = output_root / SNAPSHOT_ROOT_RELATIVE_PATH
    active: set[Path] = set()
    for entry in entries:
        source = entry.get("source") if isinstance(entry, dict) else None
        source_path = source.get("path") if isinstance(source, dict) else None
        if not isinstance(source_path, str) or not source_path:
            raise ValueError("every marketplace entry needs source.path before sidecar cleanup")
        relative = PurePosixPath(source_path)
        if (
            relative.is_absolute()
            or not relative.parts
            or tuple(relative.parts[: len(SNAPSHOT_ROOT_RELATIVE_PATH.parts)])
            != SNAPSHOT_ROOT_RELATIVE_PATH.parts
            or any(part in {"", ".", ".."} or ":" in part for part in relative.parts)
        ):
            raise ValueError("marketplace plugin source.path must remain below .xsec-factory/snapshots/ before sidecar cleanup")
        candidate = output_root.joinpath(*relative.parts)
        try:
            candidate.resolve(strict=False).relative_to(output_plugins.resolve(strict=False))
        except (OSError, ValueError) as error:
            raise ValueError("marketplace plugin source.path escaped .xsec-factory/snapshots/ before sidecar cleanup") from error
        active.add((candidate / ".xsec-market" / "releases.json").resolve(strict=False))
    return active


def clean_generated_output(output_root: Path) -> None:
    """Remove replaceable signatures without deleting immutable release state.

    Older versions removed every `.xsec-market` directory for `--clean`.  That
    made publishing a new version erase the only artifact a stable pointer
    could reference, so it is intentionally no longer a release-history clean.
    KMS sidecars for currently discoverable plugins are regenerated in this
    publication; sidecars for withdrawn snapshots remain as signed history.
    """
    output_plugins = output_root / SNAPSHOT_ROOT_RELATIVE_PATH
    if is_link(output_plugins):
        raise ValueError(f"generated plugin root must not be a symbolic link: {output_plugins}")
    if not output_plugins.exists():
        return
    if not output_plugins.is_dir():
        raise ValueError(f"generated plugin root is unavailable: {output_plugins}")
    release_roots: list[Path] = []
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
            raise ValueError(f"generated output path must remain below .xsec-factory/snapshots/: {release_root}") from error
        release_roots.append(release_root)
    # Preserve the historic validation ordering: reject unsafe plugin paths
    # before opening the marketplace metadata that decides which sidecars are
    # replaceable in this publication.
    active_release_documents = active_marketplace_release_documents(output_root)
    for release_root in release_roots:
        release_path = release_root / "releases.json"
        # Legacy detached signatures are always stale. The KMS sidecar is
        # replaced only for documents that remain in marketplace discovery;
        # an unlisted external snapshot is a disabled publication whose
        # historical sidecar must remain intact.
        release_path.with_name(release_path.name + ".sig").unlink(missing_ok=True)
        if release_path.resolve(strict=False) in active_release_documents:
            release_path.with_name(release_path.name + ".sig.jws.json").unlink(missing_ok=True)
    marketplace_path = output_root / MARKETPLACE_RELATIVE_PATH
    for suffix in (".sig", ".sig.jws.json"):
        marketplace_path.with_name(marketplace_path.name + suffix).unlink(missing_ok=True)


def build_plugin(
    source_plugin_dir: Path,
    output_plugin_dir: Path,
    *,
    native_sidecar_inputs: dict[tuple[str, str], Path] | None = None,
    native_sidecar_source_revision: str | None = None,
    source_only: bool = False,
) -> None:
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

    recipe = recipe_for_source(plugin_id, source_plugin_dir)
    if source_only and recipe is not None:
        return
    inputs = native_sidecar_inputs or {}
    provenance = native_sidecar_provenance(recipe, inputs, native_sidecar_source_revision)
    candidates = build_candidate_artifacts(source_plugin_dir, plugin_id, version, inputs, recipe)
    candidate_artifacts = [candidate[0] for candidate in candidates]
    candidate_release_id = release_id(version, engines, candidate_artifacts, provenance)
    target = append_candidate_release(
        release,
        plugin_id,
        version,
        candidate_release_id,
        candidate_artifacts,
        candidates,
        artifact_dir,
        engines,
        provenance,
    )
    channels = release["channels"]
    if not isinstance(channels, dict):
        raise ValueError(f"release metadata for {plugin_id} has invalid channels")
    channels["beta"] = {"releaseId": target["releaseId"]}
    release_path.parent.mkdir(parents=True, exist_ok=True)
    release_path.write_bytes(stable_json(release))


def build_candidate_artifacts(
    source_plugin_dir: Path,
    plugin_id: str,
    version: str,
    native_inputs: dict[tuple[str, str], Path],
    recipe: NativeSidecarRecipe | None,
) -> list[tuple[dict[str, str], bytes]]:
    """Return release records and immutable bytes without touching output state."""

    if recipe is None:
        if any(input_id == plugin_id for input_id, _ in native_inputs):
            raise ValueError(f"native sidecar inputs were supplied for a source without a native MCP: {plugin_id}")
        return [archive_candidate(source_plugin_dir, plugin_id, version, "any", "any")]
    inputs = require_inputs(recipe, native_inputs)
    files = iter_plugin_files(source_plugin_dir)
    candidates: list[tuple[dict[str, str], bytes]] = []
    for target in recipe.targets:
        with staged_plugin(source_plugin_dir, files, recipe, inputs[target.rust_target]) as staging:
            candidates.append(archive_candidate(staging, plugin_id, version, target.os_name, target.arch))
    return candidates


def native_sidecar_provenance(
    recipe: NativeSidecarRecipe | None,
    native_inputs: dict[tuple[str, str], Path],
    source_revision: str | None,
) -> dict[str, object] | None:
    if recipe is None:
        return None
    if source_revision is None:
        raise ValueError(f"native MCP plugin {recipe.plugin_id} requires a protected source revision")
    inputs = require_inputs(recipe, native_inputs)
    return provenance_for_inputs(recipe, source_revision, inputs)


def source_plugin_dir(entry: dict[str, object]) -> Path:
    source = entry.get("source")
    relative_path = source.get("path") if isinstance(source, dict) else None
    if not isinstance(relative_path, str):
        raise ValueError("every marketplace entry needs source.path")
    source_candidate = ROOT / relative_path
    if is_link(source_candidate):
        raise ValueError(f"plugin source must not be a symbolic link: {relative_path}")
    resolved = source_candidate.resolve()
    try:
        resolved.relative_to(PLUGIN_ROOT.resolve())
    except ValueError as error:
        raise ValueError(
            f"plugin source must remain below .xsec-factory/snapshots/: {relative_path}"
        ) from error
    return resolved


def preflight_native_sidecars(
    entries: list[dict[str, object]],
    native_inputs: dict[tuple[str, str], Path],
    source_revision: str | None,
    source_only: bool,
) -> None:
    native_plugin_ids = set()
    for entry in entries:
        plugin_dir = source_plugin_dir(entry)
        plugin_id = safe_artifact_component(
            json.loads((plugin_dir / "plugin.json").read_text(encoding="utf-8")).get("name"),
            "plugin manifest name",
        )
        recipe = recipe_for_source(plugin_id, plugin_dir)
        if recipe is None:
            continue
        native_plugin_ids.add(plugin_id)
        if not source_only:
            native_sidecar_provenance(recipe, native_inputs, source_revision)
    unexpected = {plugin_id for plugin_id, _ in native_inputs} - native_plugin_ids
    if unexpected:
        raise ValueError(f"native sidecar inputs do not match a native MCP plugin: {sorted(unexpected)[0]}")


def archive_candidate(
    source_plugin_dir: Path,
    plugin_id: str,
    version: str,
    os_name: str,
    arch: str,
) -> tuple[dict[str, str], bytes]:
    with tempfile.TemporaryDirectory(prefix="xsec-market-artifact-") as directory:
        candidate = Path(directory) / "candidate.xsec-plugin"
        write_zip(source_plugin_dir, candidate)
        payload = candidate.read_bytes()
    digest = sha256(payload)
    name = f"{plugin_id}-{version}-sha256-{digest[:16]}-{os_name}-{arch}.xsec-plugin"
    return ({"os": os_name, "arch": arch, "url": f"{ARTIFACT_DIR_NAME}/{name}", "sha256": digest}, payload)


def append_candidate_release(
    release: dict[str, object],
    plugin_id: str,
    version: str,
    candidate_release_id: str,
    candidate_artifacts: list[dict[str, str]],
    candidates: list[tuple[dict[str, str], bytes]],
    artifact_dir: Path,
    engines: dict[str, str],
    native_sidecar_provenance: dict[str, object] | None,
) -> dict[str, object]:
    releases = release["releases"]
    if not isinstance(releases, list):
        raise ValueError(f"release metadata for {plugin_id} has invalid releases")
    existing = {str(item["releaseId"]): item for item in releases if isinstance(item, dict)}
    target = existing.get(candidate_release_id)
    if target is not None:
        return target
    if any(item.get("version") == version for item in existing.values()):
        raise ValueError(f"release metadata for {plugin_id} already contains immutable content for version {version}; bump plugin.json before publishing different content")
    artifact_dir.mkdir(parents=True, exist_ok=True)
    for artifact, payload in candidates:
        output = path_below(artifact_dir, Path(artifact["url"]).name, "artifact path")
        if output.exists() and sha256(output) != artifact["sha256"]:
            raise ValueError(f"immutable artifact path already contains different bytes: {output}")
        if not output.exists():
            output.write_bytes(payload)
    target = {"releaseId": candidate_release_id, "version": version, "engines": engines, "artifacts": candidate_artifacts}
    if native_sidecar_provenance is not None:
        target["nativeSidecarProvenance"] = native_sidecar_provenance
    releases.append(target)
    return target


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--clean", action="store_true")
    parser.add_argument(
        "--source-only",
        action="store_true",
        help="validate portable native-MCP source without emitting its release artifact",
    )
    parser.add_argument(
        "--native-sidecar-input",
        action="append",
        default=[],
        metavar="PLUGIN@RUST_TARGET=PATH",
        help="allowlisted pre-built native MCP binary from the protected runner",
    )
    parser.add_argument(
        "--native-sidecar-source-revision",
        help="exact Desktop source revision used by the protected native-sidecar builder",
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        default=ROOT,
        help="destination marketplace root; use an empty temporary directory for validation",
    )
    args = parser.parse_args()

    if args.source_only and (args.native_sidecar_input or args.native_sidecar_source_revision):
        parser.error("--source-only cannot be combined with native sidecar inputs or a source revision")

    native_inputs = parse_native_sidecar_inputs(args.native_sidecar_input)
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
    entries = marketplace_entries()
    preflight_native_sidecars(
        entries,
        native_inputs,
        args.native_sidecar_source_revision,
        args.source_only,
    )
    if args.clean:
        clean_generated_output(output_root)

    for entry in entries:
        plugin_source_dir = source_plugin_dir(entry)
        output_plugin_dir = output_root / plugin_source_dir.relative_to(ROOT)
        build_plugin(
            plugin_source_dir,
            output_plugin_dir,
            native_sidecar_inputs=native_inputs,
            native_sidecar_source_revision=args.native_sidecar_source_revision,
            source_only=args.source_only,
        )


if __name__ == "__main__":
    main()
