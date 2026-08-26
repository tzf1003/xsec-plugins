#!/usr/bin/env python3
"""Core, dependency-free primitives for an XSEC user Marketplace Factory.

The official XSEC marketplace deliberately has a separate KMS-backed release
chain.  This module is for the *untrusted user factory* template only: it
checks a registry, packages an already checked-out external plugin commit
deterministically, and writes Desktop-compatible metadata snapshots.  It never
executes a plugin script, invokes a package manager, or accesses GitHub.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import tempfile
import zipfile


REGISTRY_RELATIVE_PATH = Path(".xsec-factory") / "registry.json"
MARKETPLACE_RELATIVE_PATH = Path(".agents") / "plugins" / "marketplace.json"
PLUGIN_ROOT_RELATIVE_PATH = Path("plugins")
PUBLICATIONS_RELATIVE_PATH = Path(".xsec-factory") / "publications"
ARTIFACT_DIR_NAME = "artifacts"
RELEASE_ID_PATTERN = re.compile(r"^sha256-[0-9a-f]{64}$")
GIT_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
# Keep emitted Factory artifacts consumable by Desktop on every platform. This
# is intentionally the same compact, lowercase ID grammar as the official
# Factory bridge, rather than merely a permissive filename component grammar.
PLUGIN_ID_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?$")
# Match the SemVer grammar accepted by Desktop.  This is intentionally stricter
# than an artifact filename component: publishing `preview` may create a ZIP,
# but Desktop cannot select it as a release version.
SEMVER_NUMERIC_IDENTIFIER = r"(?:0|[1-9][0-9]*)"
SEMVER_PRERELEASE_IDENTIFIER = r"(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
SEMVER_BUILD_IDENTIFIER = r"[0-9A-Za-z-]+"
VERSION_PATTERN = re.compile(
    rf"^{SEMVER_NUMERIC_IDENTIFIER}\.{SEMVER_NUMERIC_IDENTIFIER}\.{SEMVER_NUMERIC_IDENTIFIER}"
    rf"(?:-{SEMVER_PRERELEASE_IDENTIFIER}(?:\.{SEMVER_PRERELEASE_IDENTIFIER})*)?"
    rf"(?:\+{SEMVER_BUILD_IDENTIFIER}(?:\.{SEMVER_BUILD_IDENTIFIER})*)?$"
)
REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,38}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$")
MARKETPLACE_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
TEXT_ARCHIVE_SUFFIXES = frozenset({
    ".cjs", ".css", ".html", ".htm", ".js", ".json", ".jsx", ".md",
    ".mjs", ".ps1", ".sh", ".svg", ".toml", ".ts", ".tsx", ".txt",
    ".xml", ".yaml", ".yml",
})
EXCLUDED_PARTS = frozenset({".git", ".xsec-market", "__pycache__", "node_modules"})
MAX_ARCHIVE_ENTRIES = 10_000
MAX_ARCHIVE_FILE_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES = 128 * 1024 * 1024
MAX_SOURCE_TREE_ENTRIES = MAX_ARCHIVE_ENTRIES
MAX_ARTIFACT_FILENAME_BYTES = 240
WINDOWS_FORBIDDEN_COMPONENT_CHARACTERS = frozenset('<>"\\|?*')
WINDOWS_RESERVED_DEVICE_NAMES = frozenset({
    "con", "prn", "aux", "nul", "clock$", "conin$", "conout$",
    *(f"com{number}" for number in range(1, 10)),
    *(f"lpt{number}" for number in range(1, 10)),
})


class FactoryError(ValueError):
    """An untrusted input did not meet the Factory contract."""


def fail(message: str) -> None:
    raise FactoryError(message)


def is_link(path: Path) -> bool:
    """Cover POSIX links and Windows directory junctions."""

    return path.is_symlink() or getattr(path, "is_junction", lambda: False)()


def stable_json(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def canonical_json(value: object) -> bytes:
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


def safe_plugin_id(value: object, label: str = "plugin ID") -> str:
    if (
        not isinstance(value, str)
        or not PLUGIN_ID_PATTERN.fullmatch(value)
        or ".." in value
        or "--" in value
    ):
        fail(f"{label} must be a safe plugin identifier")
    # A Factory always packages external source. Keep Desktop's internal
    # namespace out of any user-owned Factory as well, otherwise a custom
    # source can be mistaken for OfficialDevelopment in developer workflows.
    if value == "com.xsec" or value.startswith("com.xsec."):
        fail(f"{label} is reserved for the Desktop namespace")
    return value


def safe_version(value: object, label: str = "plugin version") -> str:
    if not isinstance(value, str) or not VERSION_PATTERN.fullmatch(value) or value.endswith((".", " ")):
        fail(f"{label} must be a valid SemVer value and safe filename component")
    return value


def safe_repository(value: object, label: str = "source.repository") -> str:
    if not isinstance(value, str) or not REPOSITORY_PATTERN.fullmatch(value):
        fail(f"{label} must be an owner/repository GitHub slug")
    owner, name = value.split("/", 1)
    if any(
        component.startswith(".")
        or component.endswith(".")
        or ".." in component
        for component in (owner, name)
    ):
        fail(f"{label} must be an owner/repository GitHub slug")
    return value


def safe_git_sha(value: object, label: str = "source SHA") -> str:
    if not isinstance(value, str) or not GIT_SHA_PATTERN.fullmatch(value):
        fail(f"{label} must be a lowercase 40-character Git commit SHA")
    return value


def safe_source_path(value: object, label: str = "source.path") -> PurePosixPath:
    """Parse a source checkout-relative path without allowing checkout escape."""

    if not isinstance(value, str) or not value or value != value.strip() or "\\" in value:
        fail(f"{label} must be a non-empty forward-slash checkout-relative path")
    if value == ".":
        return PurePosixPath(".")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} or ":" in part for part in path.parts):
        fail(f"{label} must remain below the checked-out repository")
    return path


def require_object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    return value


def read_json(path: Path, label: str) -> dict[str, object]:
    if is_link(path):
        fail(f"{label} must not be a symbolic link")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{label} is not valid UTF-8 JSON: {error}")
    return require_object(value, label)


def assert_exact_keys(value: dict[str, object], keys: set[str], label: str) -> None:
    if set(value) != keys:
        fail(f"{label} has an unsupported schema")


def require_text(value: object, label: str, *, max_length: int = 256) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > max_length or "\x00" in value:
        fail(f"{label} must be a non-empty bounded string")
    return value


def resolve_below(root: Path, relative: PurePosixPath, label: str, *, require_directory: bool = False) -> Path:
    """Resolve a regular path below a checked-out tree without links."""

    if is_link(root):
        fail(f"{label} root must not be a symbolic link")
    try:
        root_resolved = root.resolve(strict=True)
    except OSError as error:
        fail(f"{label} root is unavailable: {error}")
    current = root
    if relative != PurePosixPath("."):
        for part in relative.parts:
            current = current / part
            if is_link(current):
                fail(f"{label} must not traverse symbolic links")
    try:
        resolved = current.resolve(strict=True)
        resolved.relative_to(root_resolved)
    except (OSError, ValueError) as error:
        fail(f"{label} must remain below its root: {error}")
    if require_directory:
        if not resolved.is_dir():
            fail(f"{label} must resolve to a directory")
    elif not resolved.is_file():
        fail(f"{label} must resolve to a regular file")
    return resolved


def require_engines(value: object, label: str) -> dict[str, str]:
    engines = require_object(value, f"{label}.engines")
    if set(engines) != {"xsec", "pluginApi"}:
        fail(f"{label}.engines must contain only xsec and pluginApi")
    result: dict[str, str] = {}
    for name in ("xsec", "pluginApi"):
        result[name] = require_text(engines.get(name), f"{label}.engines.{name}")
    return result


def desktop_manifest(manifest: dict[str, object], plugin_id: str, plugin_dir: Path) -> tuple[str, dict[str, str]]:
    """Validate the fields needed to package a source plugin without executing it."""

    if safe_plugin_id(manifest.get("name"), "plugin manifest name") != plugin_id:
        fail("plugin manifest name does not match the registered plugin ID")
    version = safe_version(manifest.get("version"), "plugin manifest version")
    extensions = require_object(manifest.get("extensions"), "plugin manifest extensions")
    desktop = require_object(extensions.get("com.xsec.desktop"), "plugin manifest XSEC Desktop extension")
    require_engines(desktop.get("engines"), "plugin manifest")
    entrypoints = require_object(desktop.get("entrypoints"), "plugin manifest entrypoints")
    if not entrypoints:
        fail("plugin manifest must declare at least one XSEC Desktop entrypoint")
    normalized: dict[str, str] = {}
    for name, raw_path in entrypoints.items():
        if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", name):
            fail("plugin manifest has an invalid XSEC Desktop entrypoint name")
        relative = safe_source_path(raw_path, f"plugin manifest entrypoint {name}")
        resolve_below(plugin_dir, relative, f"plugin manifest entrypoint {name}")
        normalized[name] = relative.as_posix()
    return version, normalized


@dataclass(frozen=True)
class PluginRegistration:
    plugin_id: str
    repository: str
    source_path: PurePosixPath
    beta_ref: str
    stable_ref: str
    installation: str
    authentication: str
    category: str
    status: str

    @property
    def branch_for_channel(self) -> dict[str, str]:
        return {"beta": self.beta_ref, "stable": self.stable_ref}


@dataclass(frozen=True)
class FactoryRegistry:
    name: str
    display_name: str
    plugins: tuple[PluginRegistration, ...]


def parse_registration(value: object, index: int) -> PluginRegistration:
    label = f"registry plugin at index {index}"
    entry = require_object(value, label)
    assert_exact_keys(entry, {"pluginId", "source", "policy", "category", "status"}, label)
    plugin_id = safe_plugin_id(entry.get("pluginId"), f"{label}.pluginId")
    source = require_object(entry.get("source"), f"{label}.source")
    assert_exact_keys(source, {"repository", "path", "refs"}, f"{label}.source")
    repository = safe_repository(source.get("repository"), f"{label}.source.repository")
    source_path = safe_source_path(source.get("path"), f"{label}.source.path")
    refs = require_object(source.get("refs"), f"{label}.source.refs")
    assert_exact_keys(refs, {"beta", "stable"}, f"{label}.source.refs")
    beta_ref = refs.get("beta")
    stable_ref = refs.get("stable")
    if beta_ref != "refs/heads/beta" or stable_ref != "refs/heads/main":
        fail(f"{label}.source.refs must map beta to refs/heads/beta and stable to refs/heads/main")
    policy = require_object(entry.get("policy"), f"{label}.policy")
    assert_exact_keys(policy, {"installation", "authentication"}, f"{label}.policy")
    installation = policy.get("installation")
    authentication = policy.get("authentication")
    # Desktop's portable marketplace protocol calls a user-installable plugin
    # AVAILABLE. A user-created Marketplace is still untrusted: Desktop keeps
    # its explicit confirmation gate and Factory metadata may never request a
    # silent INSTALLED_BY_DEFAULT install.
    if installation != "AVAILABLE":
        fail(f"{label}.policy.installation must be AVAILABLE for a user Marketplace Factory")
    if authentication != "ON_INSTALL":
        fail(f"{label}.policy.authentication must be ON_INSTALL")
    category = require_text(entry.get("category"), f"{label}.category", max_length=80)
    status = entry.get("status")
    if status not in {"active", "disabled"}:
        fail(f"{label}.status must be active or disabled")
    return PluginRegistration(
        plugin_id=plugin_id,
        repository=repository,
        source_path=source_path,
        beta_ref=beta_ref,
        stable_ref=stable_ref,
        installation=installation,
        authentication=authentication,
        category=category,
        status=status,
    )


def load_registry(root: Path) -> FactoryRegistry:
    path = root / REGISTRY_RELATIVE_PATH
    if is_link(path.parent):
        fail("factory registry directory must not be a symbolic link")
    value = read_json(path, "factory registry")
    assert_exact_keys(value, {"schemaVersion", "marketplace", "plugins"}, "factory registry")
    if value.get("schemaVersion") != 1:
        fail("factory registry schemaVersion must be 1")
    marketplace = require_object(value.get("marketplace"), "factory registry marketplace")
    assert_exact_keys(marketplace, {"name", "displayName"}, "factory registry marketplace")
    name = marketplace.get("name")
    if not isinstance(name, str) or not MARKETPLACE_NAME_PATTERN.fullmatch(name):
        fail("factory registry marketplace.name must be a safe lowercase identifier")
    display_name = require_text(marketplace.get("displayName"), "factory registry marketplace.displayName", max_length=120)
    entries = value.get("plugins")
    if not isinstance(entries, list):
        fail("factory registry plugins must be a list")
    plugins = tuple(parse_registration(entry, index) for index, entry in enumerate(entries))
    identifiers = [entry.plugin_id for entry in plugins]
    if len(identifiers) != len(set(identifiers)):
        fail("factory registry contains duplicate plugin IDs")
    return FactoryRegistry(name=name, display_name=display_name, plugins=plugins)


def registration_for(registry: FactoryRegistry, plugin_id: str, *, require_active: bool = True) -> PluginRegistration:
    identifier = safe_plugin_id(plugin_id)
    for registration in registry.plugins:
        if registration.plugin_id == identifier:
            if require_active and registration.status != "active":
                fail(f"plugin {identifier} is disabled in the Factory registry")
            return registration
    fail(f"plugin {identifier} is not registered in this Marketplace Factory")


def artifact_url(repository: str, release_tag: str, filename: str) -> str:
    safe_repository(repository, "factory repository")
    if not re.fullmatch(r"xsec-plugin-[0-9a-f]{16}-sha256-[0-9a-f]{64}", release_tag):
        fail("release tag is not canonical")
    if not filename or "/" in filename or "\\" in filename or len(filename.encode("utf-8")) > MAX_ARTIFACT_FILENAME_BYTES:
        fail("artifact filename is unsafe")
    return f"https://github.com/{repository}/releases/download/{release_tag}/{filename}"


def release_tag(plugin_id: str, identifier: str) -> str:
    safe_plugin_id(plugin_id)
    if not RELEASE_ID_PATTERN.fullmatch(identifier):
        fail("release ID is not canonical")
    plugin_digest = sha256(plugin_id.encode("utf-8"))[:16]
    return f"xsec-plugin-{plugin_digest}-{identifier}"


def archive_bytes(path: Path) -> bytes:
    value = path.read_bytes()
    if path.suffix.lower() not in TEXT_ARCHIVE_SUFFIXES or b"\r\n" not in value:
        return value
    try:
        value.decode("utf-8")
    except UnicodeDecodeError as error:
        fail(f"text package member must be UTF-8: {path}")
    return value.replace(b"\r\n", b"\n")


def assert_link_free_tree(plugin_dir: Path) -> None:
    if is_link(plugin_dir):
        fail("plugin source root must not be a symbolic link")
    source_entries = 0
    for current, directories, names in os.walk(plugin_dir, topdown=True, followlinks=False):
        current_path = Path(current)
        retained_directories: list[str] = []
        for name in directories:
            path = current_path / name
            relative = path.relative_to(plugin_dir)
            if name in EXCLUDED_PARTS:
                continue
            if is_link(path):
                fail(f"plugin source must not contain symbolic links: {relative.as_posix()}")
            source_entries += 1
            if source_entries > MAX_SOURCE_TREE_ENTRIES:
                fail("plugin source tree contains too many files or directories")
            retained_directories.append(name)
        directories[:] = retained_directories
        for name in names:
            path = current_path / name
            relative = path.relative_to(plugin_dir)
            if any(part in EXCLUDED_PARTS for part in relative.parts):
                continue
            if is_link(path):
                fail(f"plugin source must not contain symbolic links: {relative.as_posix()}")
            source_entries += 1
            if source_entries > MAX_SOURCE_TREE_ENTRIES:
                fail("plugin source tree contains too many files or directories")


def iter_plugin_files(plugin_dir: Path) -> list[Path]:
    assert_link_free_tree(plugin_dir)
    files: list[Path] = []
    total_bytes = 0
    for current, directories, names in os.walk(plugin_dir, topdown=True, followlinks=False):
        directories[:] = [name for name in directories if name not in EXCLUDED_PARTS]
        current_path = Path(current)
        for name in names:
            path = current_path / name
            relative = path.relative_to(plugin_dir)
            if any(part in EXCLUDED_PARTS for part in relative.parts) or not path.is_file():
                continue
            if len(files) >= MAX_ARCHIVE_ENTRIES:
                fail("plugin package contains too many files")
            size = path.stat().st_size
            if size > MAX_ARCHIVE_FILE_BYTES:
                fail(f"plugin package file is too large: {relative.as_posix()}")
            total_bytes += size
            if total_bytes > MAX_ARCHIVE_TOTAL_BYTES:
                fail("plugin package is too large")
            files.append(path)
    if not any(path.relative_to(plugin_dir).as_posix() == "plugin.json" for path in files):
        fail("plugin package must include root plugin.json")
    require_portable_package_paths(plugin_dir, files)
    return files


def portable_target_filesystem_path(relative: str) -> str:
    """Return the Desktop installer target path or reject an unsafe member."""

    if not relative.isascii():
        fail(f"plugin package path must use portable ASCII characters: {relative}")
    parts = relative.split("/")
    if not parts or any(not part or part in {".", ".."} for part in parts):
        fail(f"plugin package path is unsafe: {relative}")
    normalized_parts: list[str] = []
    for part in parts:
        if part.endswith((".", " ")):
            fail(f"plugin package path has a Windows trailing-dot or trailing-space alias: {relative}")
        if ":" in part:
            fail(f"plugin package path has a Windows NTFS stream alias: {relative}")
        if any(ord(character) <= 0x1F or character in WINDOWS_FORBIDDEN_COMPONENT_CHARACTERS for character in part):
            fail(f"plugin package path has a Windows-forbidden character: {relative}")
        device_name = part.split(".", 1)[0].lower()
        if device_name in WINDOWS_RESERVED_DEVICE_NAMES:
            fail(f"plugin package path has a Windows reserved device name: {relative}")
        normalized_parts.append(part.lower())
    return "/".join(normalized_parts)


def require_portable_package_paths(plugin_dir: Path, files: list[Path]) -> None:
    """Reject source names Desktop could not safely extract from the ZIP."""

    target_paths: dict[str, str] = {}
    for path in files:
        relative = path.relative_to(plugin_dir).as_posix()
        target = portable_target_filesystem_path(relative)
        existing = target_paths.get(target)
        if existing is not None:
            fail(
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
                fail(
                    "plugin package paths have a file/directory collision on case-insensitive filesystems: "
                    f"{existing} and {relative}"
                )


def write_zip(plugin_dir: Path, destination: Path) -> None:
    files = iter_plugin_files(plugin_dir)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(files, key=lambda item: item.relative_to(plugin_dir).as_posix()):
            info = zipfile.ZipInfo(path.relative_to(plugin_dir).as_posix())
            info.date_time = (2024, 1, 1, 0, 0, 0)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, archive_bytes(path))


def release_id(version: str, engines: dict[str, str], artifacts: list[dict[str, object]]) -> str:
    descriptor = {
        "version": version,
        "engines": engines,
        "artifacts": sorted(
            [
                {"os": artifact.get("os"), "arch": artifact.get("arch"), "sha256": artifact.get("sha256")}
                for artifact in artifacts
            ],
            key=lambda item: (str(item["os"]), str(item["arch"]), str(item["sha256"])),
        ),
    }
    return f"sha256-{sha256(canonical_json(descriptor))}"


def parse_artifact(value: object, label: str) -> dict[str, object]:
    artifact = require_object(value, label)
    assert_exact_keys(artifact, {"os", "arch", "url", "sha256"}, label)
    os_name = require_text(artifact.get("os"), f"{label}.os", max_length=40)
    arch = require_text(artifact.get("arch"), f"{label}.arch", max_length=40)
    url = artifact.get("url")
    if not isinstance(url, str) or not re.fullmatch(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/releases/download/[^/]+/[^/]+", url):
        fail(f"{label}.url must be an immutable GitHub Release asset URL")
    digest = artifact.get("sha256")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        fail(f"{label}.sha256 must be a lowercase SHA-256 digest")
    return {"os": os_name, "arch": arch, "url": url, "sha256": digest}


def parse_release_record(value: object, plugin_id: str, label: str) -> dict[str, object]:
    record = require_object(value, label)
    assert_exact_keys(record, {"releaseId", "version", "engines", "artifacts"}, label)
    identifier = record.get("releaseId")
    if not isinstance(identifier, str) or not RELEASE_ID_PATTERN.fullmatch(identifier):
        fail(f"{label}.releaseId is invalid")
    version = safe_version(record.get("version"), f"{label}.version")
    engines = require_engines(record.get("engines"), label)
    raw_artifacts = record.get("artifacts")
    if not isinstance(raw_artifacts, list) or not raw_artifacts:
        fail(f"{label}.artifacts must be a non-empty list")
    artifacts = [parse_artifact(item, f"{label}.artifacts[{index}]") for index, item in enumerate(raw_artifacts)]
    targets = [(str(item["os"]), str(item["arch"])) for item in artifacts]
    if len(targets) != len(set(targets)):
        fail(f"{label}.artifacts contains duplicate OS/architecture targets")
    if identifier != release_id(version, engines, artifacts):
        fail(f"{label}.releaseId does not match immutable content")
    return {"releaseId": identifier, "version": version, "engines": engines, "artifacts": artifacts}


def empty_release_document(plugin_id: str) -> dict[str, object]:
    return {
        "schemaVersion": 2,
        "pluginId": plugin_id,
        "releases": [],
        "channels": {"beta": {"releaseId": None}, "stable": None},
    }


def load_release_document(path: Path, plugin_id: str) -> dict[str, object]:
    if is_link(path) or is_link(path.parent):
        fail("release metadata must not use symbolic links")
    if not path.exists():
        return empty_release_document(plugin_id)
    document = read_json(path, f"release metadata for {plugin_id}")
    assert_exact_keys(document, {"schemaVersion", "pluginId", "releases", "channels"}, f"release metadata for {plugin_id}")
    if document.get("schemaVersion") != 2 or document.get("pluginId") != plugin_id:
        fail(f"release metadata for {plugin_id} has an invalid schemaVersion or pluginId")
    raw_releases = document.get("releases")
    if not isinstance(raw_releases, list):
        fail(f"release metadata for {plugin_id}.releases must be a list")
    releases = [parse_release_record(item, plugin_id, f"release metadata for {plugin_id} at index {index}") for index, item in enumerate(raw_releases)]
    identifiers = [str(item["releaseId"]) for item in releases]
    versions = [str(item["version"]) for item in releases]
    if len(identifiers) != len(set(identifiers)) or len(versions) != len(set(versions)):
        fail(f"release metadata for {plugin_id} must not duplicate release IDs or versions")
    channels = require_object(document.get("channels"), f"release metadata for {plugin_id}.channels")
    assert_exact_keys(channels, {"beta", "stable"}, f"release metadata for {plugin_id}.channels")
    beta = require_object(channels.get("beta"), f"release metadata for {plugin_id}.channels.beta")
    assert_exact_keys(beta, {"releaseId"}, f"release metadata for {plugin_id}.channels.beta")
    beta_id = beta.get("releaseId")
    if beta_id is not None and (not isinstance(beta_id, str) or beta_id not in identifiers):
        fail(f"release metadata for {plugin_id}.channels.beta must point at a known release or be null")
    stable = channels.get("stable")
    if stable is not None:
        stable_pointer = require_object(stable, f"release metadata for {plugin_id}.channels.stable")
        assert_exact_keys(stable_pointer, {"releaseId"}, f"release metadata for {plugin_id}.channels.stable")
        stable_id = stable_pointer.get("releaseId")
        if not isinstance(stable_id, str) or stable_id not in identifiers:
            fail(f"release metadata for {plugin_id}.channels.stable must point at a known release or be null")
    return {
        "schemaVersion": 2,
        "pluginId": plugin_id,
        "releases": releases,
        "channels": {"beta": {"releaseId": beta_id}, "stable": stable},
    }


def atomic_write(path: Path, payload: bytes) -> None:
    if is_link(path) or is_link(path.parent):
        fail(f"refusing to write through symbolic link: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
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


def require_write_path_below(root: Path, path: Path, label: str) -> None:
    """Reject a Factory checkout that redirects a metadata write through a link."""

    try:
        relative = path.relative_to(root)
    except ValueError as error:
        raise FactoryError(f"{label} must remain below the Factory root") from error
    if is_link(root):
        fail("Factory root must not be a symbolic link")
    current = root
    for part in relative.parts:
        current = current / part
        if current.exists() and is_link(current):
            fail(f"{label} must not traverse symbolic links")


def plugin_snapshot_dir(root: Path, plugin_id: str) -> Path:
    safe_plugin_id(plugin_id)
    candidate = root / PLUGIN_ROOT_RELATIVE_PATH / plugin_id
    try:
        candidate.resolve(strict=False).relative_to((root / PLUGIN_ROOT_RELATIVE_PATH).resolve(strict=False))
    except ValueError as error:
        raise FactoryError("plugin snapshot path escaped the Factory root") from error
    return candidate


def release_document_path(root: Path, plugin_id: str) -> Path:
    return plugin_snapshot_dir(root, plugin_id) / ".xsec-market" / "releases.json"


def publication_path(root: Path, plugin_id: str) -> Path:
    safe_plugin_id(plugin_id)
    return root / PUBLICATIONS_RELATIVE_PATH / f"{plugin_id}.json"


def source_plugin_directory(source_root: Path, registration: PluginRegistration) -> Path:
    return resolve_below(source_root, registration.source_path, f"source path for {registration.plugin_id}", require_directory=True)


def read_source_plugin(source_root: Path, registration: PluginRegistration) -> tuple[Path, dict[str, object], str, dict[str, str]]:
    plugin_dir = source_plugin_directory(source_root, registration)
    assert_link_free_tree(plugin_dir)
    manifest_path = plugin_dir / "plugin.json"
    manifest = read_json(manifest_path, f"plugin manifest for {registration.plugin_id}")
    version, entrypoints = desktop_manifest(manifest, registration.plugin_id, plugin_dir)
    return plugin_dir, manifest, version, entrypoints


def source_engines(manifest: dict[str, object]) -> dict[str, str]:
    extensions = require_object(manifest.get("extensions"), "plugin manifest extensions")
    desktop = require_object(extensions.get("com.xsec.desktop"), "plugin manifest XSEC Desktop extension")
    return require_engines(desktop.get("engines"), "plugin manifest")


def candidate_release(plugin_id: str, manifest: dict[str, object], artifact_digest: str, factory_repository: str) -> tuple[dict[str, object], str, str]:
    version = safe_version(manifest.get("version"), "plugin manifest version")
    engines = source_engines(manifest)
    filename = f"{plugin_id}-{version}-sha256-{artifact_digest[:16]}-any-any.xsec-plugin"
    if len(filename.encode("utf-8")) > MAX_ARTIFACT_FILENAME_BYTES:
        fail("plugin ID and version produce an artifact filename that is too long")
    candidate_artifacts = [{"os": "any", "arch": "any", "url": "https://example.invalid/artifact", "sha256": artifact_digest}]
    identifier = release_id(version, engines, candidate_artifacts)
    tag = release_tag(plugin_id, identifier)
    artifact = {
        "os": "any",
        "arch": "any",
        "url": artifact_url(factory_repository, tag, filename),
        "sha256": artifact_digest,
    }
    return {
        "releaseId": identifier,
        "version": version,
        "engines": engines,
        "artifacts": [artifact],
    }, filename, tag


def published_plugin_entries(root: Path, registry: FactoryRegistry) -> list[dict[str, object]]:
    """Return Desktop-compatible local entries for active, already-published plugins."""

    entries: list[dict[str, object]] = []
    for registration in sorted(registry.plugins, key=lambda item: item.plugin_id):
        if registration.status != "active":
            continue
        snapshot = plugin_snapshot_dir(root, registration.plugin_id)
        manifest_path = snapshot / "plugin.json"
        release_path = snapshot / ".xsec-market" / "releases.json"
        if not manifest_path.exists() and not release_path.exists():
            # Importing a repository only authorizes it. It becomes visible in
            # Desktop after its first immutable Beta build completes.
            continue
        if not manifest_path.is_file() or not release_path.is_file():
            fail(f"published plugin snapshot for {registration.plugin_id} is incomplete")
        manifest = read_json(manifest_path, f"plugin snapshot manifest for {registration.plugin_id}")
        if manifest.get("name") != registration.plugin_id:
            fail(f"plugin snapshot manifest for {registration.plugin_id} has the wrong name")
        release = load_release_document(release_path, registration.plugin_id)
        beta = require_object(release["channels"], "release metadata channels")["beta"]
        if not isinstance(beta, dict) or not beta.get("releaseId"):
            fail(f"published plugin snapshot for {registration.plugin_id} has no beta release")
        entries.append(
            {
                "name": registration.plugin_id,
                "source": {"source": "local", "path": f"./plugins/{registration.plugin_id}"},
                "policy": {"installation": registration.installation, "authentication": registration.authentication},
                "category": registration.category,
            }
        )
    return entries


def marketplace_document(root: Path, registry: FactoryRegistry) -> dict[str, object]:
    return {
        "name": registry.name,
        "interface": {"displayName": registry.display_name},
        "plugins": published_plugin_entries(root, registry),
    }


def write_marketplace_index(root: Path, registry: FactoryRegistry) -> None:
    document = marketplace_document(root, registry)
    destination = root / MARKETPLACE_RELATIVE_PATH
    require_write_path_below(root, destination, "marketplace index")
    atomic_write(destination, stable_json(document))


def append_publication(
    root: Path,
    registration: PluginRegistration,
    release: dict[str, object],
    source_sha: str,
    channel: str,
    publisher: str,
) -> None:
    """Append non-Desktop audit evidence without mutating a release record."""

    source_sha = safe_git_sha(source_sha)
    if channel not in {"beta", "stable"}:
        fail("publication channel must be beta or stable")
    publisher = require_text(publisher, "publication publisher", max_length=128)
    path = publication_path(root, registration.plugin_id)
    require_write_path_below(root, path, "publication evidence")
    if path.exists():
        document = read_json(path, f"publication evidence for {registration.plugin_id}")
        assert_exact_keys(document, {"schemaVersion", "pluginId", "events"}, f"publication evidence for {registration.plugin_id}")
        if document.get("schemaVersion") != 1 or document.get("pluginId") != registration.plugin_id:
            fail(f"publication evidence for {registration.plugin_id} has an invalid schema")
        events = document.get("events")
        if not isinstance(events, list):
            fail(f"publication evidence for {registration.plugin_id}.events must be a list")
    else:
        events = []
    artifact = release["artifacts"][0] if isinstance(release.get("artifacts"), list) else None
    if not isinstance(artifact, dict):
        raise AssertionError("validated release unexpectedly lacks an artifact")
    event = {
        "channel": channel,
        "releaseId": release["releaseId"],
        "source": {
            "repository": registration.repository,
            "path": registration.source_path.as_posix(),
            "ref": registration.branch_for_channel[channel],
            "sha": source_sha,
        },
        "artifact": {"sha256": artifact["sha256"], "url": artifact["url"]},
        "publisher": publisher,
    }
    if event not in events:
        events.append(event)
    atomic_write(path, stable_json({"schemaVersion": 1, "pluginId": registration.plugin_id, "events": events}))
