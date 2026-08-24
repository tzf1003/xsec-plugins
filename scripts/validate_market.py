#!/usr/bin/env python3
"""Fail-closed validation for XSEC official marketplace source and releases.

``source`` validates a disposable output made by ``build_market.py`` and is
safe for pull requests. ``published`` additionally verifies the Ed25519
metadata signatures that Desktop pins. ``signing-key`` is a publication
preflight which proves that the configured CI signing seed derives to that
pinned public key without displaying either value.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import stat
import tempfile
import unicodedata
import zipfile
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

from build_market import MARKETPLACE_RELATIVE_PATH, ROOT, is_link, sha256, signing_key, write_zip
from marketplace_contract import DEFAULT_OFFICIAL_PLUGIN_IDS, OFFICIAL_MARKETPLACE_PUBLIC_KEY_B64


MAX_ZIP_ENTRIES = 10_000
MAX_ZIP_FILE_BYTES = 64 * 1024 * 1024
MAX_ZIP_UNCOMPRESSED_BYTES = 128 * 1024 * 1024
MAX_ZIP_COMPRESSION_RATIO = 100
WINDOWS_FORBIDDEN_COMPONENT_CHARACTERS = frozenset('<>:"/\\|?*')
WINDOWS_RESERVED_DEVICE_NAMES = frozenset({
    "con", "prn", "aux", "nul",
    *(f"com{number}" for number in range(1, 10)),
    *(f"lpt{number}" for number in range(1, 10)),
})
ENTRYPOINT_NAME = re.compile(r"[a-z][a-z0-9-]{0,63}")


class MarketplaceValidationError(ValueError):
    """A marketplace invariant was not met."""


def fail(message: str) -> None:
    raise MarketplaceValidationError(message)


def read_json(path: Path, label: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{label} is not valid UTF-8 JSON: {error}")
    if not isinstance(value, dict):
        fail(f"{label} must contain a JSON object")
    return value


def raw_ed25519_public_key(value: str, label: str):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if not isinstance(value, str) or not value:
        fail(f"{label} must be a canonical Base64 raw Ed25519 public key")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        fail(f"{label} must be canonical Base64: {error}")
    if base64.b64encode(decoded).decode("ascii") != value or len(decoded) != 32:
        fail(f"{label} must contain exactly 32 raw Ed25519 public-key bytes")
    return Ed25519PublicKey.from_public_bytes(decoded)


def read_signature(signature_path: Path) -> bytes:
    try:
        encoded = signature_path.read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError) as error:
        fail(f"missing or unreadable signature {signature_path}: {error}")
    if not encoded.endswith("\n") or encoded.count("\n") != 1:
        fail(f"signature {signature_path} must be one canonical Base64 line")
    encoded = encoded[:-1]
    try:
        signature = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as error:
        fail(f"signature {signature_path} is not canonical Base64: {error}")
    if base64.b64encode(signature).decode("ascii") != encoded or len(signature) != 64:
        fail(f"signature {signature_path} must contain exactly 64 Ed25519 signature bytes")
    return signature


def verify_signature(document_path: Path, verifier) -> None:
    signature_path = document_path.with_name(document_path.name + ".sig")
    if is_link(document_path) or is_link(signature_path):
        fail(f"signed document and signature must not be symbolic links: {document_path}")
    try:
        verifier.verify(read_signature(signature_path), document_path.read_bytes())
    except MarketplaceValidationError:
        raise
    except Exception as error:  # cryptography intentionally hides signature detail.
        fail(f"Ed25519 signature verification failed for {document_path}: {error.__class__.__name__}")


def safe_relative_path(value: object, label: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or value != value.strip():
        fail(f"{label} must be a non-empty relative path")
    if "\\" in value or "%" in value:
        fail(f"{label} must use unescaped forward-slash relative paths")
    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
        fail(f"{label} must not be a URL")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} or ":" in part for part in path.parts):
        fail(f"{label} must not escape its release directory")
    return path


def resolve_below(base: Path, relative: PurePosixPath, label: str) -> Path:
    current = base
    for part in relative.parts:
        current = current / part
        if is_link(current):
            fail(f"{label} must not traverse symbolic links")
    try:
        resolved = current.resolve(strict=True)
        resolved.relative_to(base.resolve(strict=True))
    except (OSError, ValueError) as error:
        fail(f"{label} must resolve to a regular file below its release directory: {error}")
    if not resolved.is_file():
        fail(f"{label} must resolve to a regular file")
    return resolved


def desktop_entrypoints(manifest: dict[str, object], label: str) -> list[tuple[str, PurePosixPath]]:
    """Validate the XSEC entrypoint declaration shared by source and archives."""

    try:
        desktop = manifest["extensions"]["com.xsec.desktop"]
    except (KeyError, TypeError):
        fail(f"{label} lacks XSEC Desktop extension metadata")
    if not isinstance(desktop, dict):
        fail(f"{label} has invalid XSEC Desktop extension metadata")
    entrypoints = desktop.get("entrypoints")
    if not isinstance(entrypoints, dict) or not entrypoints:
        fail(f"{label} must declare at least one XSEC Desktop entrypoint")

    result: list[tuple[str, PurePosixPath]] = []
    for name, value in entrypoints.items():
        if not isinstance(name, str) or not ENTRYPOINT_NAME.fullmatch(name):
            fail(f"{label} has an invalid XSEC Desktop entrypoint name")
        relative = safe_relative_path(value, f"{label} entrypoint {name}")
        result.append((name, relative))
    return result


def zip_member_is_regular_file(info: zipfile.ZipInfo) -> bool:
    mode = info.external_attr >> 16
    return not info.is_dir() and stat.S_IFMT(mode) in {0, stat.S_IFREG}


def target_filesystem_path(path: PurePosixPath, name: str) -> str:
    """Normalize a ZIP member as a Windows-compatible installer would."""

    parts: list[str] = []
    for part in path.parts:
        nfc_part = unicodedata.normalize("NFC", part)
        if any(character in WINDOWS_FORBIDDEN_COMPONENT_CHARACTERS for character in nfc_part):
            fail(f"archive contains a Windows-forbidden character in path component {part!r} of {name!r}")
        if any(ord(character) <= 0x1F for character in nfc_part):
            fail(f"archive contains a Windows control character in path component {part!r} of {name!r}")
        trimmed_part = nfc_part.rstrip(" .")
        normalized_part = trimmed_part.casefold()
        if not normalized_part:
            fail(f"archive contains an empty target filesystem path component in {name!r}")
        device_name = trimmed_part.split(".", 1)[0].casefold()
        if device_name in WINDOWS_RESERVED_DEVICE_NAMES:
            fail(f"archive contains a Windows reserved device-name component {part!r} in {name!r}")
        parts.append(normalized_part)
    return "/".join(parts)


def validate_zip_member(name: str, info: zipfile.ZipInfo, seen: set[str]) -> None:
    if "\\" in name or name.startswith("/"):
        fail(f"archive contains unsafe entry path {name!r}")
    path = PurePosixPath(name)
    if not name or path.is_absolute() or not path.parts or any(part in {"", ".", ".."} or ":" in part for part in path.parts):
        fail(f"archive contains unsafe entry path {name!r}")
    normalized_name = target_filesystem_path(path, name)
    if normalized_name in seen:
        fail(f"archive contains duplicate or target-filesystem collision for entry {name!r}")
    seen.add(normalized_name)
    if info.flag_bits & 0x1:
        fail(f"archive entry {name!r} must not be encrypted")
    mode = info.external_attr >> 16
    if stat.S_ISLNK(mode):
        fail(f"archive entry {name!r} must not be a symbolic link")
    kind = stat.S_IFMT(mode)
    if kind not in {0, stat.S_IFREG, stat.S_IFDIR}:
        fail(f"archive entry {name!r} must be a regular file or directory")


def validate_archive(path: Path, plugin_id: str, version: str) -> dict[str, object]:
    if not zipfile.is_zipfile(path):
        fail(f"artifact {path} is not a ZIP archive")
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if not infos or len(infos) > MAX_ZIP_ENTRIES:
                fail(f"artifact {path} has an invalid number of entries")
            seen: set[str] = set()
            members: dict[str, zipfile.ZipInfo] = {}
            total_size = 0
            for info in infos:
                validate_zip_member(info.filename, info, seen)
                members[PurePosixPath(info.filename).as_posix()] = info
                if info.file_size > MAX_ZIP_FILE_BYTES:
                    fail(f"archive entry {info.filename!r} exceeds the uncompressed size limit")
                total_size += info.file_size
                if total_size > MAX_ZIP_UNCOMPRESSED_BYTES:
                    fail(f"artifact {path} exceeds the total uncompressed size limit")
                if info.file_size and (not info.compress_size or info.file_size / info.compress_size > MAX_ZIP_COMPRESSION_RATIO):
                    fail(f"archive entry {info.filename!r} exceeds the compression-ratio limit")
            try:
                manifest_bytes = archive.read("plugin.json")
            except KeyError:
                fail(f"artifact {path} does not include root plugin.json")
    except (OSError, zipfile.BadZipFile, RuntimeError) as error:
        fail(f"cannot safely read artifact {path}: {error}")
    if len(manifest_bytes) > MAX_ZIP_FILE_BYTES:
        fail(f"artifact {path} plugin.json exceeds the size limit")
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"artifact {path} plugin.json is invalid: {error}")
    if not isinstance(manifest, dict):
        fail(f"artifact {path} plugin.json must be an object")
    if manifest.get("name") != plugin_id:
        fail(f"artifact {path} plugin.json name does not match {plugin_id}")
    if manifest.get("version") != version:
        fail(f"artifact {path} plugin.json version does not match {version}")
    for entrypoint_name, entrypoint_path in desktop_entrypoints(manifest, f"artifact {path} plugin.json"):
        entrypoint = members.get(entrypoint_path.as_posix())
        if entrypoint is None:
            fail(f"artifact {path} does not include XSEC Desktop entrypoint {entrypoint_name} at {entrypoint_path.as_posix()}")
        if not zip_member_is_regular_file(entrypoint):
            fail(f"artifact {path} XSEC Desktop entrypoint {entrypoint_name} must be a regular file")
    return manifest


def marketplace_entries(root: Path) -> list[tuple[str, Path, dict[str, object]]]:
    marketplace_path = root / MARKETPLACE_RELATIVE_PATH
    if is_link(marketplace_path):
        fail("marketplace metadata must not be a symbolic link")
    marketplace = read_json(marketplace_path, str(marketplace_path))
    if marketplace.get("name") != "xsec-official":
        fail("marketplace name must be xsec-official")
    entries = marketplace.get("plugins")
    if not isinstance(entries, list):
        fail("marketplace plugins must be a list")
    result: list[tuple[str, Path, dict[str, object]]] = []
    seen_ids: set[str] = set()
    default_ids: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            fail("marketplace entries must be objects")
        plugin_id = entry.get("name")
        if not isinstance(plugin_id, str) or not plugin_id:
            fail("marketplace entry name must be a non-empty string")
        if plugin_id in seen_ids:
            fail(f"marketplace contains duplicate plugin {plugin_id}")
        seen_ids.add(plugin_id)
        source = entry.get("source")
        if not isinstance(source, dict) or source.get("source") != "local":
            fail(f"marketplace plugin {plugin_id} must use a local source")
        source_path = source.get("path")
        expected_path = f"./plugins/{plugin_id}"
        if source_path != expected_path:
            fail(f"marketplace plugin {plugin_id} source.path must be {expected_path}")
        plugin_dir = root / "plugins" / plugin_id
        if is_link(plugin_dir) or not plugin_dir.is_dir():
            fail(f"marketplace plugin {plugin_id} source directory is unavailable or a symbolic link")
        policy = entry.get("policy")
        if not isinstance(policy, dict):
            fail(f"marketplace plugin {plugin_id} must have an installation policy")
        if policy.get("installation") == "INSTALLED_BY_DEFAULT":
            if policy.get("authentication") != "ON_INSTALL":
                fail(f"default marketplace plugin {plugin_id} must authenticate on install")
            default_ids.add(plugin_id)
        result.append((plugin_id, plugin_dir, entry))
    if default_ids != set(DEFAULT_OFFICIAL_PLUGIN_IDS):
        missing = sorted(set(DEFAULT_OFFICIAL_PLUGIN_IDS) - default_ids)
        unexpected = sorted(default_ids - set(DEFAULT_OFFICIAL_PLUGIN_IDS))
        fail(f"default official plugin set mismatch (missing={missing}, unexpected={unexpected})")
    return result


def validate_release(plugin_id: str, plugin_dir: Path) -> list[tuple[Path, str, dict[str, object]]]:
    release_path = plugin_dir / ".xsec-market" / "releases.json"
    if is_link(release_path.parent) or is_link(release_path):
        fail(f"release metadata for {plugin_id} must not use symbolic links")
    release = read_json(release_path, str(release_path))
    if release.get("schemaVersion") != 1 or release.get("pluginId") != plugin_id:
        fail(f"release metadata for {plugin_id} has an invalid schemaVersion or pluginId")
    releases = release.get("releases")
    if not isinstance(releases, list) or not releases:
        fail(f"release metadata for {plugin_id} must have at least one release")
    result: list[tuple[Path, str, dict[str, object]]] = []
    seen_release_keys: set[tuple[str, str]] = set()
    for item in releases:
        if not isinstance(item, dict):
            fail(f"release metadata for {plugin_id} contains a non-object release")
        version, channel = item.get("version"), item.get("channel")
        if not isinstance(version, str) or not version or not isinstance(channel, str) or not channel:
            fail(f"release metadata for {plugin_id} has an invalid version or channel")
        if (version, channel) in seen_release_keys:
            fail(f"release metadata for {plugin_id} duplicates {version}/{channel}")
        seen_release_keys.add((version, channel))
        artifacts = item.get("artifacts")
        if not isinstance(artifacts, list) or not artifacts:
            fail(f"release metadata for {plugin_id} {version}/{channel} has no artifacts")
        for artifact in artifacts:
            if not isinstance(artifact, dict):
                fail(f"release metadata for {plugin_id} contains a non-object artifact")
            if not isinstance(artifact.get("os"), str) or not isinstance(artifact.get("arch"), str):
                fail(f"release metadata for {plugin_id} artifact must have os and arch")
            digest = artifact.get("sha256")
            if not isinstance(digest, str) or len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
                fail(f"release metadata for {plugin_id} has a non-canonical SHA-256 digest")
            relative = safe_relative_path(artifact.get("url"), f"artifact URL for {plugin_id}")
            artifact_path = resolve_below(release_path.parent, relative, f"artifact URL for {plugin_id}")
            if sha256(artifact_path) != digest:
                fail(f"artifact SHA-256 does not match release metadata for {plugin_id}")
            manifest = validate_archive(artifact_path, plugin_id, version)
            result.append((artifact_path, version, manifest))
    return result


def validate_source_manifest(plugin_id: str, plugin_dir: Path) -> dict[str, object]:
    manifest = read_json(plugin_dir / "plugin.json", f"plugin manifest for {plugin_id}")
    if manifest.get("name") != plugin_id:
        fail(f"plugin manifest name does not match marketplace entry {plugin_id}")
    if not isinstance(manifest.get("version"), str) or not manifest["version"]:
        fail(f"plugin manifest {plugin_id} has no version")
    try:
        engines = manifest["extensions"]["com.xsec.desktop"]["engines"]
    except (KeyError, TypeError):
        fail(f"plugin manifest {plugin_id} lacks XSEC Desktop engine metadata")
    if not isinstance(engines, dict):
        fail(f"plugin manifest {plugin_id} has invalid XSEC Desktop engine metadata")
    for entrypoint_name, entrypoint_path in desktop_entrypoints(manifest, f"plugin manifest {plugin_id}"):
        resolve_below(plugin_dir, entrypoint_path, f"plugin manifest {plugin_id} entrypoint {entrypoint_name}")
    return manifest


def validate_source(source_root: Path, built_root: Path) -> None:
    source_entries = marketplace_entries(source_root)
    built_entries = marketplace_entries(built_root)
    if (source_root / MARKETPLACE_RELATIVE_PATH).read_bytes() != (built_root / MARKETPLACE_RELATIVE_PATH).read_bytes():
        fail("temporary marketplace metadata differs from source metadata")
    built_by_id = {plugin_id: plugin_dir for plugin_id, plugin_dir, _ in built_entries}
    if {plugin_id for plugin_id, _, _ in source_entries} != set(built_by_id):
        fail("temporary marketplace plugin set differs from source plugin set")
    for plugin_id, source_dir, _ in source_entries:
        source_manifest = validate_source_manifest(plugin_id, source_dir)
        built_plugin_dir = built_by_id[plugin_id]
        generated_release = read_json(
            built_plugin_dir / ".xsec-market" / "releases.json",
            f"temporary release metadata for {plugin_id}",
        )
        generated_releases = generated_release.get("releases")
        if not isinstance(generated_releases, list) or len(generated_releases) != 1 or not isinstance(generated_releases[0], dict):
            fail(f"temporary output for {plugin_id} must contain exactly one stable release")
        generated_item = generated_releases[0]
        if (
            generated_item.get("version") != source_manifest["version"]
            or generated_item.get("channel") != "stable"
            or generated_item.get("engines") != source_manifest["extensions"]["com.xsec.desktop"]["engines"]
        ):
            fail(f"temporary release metadata for {plugin_id} does not match its source manifest")
        artifacts = validate_release(plugin_id, built_plugin_dir)
        expected_artifact_name = f"{plugin_id}-{source_manifest['version']}-any-any.xsec-plugin"
        if len(artifacts) != 1 or artifacts[0][0].name != expected_artifact_name or artifacts[0][1] != source_manifest["version"]:
            fail(f"temporary output for {plugin_id} does not contain exactly its current stable artifact")
        with tempfile.TemporaryDirectory(prefix="xsec-market-repro-") as directory:
            reproducible = Path(directory) / expected_artifact_name
            write_zip(source_dir, reproducible)
            if reproducible.read_bytes() != artifacts[0][0].read_bytes():
                fail(f"artifact for {plugin_id} is not deterministic from its source tree")


def validate_published(root: Path, public_key_b64: str) -> None:
    verifier = raw_ed25519_public_key(public_key_b64, "official marketplace public key")
    marketplace_path = root / MARKETPLACE_RELATIVE_PATH
    verify_signature(marketplace_path, verifier)
    for plugin_id, plugin_dir, _ in marketplace_entries(root):
        release_path = plugin_dir / ".xsec-market" / "releases.json"
        verify_signature(release_path, verifier)
        validate_source_manifest(plugin_id, plugin_dir)
        validate_release(plugin_id, plugin_dir)


def validate_signing_key(public_key_b64: str) -> None:
    key = signing_key()
    if key is None:
        fail("XSEC_MARKETPLACE_SIGNING_KEY_B64 is required for signing-key validation")
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    expected = raw_ed25519_public_key(public_key_b64, "official marketplace public key").public_bytes(Encoding.Raw, PublicFormat.Raw)
    actual = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    if actual != expected:
        fail("configured marketplace signing key does not match the Desktop-pinned public key")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    source_parser = subcommands.add_parser("source", help="validate source and a temporary unsigned build")
    source_parser.add_argument("--source-root", type=Path, default=ROOT)
    source_parser.add_argument("--built-root", type=Path, required=True)
    published_parser = subcommands.add_parser("published", help="validate signed published artifacts")
    published_parser.add_argument("--root", type=Path, default=ROOT)
    published_parser.add_argument("--public-key-b64", default=OFFICIAL_MARKETPLACE_PUBLIC_KEY_B64)
    signing_parser = subcommands.add_parser("signing-key", help="check CI signing seed against Desktop trust root")
    signing_parser.add_argument("--public-key-b64", default=OFFICIAL_MARKETPLACE_PUBLIC_KEY_B64)
    args = parser.parse_args()
    try:
        if args.command == "source":
            validate_source(args.source_root.resolve(), args.built_root.resolve())
        elif args.command == "published":
            validate_published(args.root.resolve(), args.public_key_b64)
        else:
            validate_signing_key(args.public_key_b64)
    except MarketplaceValidationError as error:
        raise SystemExit(f"marketplace validation failed: {error}") from error
    print(f"marketplace {args.command} validation passed")


if __name__ == "__main__":
    main()
