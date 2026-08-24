#!/usr/bin/env python3
"""Build deterministic XSEC plugin artifacts and unsigned marketplace metadata.

The default output is the repository itself, for the protected publishing
workflow. Validation and pull-request jobs must instead supply ``--output-root``
to make a complete, disposable marketplace tree without touching tracked
release artifacts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MARKETPLACE_RELATIVE_PATH = Path(".agents") / "plugins" / "marketplace.json"
MARKETPLACE = ROOT / MARKETPLACE_RELATIVE_PATH
PLUGIN_ROOT = ROOT / "plugins"
ARTIFACT_DIR_NAME = "artifacts"
EXCLUDED_PARTS = {"__pycache__", ".git", ".xsec-market"}


def is_link(path: Path) -> bool:
    """Cover POSIX links and Windows directory junctions before filesystem writes."""

    return path.is_symlink() or getattr(path, "is_junction", lambda: False)()


def stable_json(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


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
        # validation tree include files outside the plugin package.
        iter_plugin_files(source_dir)
        shutil.copytree(
            source_dir,
            output_root / "plugins" / source_dir.name,
            ignore=shutil.ignore_patterns(".xsec-market", "__pycache__", ".git"),
        )


def clean_generated_output(output_root: Path) -> None:
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
        shutil.rmtree(release_root)
    marketplace_path = output_root / MARKETPLACE_RELATIVE_PATH
    for suffix in (".sig", ".sig.jws.json"):
        marketplace_path.with_name(marketplace_path.name + suffix).unlink(missing_ok=True)


def build_plugin(source_plugin_dir: Path, output_plugin_dir: Path) -> None:
    manifest = json.loads((source_plugin_dir / "plugin.json").read_text(encoding="utf-8"))
    plugin_id = safe_artifact_component(manifest.get("name"), "plugin manifest name")
    version = safe_artifact_component(manifest.get("version"), "plugin manifest version")
    release_root = output_plugin_dir / ".xsec-market"
    artifact_dir = release_root / ARTIFACT_DIR_NAME
    artifact_name = f"{plugin_id}-{version}-any-any.xsec-plugin"
    artifact = path_below(artifact_dir, artifact_name, "artifact path")
    write_zip(source_plugin_dir, artifact)
    release = {
        "schemaVersion": 1,
        "pluginId": plugin_id,
        "releases": [
            {
                "version": version,
                "channel": "stable",
                "engines": manifest["extensions"]["com.xsec.desktop"]["engines"],
                "artifacts": [
                    {
                        "os": "any",
                        "arch": "any",
                        "url": f"{ARTIFACT_DIR_NAME}/{artifact_name}",
                        "sha256": sha256(artifact),
                    }
                ],
            }
        ],
    }
    release_path = release_root / "releases.json"
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
