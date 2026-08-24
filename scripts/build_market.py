#!/usr/bin/env python3
"""Build deterministic XSEC plugin artifacts and signed marketplace metadata.

The source tree is intentionally compatible with the Codex marketplace format:
`.agents/plugins/marketplace.json` indexes plugin roots while every root also
contains an XSEC Agent Plugins manifest.  Release metadata is kept in the
XSEC-specific `.xsec-market` namespace so it does not extend the Codex index.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MARKETPLACE = ROOT / ".agents" / "plugins" / "marketplace.json"
PLUGIN_ROOT = ROOT / "plugins"
ARTIFACT_DIR_NAME = "artifacts"
EXCLUDED_PARTS = {"__pycache__", ".git", ".xsec-market"}


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


def signing_key():
    encoded = os.environ.get("XSEC_MARKETPLACE_SIGNING_KEY_B64")
    if not encoded:
        return None
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    seed = base64.b64decode(encoded)
    if len(seed) != 32:
        raise ValueError("XSEC_MARKETPLACE_SIGNING_KEY_B64 must decode to an Ed25519 32-byte seed")
    return Ed25519PrivateKey.from_private_bytes(seed)


def sign(path: Path, key) -> None:
    signature = key.sign(path.read_bytes())
    path.with_name(path.name + ".sig").write_text(base64.b64encode(signature).decode("ascii") + "\n", encoding="ascii")


def write_zip(plugin_dir: Path, destination: Path) -> None:
    files = []
    for path in plugin_dir.rglob("*"):
        if not path.is_file() or any(part in EXCLUDED_PARTS for part in path.relative_to(plugin_dir).parts):
            continue
        files.append(path)
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(files, key=lambda item: item.relative_to(plugin_dir).as_posix()):
            info = zipfile.ZipInfo(path.relative_to(plugin_dir).as_posix())
            info.date_time = (2024, 1, 1, 0, 0, 0)
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, path.read_bytes())


def build_plugin(plugin_dir: Path, key, allow_unsigned: bool) -> None:
    manifest = json.loads((plugin_dir / "plugin.json").read_text(encoding="utf-8"))
    plugin_id = manifest["name"]
    version = manifest["version"]
    release_root = plugin_dir / ".xsec-market"
    artifact_dir = release_root / ARTIFACT_DIR_NAME
    artifact_dir.mkdir(parents=True, exist_ok=True)
    artifact_name = f"{plugin_id}-{version}-any-any.xsec-plugin"
    artifact = artifact_dir / artifact_name
    write_zip(plugin_dir, artifact)
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
    release_path.write_bytes(stable_json(release))
    signature_path = release_path.with_name(release_path.name + ".sig")
    if key:
        sign(release_path, key)
    elif allow_unsigned:
        signature_path.unlink(missing_ok=True)
    else:
        raise RuntimeError("a signing key is required; pass --allow-unsigned only for local development")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--allow-unsigned", action="store_true")
    parser.add_argument("--clean", action="store_true")
    args = parser.parse_args()

    key = signing_key()
    if args.clean:
        for artifact_dir in PLUGIN_ROOT.glob(f"*/.xsec-market/{ARTIFACT_DIR_NAME}"):
            shutil.rmtree(artifact_dir)
    entries = json.loads(MARKETPLACE.read_text(encoding="utf-8"))["plugins"]
    for entry in entries:
        plugin_dir = ROOT / entry["source"]["path"]
        build_plugin(plugin_dir, key, args.allow_unsigned)
    if key:
        sign(MARKETPLACE, key)
    elif args.allow_unsigned:
        MARKETPLACE.with_name(MARKETPLACE.name + ".sig").unlink(missing_ok=True)


if __name__ == "__main__":
    main()
