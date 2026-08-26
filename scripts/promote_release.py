#!/usr/bin/env python3
"""Move a v2 stable channel pointer without rebuilding a plugin artifact.

This script is deliberately narrow: it refuses legacy metadata, does not read
or write artifact files, and can only select a release already present in the
checked-in immutable release list.  The protected workflow re-signs the
changed release document after this operation.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from build_market import RELEASE_ID_PATTERN, ROOT, is_link, load_release_document, stable_json


class PromotionError(ValueError):
    """A requested stable promotion is invalid or unsafe."""


def release_path(root: Path, plugin_id: str) -> Path:
    if not plugin_id or plugin_id in {".", ".."} or any(character in plugin_id for character in ("/", "\\", ":", "\x00")):
        raise PromotionError("plugin ID must be a safe marketplace directory name")
    candidate = root / "plugins" / plugin_id / ".xsec-market" / "releases.json"
    if is_link(candidate) or is_link(candidate.parent):
        raise PromotionError("release metadata must not use symbolic links")
    try:
        candidate.resolve(strict=True).relative_to(root.resolve(strict=True))
    except (OSError, ValueError) as error:
        raise PromotionError("release metadata must remain inside the marketplace root") from error
    return candidate


def promote_stable(root: Path, plugin_id: str, target_release_id: str) -> bool:
    """Update just `channels.stable.releaseId`; return whether bytes changed."""

    if not RELEASE_ID_PATTERN.fullmatch(target_release_id):
        raise PromotionError("release ID must be a canonical content-addressed releaseId")
    path = release_path(root, plugin_id)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PromotionError("release metadata is not valid UTF-8 JSON") from error
    if not isinstance(raw, dict) or raw.get("schemaVersion") != 2:
        raise PromotionError("stable promotion requires schema v2 release metadata")
    try:
        document = load_release_document(path, plugin_id)
    except ValueError as error:
        raise PromotionError(str(error)) from error
    releases = document["releases"]
    if not isinstance(releases, list) or target_release_id not in {item.get("releaseId") for item in releases if isinstance(item, dict)}:
        raise PromotionError("stable promotion target is not an existing immutable release")
    channels = document["channels"]
    if not isinstance(channels, dict):  # guarded by load_release_document
        raise PromotionError("release metadata has invalid channel pointers")
    current = channels.get("stable")
    if isinstance(current, dict) and current.get("releaseId") == target_release_id:
        return False
    channels["stable"] = {"releaseId": target_release_id}
    path.write_bytes(stable_json(document))
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plugin-id", required=True)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    try:
        changed = promote_stable(args.root.resolve(), args.plugin_id, args.release_id)
    except PromotionError as error:
        raise SystemExit(f"stable promotion failed: {error}") from error
    print("stable channel pointer updated" if changed else "stable channel pointer already selected")


if __name__ == "__main__":
    main()
