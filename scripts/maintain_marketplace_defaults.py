#!/usr/bin/env python3
"""Apply the reviewed host-owned project workspace Marketplace transition."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


PROJECT_WORKSPACE_PLUGIN_ID = "com.xsec.project-workspace"
MARKETPLACE_PATH = Path(".agents/plugins/marketplace.json")
REGISTRY_PATH = Path(".xsec-factory/official-registry.json")


class MarketplaceDefaultsMaintenanceError(ValueError):
    """The protected default-set transition is malformed."""


def fail(message: str) -> None:
    raise MarketplaceDefaultsMaintenanceError(message)


def read_object(path: Path, label: str) -> dict[str, object]:
    if path.is_symlink() or not path.is_file():
        fail(f"{label} must be a regular file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MarketplaceDefaultsMaintenanceError(f"{label} cannot be read") from error
    if not isinstance(value, dict):
        fail(f"{label} must be a JSON object")
    return value


def write_object(path: Path, value: dict[str, object]) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def registry_entry(document: dict[str, object]) -> dict[str, object]:
    if document.get("schemaVersion") != 2 or not isinstance(document.get("plugins"), list):
        fail("official Factory registry must use schemaVersion 2 with a plugin list")
    matches = [
        entry
        for entry in document["plugins"]
        if isinstance(entry, dict) and entry.get("pluginId") == PROJECT_WORKSPACE_PLUGIN_ID
    ]
    if len(matches) != 1:
        fail("official Factory registry must contain one project workspace entry")
    entry = matches[0]
    if entry.get("trustTier") != "first-party":
        fail("project workspace must remain a first-party retained package")
    if entry.get("policy") != {"installation": "INSTALLED_BY_DEFAULT", "authentication": "ON_INSTALL"}:
        fail("project workspace Registry policy is invalid")
    if entry.get("status") not in {"active", "disabled"}:
        fail("project workspace Registry status cannot enter the reviewed transition")
    return entry


def marketplace_matches(document: dict[str, object]) -> tuple[list[object], list[int]]:
    plugins = document.get("plugins")
    if not isinstance(plugins, list):
        fail("official Marketplace index must contain a plugin list")
    matches = [
        index
        for index, entry in enumerate(plugins)
        if isinstance(entry, dict) and entry.get("name") == PROJECT_WORKSPACE_PLUGIN_ID
    ]
    if len(matches) > 1:
        fail("official Marketplace index contains duplicate project workspace entries")
    return plugins, matches


def apply_transition(root: Path) -> bool:
    marketplace_path = root / MARKETPLACE_PATH
    registry_path = root / REGISTRY_PATH
    marketplace = read_object(marketplace_path, "official Marketplace index")
    registry = read_object(registry_path, "official Factory registry")
    entry = registry_entry(registry)
    plugins, matches = marketplace_matches(marketplace)
    status = entry["status"]
    if status == "disabled" and not matches:
        return False
    if status != "active" or len(matches) != 1:
        fail("project workspace discovery and Registry status are not in one atomic state")
    entry["status"] = "disabled"
    del plugins[matches[0]]
    write_object(registry_path, registry)
    write_object(marketplace_path, marketplace)
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        changed = apply_transition(args.root.resolve(strict=True))
    except (MarketplaceDefaultsMaintenanceError, OSError) as error:
        print(f"Marketplace default-set maintenance failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"changed": changed}, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
