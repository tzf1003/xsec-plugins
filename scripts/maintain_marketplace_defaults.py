#!/usr/bin/env python3
"""Apply the reviewed Marketplace default-set transition."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


PROJECT_WORKSPACE_PLUGIN_ID = "com.xsec.project-workspace"
ATTACK_PATH_PLUGIN_ID = "com.xsec.attack-path"
MARKETPLACE_PATH = Path(".agents/plugins/marketplace.json")
REGISTRY_PATH = Path(".xsec-factory/official-registry.json")
DEFAULT_POLICY = {"installation": "INSTALLED_BY_DEFAULT", "authentication": "ON_INSTALL"}
AVAILABLE_POLICY = {"installation": "AVAILABLE", "authentication": "ON_INSTALL"}


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


def registry_entry(document: dict[str, object], plugin_id: str) -> dict[str, object]:
    if document.get("schemaVersion") != 2 or not isinstance(document.get("plugins"), list):
        fail("official Factory registry must use schemaVersion 2 with a plugin list")
    matches = [
        entry
        for entry in document["plugins"]
        if isinstance(entry, dict) and entry.get("pluginId") == plugin_id
    ]
    if len(matches) != 1:
        fail(f"official Factory registry must contain one {plugin_id} entry")
    entry = matches[0]
    if entry.get("trustTier") != "first-party":
        fail(f"{plugin_id} must remain a first-party retained package")
    return entry


def marketplace_matches(document: dict[str, object], plugin_id: str) -> tuple[list[object], list[int]]:
    plugins = document.get("plugins")
    if not isinstance(plugins, list):
        fail("official Marketplace index must contain a plugin list")
    matches = [
        index
        for index, entry in enumerate(plugins)
        if isinstance(entry, dict) and entry.get("name") == plugin_id
    ]
    if len(matches) > 1:
        fail(f"official Marketplace index contains duplicate {plugin_id} entries")
    return plugins, matches


def disable_project_workspace(registry: dict[str, object], marketplace: dict[str, object]) -> bool:
    entry = registry_entry(registry, PROJECT_WORKSPACE_PLUGIN_ID)
    plugins, matches = marketplace_matches(marketplace, PROJECT_WORKSPACE_PLUGIN_ID)
    if entry.get("policy") != DEFAULT_POLICY or entry.get("status") not in {"active", "disabled"}:
        fail("project workspace Registry policy or status is invalid")
    if entry["status"] == "disabled" and not matches:
        return False
    if entry["status"] != "active" or len(matches) != 1:
        fail("project workspace discovery and Registry status are not in one atomic state")
    entry["status"] = "disabled"
    del plugins[matches[0]]
    return True


def make_attack_path_available(registry: dict[str, object], marketplace: dict[str, object]) -> bool:
    entry = registry_entry(registry, ATTACK_PATH_PLUGIN_ID)
    plugins, matches = marketplace_matches(marketplace, ATTACK_PATH_PLUGIN_ID)
    if entry.get("status") != "active" or len(matches) != 1:
        fail("attack path discovery and Registry status are not in one atomic state")
    market_entry = plugins[matches[0]]
    if not isinstance(market_entry, dict):
        fail("attack path Marketplace entry is invalid")
    if entry.get("policy") == AVAILABLE_POLICY and market_entry.get("policy") == AVAILABLE_POLICY:
        return False
    if entry.get("policy") != DEFAULT_POLICY or market_entry.get("policy") != DEFAULT_POLICY:
        fail("attack path installation policy is not in one atomic state")
    entry["policy"] = dict(AVAILABLE_POLICY)
    market_entry["policy"] = dict(AVAILABLE_POLICY)
    return True


def apply_transition(root: Path) -> bool:
    marketplace_path = root / MARKETPLACE_PATH
    registry_path = root / REGISTRY_PATH
    marketplace = read_object(marketplace_path, "official Marketplace index")
    registry = read_object(registry_path, "official Factory registry")
    changed = disable_project_workspace(registry, marketplace)
    changed = make_attack_path_available(registry, marketplace) or changed
    if changed:
        write_object(registry_path, registry)
        write_object(marketplace_path, marketplace)
    return changed


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
