#!/usr/bin/env python3
"""Synchronize official manifest metadata without generating placeholder UI.

The marketplace owns every executable frontend. This helper intentionally does
not create one: a missing frontend is a release failure, not a reason to fall
back to a Desktop-bundled renderer or a misleading success screen.
"""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

from build_market import SNAPSHOT_ROOT_RELATIVE_PATH
from marketplace_contract import OFFICIAL_PLUGIN_IDS, active_official_plugin_policies


ROOT = Path(__file__).resolve().parents[1]
PLUGIN_IDS = list(OFFICIAL_PLUGIN_IDS)


def codex_manifest(manifest: dict[str, object]) -> dict[str, object]:
    extension = manifest["extensions"]["com.xsec.desktop"]
    display_name = extension["displayName"]
    return {
        "name": manifest["name"],
        "version": manifest["version"],
        "description": manifest["description"],
        "author": manifest["author"],
        "license": manifest["license"],
        "repository": "https://github.com/tzf1003/xsec-plugins",
        "interface": {
            "displayName": display_name,
            "shortDescription": manifest["description"],
            "longDescription": f"XSEC 官方插件：{display_name}。可在 XSEC 插件市场安装、禁用和更新。",
            "developerName": "XSEC",
            "category": "Security",
            "capabilities": ["XSEC Desktop"],
            "websiteURL": "https://github.com/tzf1003/xsec-plugins",
            "defaultPrompt": [f"打开 {display_name}"],
            "brandColor": "#4F7CFF",
        },
    }


def marketplace_entry(plugin_id: str, policy: dict[str, str]) -> dict[str, object]:
    return {
        "name": plugin_id,
        "source": {"source": "local", "path": f"./.xsec-factory/snapshots/{plugin_id}"},
        "policy": policy,
        "category": "Security",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("desktop_plugins", type=Path)
    args = parser.parse_args()
    source_root = args.desktop_plugins.resolve()
    active_plugins = active_official_plugin_policies(ROOT)
    active_plugin_ids = tuple(plugin_id for plugin_id, _ in active_plugins)
    unknown_active_ids = set(active_plugin_ids).difference(PLUGIN_IDS)
    if unknown_active_ids:
        names = ", ".join(sorted(unknown_active_ids))
        raise ValueError(f"active Registry plugins are not retained official packages: {names}")
    for plugin_id in PLUGIN_IDS:
        source = source_root / plugin_id / "plugin.json"
        if not source.is_file():
            raise FileNotFoundError(source)
        destination = ROOT / SNAPSHOT_ROOT_RELATIVE_PATH / plugin_id
        destination.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination / "plugin.json")
        manifest = json.loads(source.read_text(encoding="utf-8"))
        codex_dir = destination / ".codex-plugin"
        codex_dir.mkdir(exist_ok=True)
        (codex_dir / "plugin.json").write_text(
            json.dumps(codex_manifest(manifest), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        frontend = destination / "com.xsec.desktop" / "frontend" / "index.js"
        if not frontend.is_file():
            raise FileNotFoundError(
                f"official plugin frontend must be maintained in xsec-plugins: {frontend}"
            )
    index = {
        "name": "xsec-official",
        "interface": {"displayName": "XSEC 官方插件市场"},
        "plugins": [
            marketplace_entry(plugin_id, policy)
            for plugin_id, policy in active_plugins
        ],
    }
    index_path = ROOT / ".agents" / "plugins" / "marketplace.json"
    index_path.parent.mkdir(parents=True, exist_ok=True)
    index_path.write_text(json.dumps(index, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
