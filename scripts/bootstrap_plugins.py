#!/usr/bin/env python3
"""Bootstrap the official marketplace from the Desktop-owned manifest contract.

This intentionally copies only manifest metadata. Runtime UI is delivered by
Desktop's compatible official-plugin bridge while the package API is migrated;
the marker file makes that transitional ownership explicit instead of silently
shipping an empty frontend bundle.
"""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PLUGIN_IDS = [
    "com.xsec.asset-discovery",
    "com.xsec.attack-path",
    "com.xsec.project-workspace",
    "com.xsec.system-terminal",
    "com.xsec.workspace.approvals",
    "com.xsec.workspace.browser",
    "com.xsec.workspace.conversation-tree",
    "com.xsec.workspace.files",
    "com.xsec.workspace.project-outcomes",
    "com.xsec.workspace.sub-agent",
    "com.xsec.workspace.traffic",
]


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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("desktop_plugins", type=Path)
    args = parser.parse_args()
    source_root = args.desktop_plugins.resolve()
    entries = []
    for plugin_id in PLUGIN_IDS:
        source = source_root / plugin_id / "plugin.json"
        if not source.is_file():
            raise FileNotFoundError(source)
        destination = ROOT / "plugins" / plugin_id
        destination.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination / "plugin.json")
        manifest = json.loads(source.read_text(encoding="utf-8"))
        codex_dir = destination / ".codex-plugin"
        codex_dir.mkdir(exist_ok=True)
        (codex_dir / "plugin.json").write_text(
            json.dumps(codex_manifest(manifest), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        (destination / "OFFICIAL_PLUGIN_BRIDGE.md").write_text(
            "# Official plugin bridge\n\n"
            "This package owns the signed plugin manifest, permissions and release lifecycle. "
            "XSEC Desktop currently binds its compatible built-in renderer only after this package "
            "is installed and enabled. The bridge is intentionally explicit so package state, rather "
            "than the application installer, is the source of truth.\n",
            encoding="utf-8",
        )
        frontend = destination / "com.xsec.desktop" / "frontend" / "index.js"
        frontend.parent.mkdir(parents=True, exist_ok=True)
        frontend.write_text(
            "// The Desktop official-plugin bridge owns the compatible renderer.\n"
            "// This entrypoint keeps the signed package independently valid.\n"
            "document.body.textContent = 'XSEC official plugin is active in Desktop.';\n",
            encoding="utf-8",
        )
        entries.append({
            "name": plugin_id,
            "source": {"source": "local", "path": f"./plugins/{plugin_id}"},
            "policy": {"installation": "INSTALLED_BY_DEFAULT", "authentication": "ON_INSTALL"},
            "category": "Security",
        })
    index = {
        "name": "xsec-official",
        "interface": {"displayName": "XSEC 官方插件市场"},
        "plugins": entries,
    }
    index_path = ROOT / ".agents" / "plugins" / "marketplace.json"
    index_path.parent.mkdir(parents=True, exist_ok=True)
    index_path.write_text(json.dumps(index, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
