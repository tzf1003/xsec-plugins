from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from marketplace_contract import OFFICIAL_PLUGIN_IDS  # noqa: E402


class BootstrapPluginsTests(unittest.TestCase):
    def prepare_marketplace(self, root: Path) -> Path:
        source_root = root / "desktop-plugins"
        scripts_root = root / "scripts"
        scripts_root.mkdir(parents=True)
        for name in ("bootstrap_plugins.py", "build_market.py", "marketplace_contract.py"):
            shutil.copy2(ROOT / "scripts" / name, scripts_root / name)
        factory_root = root / ".xsec-factory"
        factory_root.mkdir()
        shutil.copy2(ROOT / factory_root.name / "official-registry.json", factory_root)
        for plugin_id in OFFICIAL_PLUGIN_IDS:
            snapshot = ROOT / factory_root.name / "snapshots" / plugin_id
            shutil.copytree(snapshot, factory_root / "snapshots" / plugin_id)
            source = source_root / plugin_id
            source.mkdir(parents=True)
            shutil.copy2(snapshot / "plugin.json", source / "plugin.json")
        return source_root

    def test_bootstrap_uses_active_registry_defaults_and_retains_disabled_snapshot(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-bootstrap-defaults-") as directory:
            root = Path(directory)
            source_root = self.prepare_marketplace(root)
            retained_frontend = (
                root / ".xsec-factory" / "snapshots" / "com.xsec.project-workspace"
                / "com.xsec.desktop" / "frontend" / "index.js"
            ).read_bytes()
            subprocess.run(
                [sys.executable, str(root / "scripts" / "bootstrap_plugins.py"), str(source_root)],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            )
            registry = json.loads((root / ".xsec-factory" / "official-registry.json").read_text())
            expected = [
                entry["pluginId"] for entry in registry["plugins"]
                if entry["trustTier"] == "first-party" and entry["status"] == "active"
            ]
            marketplace = json.loads((root / ".agents" / "plugins" / "marketplace.json").read_text())
            self.assertEqual([entry["name"] for entry in marketplace["plugins"]], expected)
            retained_path = (
                root / ".xsec-factory" / "snapshots" / "com.xsec.project-workspace"
                / "com.xsec.desktop" / "frontend" / "index.js"
            )
            self.assertEqual(retained_path.read_bytes(), retained_frontend)


if __name__ == "__main__":
    unittest.main()
