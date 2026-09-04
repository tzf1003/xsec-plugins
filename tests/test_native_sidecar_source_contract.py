from __future__ import annotations

import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_market  # noqa: E402
import native_sidecars  # noqa: E402
import validate_market  # noqa: E402


SOURCE_REVISION = "b" * 40


def write_native_source(root: Path, recipe: native_sidecars.NativeSidecarRecipe, servers: dict[str, object]) -> Path:
    source = root / recipe.plugin_id
    (source / "com.xsec.desktop" / "frontend").mkdir(parents=True)
    (source / "skills" / recipe.skill_id).mkdir(parents=True)
    manifest = {
        "name": recipe.plugin_id,
        "version": "2.1.0",
        "extensions": {"com.xsec.desktop": {
            "schemaVersion": 2,
            "engines": {"xsec": ">=0.1.0", "pluginApi": "^1.3.0"},
            "entrypoints": {"frontend": "com.xsec.desktop/frontend/index.js"},
            "permissions": {"mcp.servers.register": {}, "native.execute": {}},
        }},
    }
    (source / "plugin.json").write_text(json.dumps(manifest), encoding="utf-8")
    (source / "mcp.json").write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")
    (source / "com.xsec.desktop" / "frontend" / "index.js").write_text("export {};\n", encoding="utf-8")
    (source / "skills" / recipe.skill_id / "SKILL.md").write_text("# Native source\n", encoding="utf-8")
    return source


def sidecar_inputs(root: Path, recipe: native_sidecars.NativeSidecarRecipe) -> dict[tuple[str, str], Path]:
    inputs = {}
    for target in recipe.targets:
        binary = root / target.rust_target
        binary.write_bytes(target.rust_target.encode())
        inputs[(recipe.plugin_id, target.rust_target)] = binary
    return inputs


class NativeSidecarSourceContractTests(unittest.TestCase):
    def test_legacy_registered_sources_build_portable_any_artifacts(self) -> None:
        # Only cover allowlisted plugins whose snapshots have not opted into the
        # native sidecar contract yet. Adopted native snapshots are covered by
        # the explicit native contract / adoption tests instead.
        legacy_plugin_ids = [
            plugin_id
            for plugin_id in native_sidecars.RECIPES
            if native_sidecars.recipe_for_source(plugin_id, ROOT / ".xsec-factory" / "snapshots" / plugin_id) is None
        ]
        if not legacy_plugin_ids:
            self.skipTest("all registered recipes have opted into the native sidecar contract")
        for plugin_id in legacy_plugin_ids:
            source = ROOT / ".xsec-factory" / "snapshots" / plugin_id
            with self.subTest(plugin_id=plugin_id), tempfile.TemporaryDirectory(prefix="xsec-legacy-source-") as directory:
                output = Path(directory) / plugin_id
                self.assertIsNone(native_sidecars.recipe_for_source(plugin_id, source))
                build_market.build_plugin(source, output)
                validate_market.validate_release(plugin_id, output)
                release = json.loads((output / ".xsec-market" / "releases.json").read_text(encoding="utf-8"))
                self.assertEqual({(item["os"], item["arch"]) for item in release["releases"][0]["artifacts"]}, {("any", "any")})

    def test_native_contract_rejects_a_legacy_node_mcp_declaration(self) -> None:
        recipe = native_sidecars.ATTACK_PATH_RECIPE
        servers = {"attack-path": {"type": "stdio", "command": "node", "args": ["sidecar.js"], "cwd": "${PLUGIN_DATA}"}}
        with tempfile.TemporaryDirectory(prefix="xsec-native-contract-") as directory:
            source = write_native_source(Path(directory), recipe, servers)
            with self.assertRaisesRegex(ValueError, "must declare attack-path"):
                native_sidecars.recipe_for_source(recipe.plugin_id, source)

    def test_asset_discovery_native_contract_builds_all_platform_artifacts(self) -> None:
        recipe = native_sidecars.ASSET_DISCOVERY_RECIPE
        servers = {
            "asset-normalize": {"type": "stdio", "command": "./bin/asset-discovery-mcp", "cwd": "${PLUGIN_DATA}"},
            "asset-hunter": {"type": "stdio", "command": "./bin/asset-discovery-mcp", "args": ["--provider", "hunter"], "cwd": "${PLUGIN_DATA}", "env": {"XSEC_ASSET_HUNTER_API_BASE_URL": "https://hunter.qianxin.com/openApi/search"}},
            "asset-fofa": {"type": "stdio", "command": "./bin/asset-discovery-mcp", "args": ["--provider", "fofa"], "cwd": "${PLUGIN_DATA}", "env": {"XSEC_ASSET_FOFA_API_BASE_URL": "https://fofoapi.com"}},
        }
        with tempfile.TemporaryDirectory(prefix="xsec-asset-native-") as directory:
            root = Path(directory)
            source = write_native_source(root, recipe, servers)
            raw = (source / "mcp.json").read_bytes()
            invalid_args = json.loads(raw)
            invalid_args["mcpServers"]["asset-hunter"]["args"] = ["--provider", "fofa"]
            with self.assertRaisesRegex(ValueError, "invalid arguments for asset-hunter"):
                native_sidecars.validate_mcp_declaration(recipe, json.dumps(invalid_args).encode(), "asset mcp.json")
            for server in (
                {"remote-asset": {"type": "streamable-http", "url": "https://example.test/mcp"}},
                {"asset-hunter": {"type": "sse"}},
            ):
                invalid = json.loads(raw)
                invalid["mcpServers"].update(server)
                with self.assertRaisesRegex(ValueError, "must declare only the allowlisted stdio servers"):
                    native_sidecars.validate_mcp_declaration(recipe, json.dumps(invalid).encode(), "asset mcp.json")
            output = root / "output"
            inputs = sidecar_inputs(root, recipe)
            build_market.build_plugin(source, output, native_sidecar_inputs=inputs, native_sidecar_source_revision=SOURCE_REVISION)
            validate_market.validate_release(recipe.plugin_id, output)
            release = json.loads((output / ".xsec-market" / "releases.json").read_text(encoding="utf-8"))
            for artifact, target in zip(release["releases"][0]["artifacts"], recipe.targets, strict=True):
                with zipfile.ZipFile(output / ".xsec-market" / artifact["url"]) as archive:
                    entrypoint = native_sidecars.archive_path_for(recipe, target).as_posix()
                    self.assertEqual(archive.read(entrypoint), inputs[(recipe.plugin_id, target.rust_target)].read_bytes())


if __name__ == "__main__":
    unittest.main()
