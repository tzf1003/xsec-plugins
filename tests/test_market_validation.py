from __future__ import annotations

from contextlib import nullcontext
import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import build_market  # noqa: E402
import promote_release  # noqa: E402
import validate_market  # noqa: E402
from validate_market import (  # noqa: E402
    MarketplaceValidationError,
    validate_archive,
    validate_source_manifest,
    validate_source,
)


def snapshot_dir(root: Path, plugin_id: str) -> Path:
    return root / build_market.SNAPSHOT_ROOT_RELATIVE_PATH / plugin_id


class MarketplaceValidationTests(unittest.TestCase):
    maxDiff = None

    def build_marketplace(self, destination: Path) -> None:
        command = [
            sys.executable,
            "scripts/build_market.py",
            "--clean",
            "--output-root",
            str(destination),
        ]
        subprocess.run(command, cwd=ROOT, check=True, capture_output=True, text=True)

    def test_source_gate_accepts_disposable_unsigned_output(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-source-test-") as directory:
            output = Path(directory) / "marketplace"
            self.build_marketplace(output)
            validate_source(ROOT, output)

    def test_official_plugin_settings_pages_and_plugin_bound_rpcs_are_declared(self) -> None:
        """The six reviewed settings surfaces remain field-renderable packages."""

        contracts = validate_market.OFFICIAL_PLUGIN_SETTINGS_CONTRACT
        self.assertEqual(set(contracts), {
            "com.xsec.asset-discovery",
            "com.xsec.project-workspace",
            "com.xsec.system-terminal",
            "com.xsec.workspace.approvals",
            "com.xsec.workspace.browser",
            "com.xsec.workspace.traffic",
        })
        for plugin_id, contract in contracts.items():
            with self.subTest(plugin_id=plugin_id):
                plugin_dir = snapshot_dir(ROOT, plugin_id)
                manifest = json.loads((plugin_dir / "plugin.json").read_text(encoding="utf-8"))
                source = (plugin_dir / "com.xsec.desktop" / "frontend" / "index.js").read_text(encoding="utf-8")
                validate_market.validate_official_settings_contract(manifest, plugin_id)
                self.assertIn("host.context?.kind", source)
                self.assertIn("settings-page", source)
                self.assertIn(
                    f"onSettingsPage:{contract['page']}",
                    manifest["extensions"]["com.xsec.desktop"]["activationEvents"],
                )
                for method, (capability, binding) in contract["methods"].items():
                    self.assertIn(method, source)
                    descriptor = manifest["extensions"]["com.xsec.desktop"]["frontendApi"]["methods"][method]
                    self.assertEqual(descriptor, {"capability": capability, "binding": binding})

    def test_official_plugin_settings_rejects_session_bound_read(self) -> None:
        plugin_id = "com.xsec.system-terminal"
        manifest = json.loads((snapshot_dir(ROOT, plugin_id) / "plugin.json").read_text(encoding="utf-8"))
        manifest["extensions"]["com.xsec.desktop"]["frontendApi"]["methods"]["xsec.terminal.settings.get"]["binding"] = "session"
        with self.assertRaisesRegex(MarketplaceValidationError, "canonical plugin settings permission"):
            validate_market.validate_official_settings_contract(manifest, plugin_id)

    def test_official_plugin_settings_rejects_missing_settings_activation(self) -> None:
        plugin_id = "com.xsec.system-terminal"
        manifest = json.loads((snapshot_dir(ROOT, plugin_id) / "plugin.json").read_text(encoding="utf-8"))
        manifest["extensions"]["com.xsec.desktop"]["activationEvents"] = ["onWorkspaceTool:system-terminal"]
        with self.assertRaisesRegex(MarketplaceValidationError, "activate for its canonical plugin settings page"):
            validate_market.validate_official_settings_contract(manifest, plugin_id)

    def test_terminal_profile_controls_are_limited_to_the_settings_page_branch(self) -> None:
        source = (
            snapshot_dir(ROOT, "com.xsec.system-terminal") / "com.xsec.desktop" / "frontend" / "index.js"
        ).read_text(encoding="utf-8")
        settings_source, main_source = source.split("export function activate(host)", 1)

        # Profile selection is a persistent default, so it may only appear in
        # the isolated settings-page renderer. The terminal surface must never
        # reintroduce the old selector/restart/clear toolbar.
        self.assertIn("function terminalSettings(host)", settings_source)
        self.assertIn('profile=e("select")', settings_source)
        self.assertIn("xsec.terminal.settings.set", settings_source)
        self.assertIn('catch(error){status(`读取终端设置失败：${error instanceof Error?error.message:String(error)}`,true);throw error}', settings_source)
        self.assertIn('host.context?.kind==="settings-page"', main_source)
        self.assertIn('retry=e("button","settings-link","重试启动终端")', main_source)
        self.assertIn('retry.onclick=()=>void open()', main_source)
        for forbidden in (
            'e("select")',
            '"重新启动"',
            '"清屏"',
            "xsec.terminal.profiles",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, main_source)

    def test_settings_read_failures_do_not_discard_workspace_data_or_clear_the_notice(self) -> None:
        """Auxiliary plugin settings reads must not hide the useful failure state."""

        asset_source = (
            snapshot_dir(ROOT, "com.xsec.asset-discovery") / "com.xsec.desktop" / "frontend" / "index.js"
        ).read_text(encoding="utf-8")
        # Runs and assets are the main workspace data.  The settings read is
        # intentionally converted to a value-or-error result before the
        # Promise.all so a failed settings RPC cannot enter the branch that
        # clears those two rendered lists.
        self.assertRegex(
            asset_source,
            r'Promise\.resolve\(\)\.then\(\(?\(\)=>host\.request\("xsec\.asset-discovery\.settings\.get",\{\}\)',
        )
        self.assertRegex(asset_source, r'const\s*\[\s*runsData\s*,\s*assetsData\s*,\s*settings\s*\]\s*=\s*await\s+Promise\.all')
        self.assertRegex(asset_source, r'if\s*\(\s*"error"\s*in\s*settings\s*\)')
        self.assertRegex(
            asset_source,
            r'renderRuns\(runsData\);renderAssets\(assetsData\);if\s*\(\s*"error"\s*in\s*settings\s*\)',
        )
        # The recovery affordance must describe the credential required by the
        # selected default provider, rather than treating a different
        # provider's configured credential as sufficient.
        self.assertIn(
            'const provider=settings.value?.provider==="fofa"?"fofa":"hunter";const missing=provider==="fofa"?!settings.value?.fofaApiKeyConfigured:!settings.value?.hunterApiKeyConfigured;',
            asset_source,
        )
        # Credentials stay out of the generic plugin KV store. The settings
        # page offers only write/clear actions; its settings read still
        # receives the configured booleans rather than secret values.
        self.assertIn('xsec.asset-discovery.credentials.set', asset_source)
        self.assertIn('xsec.asset-discovery.credentials.clear', asset_source)
        self.assertIn('type="password"', asset_source)
        self.assertIn('async function load(preserveDraft=false)', asset_source)
        self.assertIn("await load(true);note(", asset_source)
        self.assertIn("controls.credentialActions.forEach", asset_source)
        self.assertIn("if(!settingsReady)return;const value=input.value.trim()", asset_source)
        self.assertIn("if(!settingsReady)return;if(!confirm", asset_source)
        self.assertIn("controls.credentialActions.forEach", asset_source)
        self.assertIn("if(!settingsReady)return;const value", asset_source)
        self.assertIn("if(!settingsReady)return;if(!confirm", asset_source)
        asset_manifest = json.loads(
            (snapshot_dir(ROOT, "com.xsec.asset-discovery") / "plugin.json").read_text(encoding="utf-8")
        )
        asset_methods = asset_manifest["extensions"]["com.xsec.desktop"]["frontendApi"]["methods"]
        self.assertEqual(asset_methods["xsec.asset-discovery.credentials.set"]["binding"], "plugin")
        self.assertEqual(asset_methods["xsec.asset-discovery.credentials.clear"]["binding"], "plugin")
        self.assertEqual(
            validate_market.OFFICIAL_PLUGIN_SETTINGS_CONTRACT["com.xsec.asset-discovery"]["methods"],
            {
                "xsec.asset-discovery.settings.get": ("pluginData.read", "plugin"),
                "xsec.asset-discovery.settings.set": ("pluginData.write", "plugin"),
                "xsec.asset-discovery.credentials.set": ("pluginData.write", "plugin"),
                "xsec.asset-discovery.credentials.clear": ("pluginData.write", "plugin"),
                "xsec.plugin.settings.open": ("pluginData.read", "plugin"),
            },
        )

        approval_source = (
            snapshot_dir(ROOT, "com.xsec.workspace.approvals") / "com.xsec.desktop" / "frontend" / "index.js"
        ).read_text(encoding="utf-8")
        self.assertIn("let settingsReady = false;", approval_source)
        self.assertIn("settingsReady = false;", approval_source)
        self.assertIn("if (!settingsReady)", approval_source)
        self.assertIn('saveButton.disabled = true;', approval_source)

        traffic_source = (
            snapshot_dir(ROOT, "com.xsec.workspace.traffic") / "com.xsec.desktop" / "frontend" / "index.js"
        ).read_text(encoding="utf-8")
        # The helpers deliberately propagate to load().  Its single outer
        # catch writes the error after the rejected Promise.all, so it cannot
        # be overwritten by the success-only note("") below it.
        self.assertIn(
            'async function loadRules(){renderRules(await host.request("xsec.traffic.passive-rules.list",{}))}',
            traffic_source,
        )
        self.assertIn(
            'async function loadCa(){const view=await host.request("xsec.traffic.ca.status",{});',
            traffic_source,
        )
        self.assertIn('settingsReady=true;controls.save.disabled=false;await Promise.all', traffic_source)
        self.assertIn('await Promise.all([loadCa(),loadRules()]);note("")}catch(error){note(`', traffic_source)
        self.assertIn('enabled.onchange=()=>void toggle(rule.rule_id,enabled.checked,enabled);', traffic_source)
        self.assertIn('control.checked=!enabled;note(`更新被动规则失败：', traffic_source)
        self.assertIn('CA 已导入，但刷新 CA 状态失败', traffic_source)
        self.assertIn('规则已保存，但刷新规则列表失败', traffic_source)
        self.assertIn('规则已删除，但刷新规则列表失败', traffic_source)

        for plugin_id in validate_market.OFFICIAL_PLUGIN_SETTINGS_CONTRACT:
            frontend = snapshot_dir(ROOT, plugin_id) / "com.xsec.desktop" / "frontend" / "index.js"
            settings_source = frontend.read_text(encoding="utf-8")
            self.assertRegex(settings_source, r"settingsReady\s*=\s*false", plugin_id)
            self.assertRegex(settings_source, r"if\s*\(!settingsReady\)", plugin_id)
            self.assertRegex(settings_source, r"\bretry(?:Button)?\.onclick", plugin_id)
            self.assertRegex(settings_source, r"\.disabled\s*=\s*true", plugin_id)

    def test_v1_migration_initially_points_beta_and_stable_to_the_same_release(self) -> None:
        artifacts = [{"os": "any", "arch": "any", "url": "artifacts/test.xsec-plugin", "sha256": "a" * 64}]
        legacy = {
            "schemaVersion": 1,
            "pluginId": "com.example.test",
            "releases": [{"version": "1.0.0", "channel": "stable", "engines": {"xsec": ">=1", "pluginApi": "^1"}, "artifacts": artifacts}],
        }

        migrated = build_market.migrate_v1_release_document(legacy, "com.example.test")

        self.assertEqual(migrated["schemaVersion"], 2)
        self.assertEqual(migrated["channels"]["beta"], migrated["channels"]["stable"])
        self.assertEqual(migrated["channels"]["stable"]["releaseId"], migrated["releases"][0]["releaseId"])

    def test_release_id_canonicalization_is_cross_client_deterministic(self) -> None:
        artifacts = [
            {"os": "windows", "arch": "x86_64", "url": "windows.xsec-plugin", "sha256": "a" * 64},
            {"os": "linux", "arch": "aarch64", "url": "linux.xsec-plugin", "sha256": "b" * 64},
            {"os": "darwin", "arch": "x86_64", "url": "darwin.xsec-plugin", "sha256": "c" * 64},
        ]
        self.assertEqual(
            build_market.release_id("1.2.3", {"xsec": ">=0.1.0", "pluginApi": "^1.2.0"}, artifacts),
            "sha256-ec6330f7e2dd37747576d26c5597dcc25cd68797d19f113ff357805b2e1ceb54",
        )
        self.assertEqual(
            build_market.release_id("1.2.3", {"pluginApi": "^1.2.0", "xsec": ">=0.1.0"}, list(reversed(artifacts))),
            "sha256-ec6330f7e2dd37747576d26c5597dcc25cd68797d19f113ff357805b2e1ceb54",
        )

    def test_release_engine_and_beta_only_pointer_contract_is_strict(self) -> None:
        with self.assertRaisesRegex(ValueError, "only xsec and pluginApi"):
            build_market.require_release_engines(
                {"xsec": ">=0.1.0", "pluginApi": "^1.2.0", "feature": "preview"},
                "test release",
            )
        with tempfile.TemporaryDirectory(prefix="xsec-market-stable-pointer-") as directory:
            release_path = Path(directory) / "releases.json"
            release_path.write_text(
                json.dumps(
                    {
                        "schemaVersion": 2,
                        "pluginId": "com.example.test",
                        "releases": [],
                        "channels": {"beta": {"releaseId": None}, "stable": {"releaseId": None}},
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "use null"):
                build_market.load_release_document(release_path, "com.example.test")

    def test_beta_build_requires_a_version_bump_for_new_immutable_content(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-v2-build-") as directory:
            root = Path(directory)
            plugin_dir = root / "source"
            output_dir = root / "output"
            entrypoint = plugin_dir / "frontend" / "index.js"
            entrypoint.parent.mkdir(parents=True)
            manifest = {
                "name": "com.example.test",
                "version": "1.0.0",
                "extensions": {"com.xsec.desktop": {"engines": {"xsec": ">=1", "pluginApi": "^1"}, "entrypoints": {"frontend": "./frontend/index.js"}}},
            }
            (plugin_dir / "plugin.json").write_text(json.dumps(manifest), encoding="utf-8")
            entrypoint.write_text("export const value = 1;\n", encoding="utf-8")

            build_market.build_plugin(plugin_dir, output_dir)
            first = build_market.load_release_document(output_dir / ".xsec-market" / "releases.json", "com.example.test")
            first_id = first["channels"]["beta"]["releaseId"]
            self.assertIsNone(first["channels"]["stable"])
            validated_first, validated_records = validate_market.validate_release_index("com.example.test", output_dir)
            self.assertEqual(validated_first, first)
            self.assertIn(first_id, validated_records)

            # A cloud release must use a new SemVer. Desktop can hot-reload a
            # same-version local dev revision, but the installer and rollback
            # records use a version path and cannot safely represent two
            # Marketplace artifacts at one version.
            entrypoint.write_text("export const value = 2;\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "bump plugin.json"):
                build_market.build_plugin(plugin_dir, output_dir)
            manifest["version"] = "1.0.1"
            (plugin_dir / "plugin.json").write_text(json.dumps(manifest), encoding="utf-8")
            build_market.build_plugin(plugin_dir, output_dir)
            second = build_market.load_release_document(output_dir / ".xsec-market" / "releases.json", "com.example.test")
            second_id = second["channels"]["beta"]["releaseId"]
            self.assertNotEqual(first_id, second_id)
            self.assertIsNone(second["channels"]["stable"])
            self.assertEqual(len(second["releases"]), 2)
            artifacts = sorted((output_dir / ".xsec-market" / "artifacts").glob("*.xsec-plugin"))
            self.assertEqual(len(artifacts), 2)
            self.assertEqual(len({artifact.name for artifact in artifacts}), 2)

    def test_release_index_keeps_historical_archive_checks_without_requiring_the_current_frontend_contract(self) -> None:
        """A new frontend policy cannot invalidate an immutable rollback archive."""

        with tempfile.TemporaryDirectory(prefix="xsec-market-historical-archive-") as directory:
            plugin_id = "com.xsec.asset-discovery"
            plugin_dir = Path(directory) / plugin_id
            entrypoint = plugin_dir / "frontend" / "index.js"
            entrypoint.parent.mkdir(parents=True)
            manifest = {
                "name": plugin_id,
                "version": "1.0.0",
                "extensions": {
                    "com.xsec.desktop": {
                        "engines": {"xsec": ">=1", "pluginApi": "^1.0.0"},
                        "entrypoints": {"frontend": "./frontend/index.js"},
                    }
                },
            }
            (plugin_dir / "plugin.json").write_text(json.dumps(manifest), encoding="utf-8")
            entrypoint.write_text("export function activate(){ return {}; }\n", encoding="utf-8")
            build_market.build_plugin(plugin_dir, plugin_dir)
            release_path = plugin_dir / ".xsec-market" / "releases.json"
            release = build_market.load_release_document(release_path, plugin_id)
            beta_id = release["channels"]["beta"]["releaseId"]
            beta_release = next(item for item in release["releases"] if item["releaseId"] == beta_id)
            artifact = release_path.parent / beta_release["artifacts"][0]["url"]

            with self.assertRaisesRegex(MarketplaceValidationError, "plugin API 1.2"):
                validate_archive(artifact, plugin_id, manifest["version"])
            _, records = validate_market.validate_release_index(plugin_id, plugin_dir)
            self.assertIn(beta_id, records)

    def test_stable_promotion_reuses_an_existing_release_and_changes_no_artifact(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-stable-promotion-") as directory:
            root = Path(directory)
            plugin_dir = snapshot_dir(root, "com.example.test")
            entrypoint = plugin_dir / "frontend" / "index.js"
            entrypoint.parent.mkdir(parents=True)
            manifest = {
                "name": "com.example.test",
                "version": "1.0.0",
                "extensions": {"com.xsec.desktop": {"engines": {"xsec": ">=1", "pluginApi": "^1"}, "entrypoints": {"frontend": "./frontend/index.js"}}},
            }
            (plugin_dir / "plugin.json").write_text(json.dumps(manifest), encoding="utf-8")
            entrypoint.write_text("export const value = 1;\n", encoding="utf-8")
            build_market.build_plugin(plugin_dir, plugin_dir)
            entrypoint.write_text("export const value = 2;\n", encoding="utf-8")
            manifest["version"] = "1.0.1"
            (plugin_dir / "plugin.json").write_text(json.dumps(manifest), encoding="utf-8")
            build_market.build_plugin(plugin_dir, plugin_dir)
            release_path = plugin_dir / ".xsec-market" / "releases.json"
            before = build_market.load_release_document(release_path, "com.example.test")
            beta_id = before["channels"]["beta"]["releaseId"]
            stable_id = before["channels"]["stable"]
            artifact_bytes = {path.name: path.read_bytes() for path in (plugin_dir / ".xsec-market" / "artifacts").glob("*.xsec-plugin")}

            self.assertTrue(promote_release.promote_stable(root, "com.example.test", str(beta_id)))
            after = build_market.load_release_document(release_path, "com.example.test")
            self.assertEqual(after["channels"]["stable"]["releaseId"], beta_id)
            self.assertNotEqual(stable_id, beta_id)
            self.assertEqual(artifact_bytes, {path.name: path.read_bytes() for path in (plugin_dir / ".xsec-market" / "artifacts").glob("*.xsec-plugin")})
            self.assertFalse(promote_release.promote_stable(root, "com.example.test", str(beta_id)))

    def test_stable_promotion_workflow_detects_snapshot_metadata_changes(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "promote-stable.yml").read_text(encoding="utf-8")

        self.assertIn("git diff --quiet -- .xsec-factory/snapshots", workflow)

    def test_stable_promotion_rejects_an_unknown_release_id(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-stable-promotion-invalid-") as directory:
            root = Path(directory)
            plugin_dir = snapshot_dir(root, "com.example.test") / ".xsec-market"
            plugin_dir.mkdir(parents=True)
            release = {
                "schemaVersion": 2,
                "pluginId": "com.example.test",
                "releases": [],
                "channels": {"beta": {"releaseId": None}, "stable": None},
            }
            (plugin_dir / "releases.json").write_text(json.dumps(release), encoding="utf-8")
            with self.assertRaisesRegex(promote_release.PromotionError, "target is not an existing immutable release"):
                promote_release.promote_stable(root, "com.example.test", "sha256-" + "a" * 64)

    def test_source_gate_rejects_tampered_generated_artifact(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-tampered-artifact-") as directory:
            output = Path(directory) / "marketplace"
            self.build_marketplace(output)
            artifact = next(output.glob(".xsec-factory/snapshots/*/.xsec-market/artifacts/*.xsec-plugin"))
            with artifact.open("ab") as handle:
                handle.write(b"tampered")
            with self.assertRaisesRegex(MarketplaceValidationError, "SHA-256"):
                validate_source(ROOT, output)

    def test_approvals_frontend_v2_contract_survives_the_generated_archive(self) -> None:
        plugin_id = "com.xsec.workspace.approvals"
        plugin_dir = snapshot_dir(ROOT, plugin_id)
        manifest = validate_source_manifest(plugin_id, plugin_dir)
        desktop = manifest["extensions"]["com.xsec.desktop"]
        self.assertEqual(desktop["frontendApi"]["version"], 2)
        frontend = plugin_dir / "com.xsec.desktop" / "frontend" / "index.js"
        self.assertRegex(frontend.read_text(encoding="utf-8"), r"export\s+function\s+activate\s*\(\s*host\s*\)")

        with tempfile.TemporaryDirectory(prefix="xsec-market-approvals-frontend-") as directory:
            output = Path(directory) / "marketplace"
            self.build_marketplace(output)
            release_path = snapshot_dir(output, plugin_id) / ".xsec-market" / "releases.json"
            release = build_market.load_release_document(release_path, plugin_id)
            beta_id = release["channels"]["beta"]["releaseId"]
            beta_release = next(item for item in release["releases"] if item["releaseId"] == beta_id)
            artifact = release_path.parent / beta_release["artifacts"][0]["url"]
            archived_manifest = validate_archive(artifact, plugin_id, manifest["version"])
            self.assertEqual(archived_manifest["extensions"]["com.xsec.desktop"]["frontendApi"]["version"], 2)

    def test_every_official_frontend_is_executable_and_placeholder_free(self) -> None:
        placeholder = "XSEC official plugin is active in Desktop."
        for plugin_dir in sorted((ROOT / build_market.SNAPSHOT_ROOT_RELATIVE_PATH).iterdir()):
            if not plugin_dir.is_dir():
                continue
            plugin_id = plugin_dir.name
            manifest = validate_source_manifest(plugin_id, plugin_dir)
            desktop = manifest["extensions"]["com.xsec.desktop"]
            methods = desktop["frontendApi"]["methods"]
            expected_plugin_api = (
                "^1.4.0"
                if set(methods) & validate_market.WORKSPACE_COMPOSER_METHODS
                else "^1.3.0"
                if "xsec.workspace.tool.open" in methods
                else "^1.2.0"
            )
            self.assertEqual(desktop["engines"]["pluginApi"], expected_plugin_api, plugin_id)
            self.assertEqual(desktop["frontendApi"]["version"], 2, plugin_id)
            self.assertTrue(desktop["frontendApi"]["methods"], plugin_id)
            source = (plugin_dir / "com.xsec.desktop" / "frontend" / "index.js").read_text(encoding="utf-8")
            self.assertNotIn(placeholder, source, plugin_id)
            self.assertIn("export function activate(host)", source, plugin_id)

    def test_generic_official_frontend_gate_rejects_success_screen_stub(self) -> None:
        plugin_id = "com.xsec.workspace.files"
        plugin_dir = snapshot_dir(ROOT, plugin_id)
        manifest = json.loads((plugin_dir / "plugin.json").read_text(encoding="utf-8"))
        stub = "export function activate(host){document.body.textContent='XSEC official plugin is active in Desktop.';return{mount(){},update(){},dispose(){}}}"
        with self.assertRaisesRegex(MarketplaceValidationError, "placeholder/fallback marker"):
            validate_market.validate_official_frontend(manifest, stub, "files stub")

    def test_approvals_frontend_rejects_any_noncanonical_reviewed_structure(self) -> None:
        plugin_id = "com.xsec.workspace.approvals"
        plugin_dir = snapshot_dir(ROOT, plugin_id)
        manifest = json.loads((plugin_dir / "plugin.json").read_text(encoding="utf-8"))
        entrypoint = "com.xsec.desktop/frontend/index.js"
        source = (plugin_dir / entrypoint).read_text(encoding="utf-8")

        with tempfile.TemporaryDirectory(prefix="xsec-market-approvals-structure-") as directory:
            artifact = Path(directory) / "noncanonical.xsec-plugin"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("plugin.json", json.dumps(manifest))
                archive.writestr(entrypoint, source + "\n")
            with self.assertRaisesRegex(MarketplaceValidationError, "approved official approvals frontend structure"):
                validate_archive(artifact, plugin_id, manifest["version"])

    def test_approvals_frontend_contract_rejects_placeholder_archive(self) -> None:
        plugin_id = "com.xsec.workspace.approvals"
        plugin_dir = snapshot_dir(ROOT, plugin_id)
        manifest = json.loads((plugin_dir / "plugin.json").read_text(encoding="utf-8"))
        entrypoint = "com.xsec.desktop/frontend/index.js"
        source = (plugin_dir / entrypoint).read_text(encoding="utf-8")

        for label, change_manifest, archive_source, message in (
            (
                "old-api",
                lambda value: value["extensions"]["com.xsec.desktop"]["frontendApi"].update({"version": 1}),
                source,
                "frontend API v2",
            ),
            (
                "missing-session-read-permission",
                lambda value: value["extensions"]["com.xsec.desktop"]["permissions"].pop("workspace.session.read"),
                source,
                "session read permission",
            ),
            (
                "unsupported-plugin-api-engine",
                lambda value: value["extensions"]["com.xsec.desktop"]["engines"].update({"pluginApi": "^1.0.0"}),
                source,
                "plugin API 1.2",
            ),
            (
                "missing-approvals-workspace-tool",
                lambda value: value["extensions"]["com.xsec.desktop"]["contributes"]["workspaceTools"].pop("approvals"),
                source,
                "canonical approvals workspace-tool contribution",
            ),
            (
                "renamed-approvals-workspace-tool",
                lambda value: value["extensions"]["com.xsec.desktop"]["contributes"]["workspaceTools"].update({"approval-log": value["extensions"]["com.xsec.desktop"]["contributes"]["workspaceTools"].pop("approvals")}),
                source,
                "canonical approvals workspace-tool contribution",
            ),
            (
                "missing-approvals-workspace-tool-activation",
                lambda value: value["extensions"]["com.xsec.desktop"].update({"activationEvents": []}),
                source,
                "workspace-tool activation event",
            ),
            (
                "renamed-approvals-workspace-tool-activation",
                lambda value: value["extensions"]["com.xsec.desktop"].update({"activationEvents": ["onWorkspaceTool:approval-log"]}),
                source,
                "workspace-tool activation event",
            ),
            (
                "placeholder-module",
                lambda value: None,
                "export function renderPlaceholder() {}\n",
                "export an executable activate",
            ),
            (
                "commented-out-contract",
                lambda value: None,
                """/*
export function activate(host) {
  return host.request(\"xsec.approvals.list\", {});
  return host.request(\"xsec.approvals.statistics\", {});
}
*/
export function renderPlaceholder() {}
""",
                "export an executable activate",
            ),
            (
                "regex-literal-contract",
                lambda value: None,
                "/export function activate(host) host.request(\"xsec.approvals.list\") host.request(\"xsec.approvals.statistics\")/;\n",
                "export an executable activate",
            ),
            (
                "conditional-regex-literal-contract",
                lambda value: None,
                "if (true) /export function activate(host) host.request(\"xsec.approvals.list\") host.request(\"xsec.approvals.statistics\")/;\n",
                "export an executable activate",
            ),
            (
                "quoted-export",
                lambda value: None,
                "\"export\"\nfunction activate(host) { host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); }\n",
                "export an executable activate",
            ),
            (
                "quoted-host-receiver",
                lambda value: None,
                "export function activate(host) { \"host\".request(\"xsec.approvals.list\", {}); \"host\".request(\"xsec.approvals.statistics\", {}); }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-outside-activate",
                lambda value: None,
                "export function activate(host) { return {}; }\nfunction unused() { host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-in-unreachable-activation-helper",
                lambda value: None,
                "export function activate(host) { function neverCalled() { host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); } return {}; }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-in-unreachable-arrow-helper",
                lambda value: None,
                "export function activate(host) { const neverCalled = () => { host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); }; return {}; }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-in-unreachable-expression-arrow-helper",
                lambda value: None,
                "export function activate(host) { const neverCalled = () => Promise.all([host.request(\"xsec.approvals.list\", {}), host.request(\"xsec.approvals.statistics\", {})]); return {}; }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-in-unreachable-anonymous-helper",
                lambda value: None,
                "export function activate(host) { const neverCalled = function () { host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); }; return {}; }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-in-helper-shadowed-by-member-call",
                lambda value: None,
                "export function activate(host) { function load() { host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); } const other = { load() {} }; other.load(); return {}; }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-in-unreachable-object-method",
                lambda value: None,
                "export function activate(host) { const neverCalled = { load() { host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); } }; return {}; }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-in-nested-returned-object-method",
                lambda value: None,
                "export function activate(host) { return { mount() {}, extra: { update() { host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); } } }; }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-in-arrow-closure-returning-lifecycle",
                lambda value: None,
                "export function activate(host) { const neverCalled = () => { return { mount() { host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); } }; }; return {}; }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-in-generator-closure-returning-lifecycle",
                lambda value: None,
                "export function activate(host) { const neverCalled = function* () { return { mount() { host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); } }; }; return {}; }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-in-lifecycle-with-shadowed-host-parameter",
                lambda value: None,
                "export function activate(host) { return { mount(host) { host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); } }; }\n",
                "host broker contract",
            ),
            (
                "rpc-after-activation-return",
                lambda value: None,
                "export function activate(host) { return {}; host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-after-asi-return-object",
                lambda value: None,
                "export function activate(host) { return {}\nhost.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-after-asi-bare-return",
                lambda value: None,
                "export function activate(host) { return\nhost.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-after-throw",
                lambda value: None,
                "export function activate(host) { throw new Error(\"stop\"); host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-in-helper-called-after-activation-return",
                lambda value: None,
                "export function activate(host) { function load() { host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); } return {}; load(); }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-after-lifecycle-return",
                lambda value: None,
                "export function activate(host) { return { mount() { return; host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); } }; }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-after-host-reassignment",
                lambda value: None,
                "export function activate(host) { host = { request() {} }; host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); return {}; }\n",
                "host broker contract",
            ),
            (
                "rpc-in-helper-after-activation-host-reassignment",
                lambda value: None,
                "export function activate(host) { function load() { host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); } host &&= { request() {} }; load(); return {}; }\n",
                "host broker contract",
            ),
            (
                "rpc-in-helper-after-lifecycle-host-update",
                lambda value: None,
                "export function activate(host) { function load() { host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); } return { mount() { ++host; load(); } }; }\n",
                "host broker contract",
            ),
            (
                "rpc-in-lifecycle-after-activation-host-reassignment",
                lambda value: None,
                "export function activate(host) { host ??= { request() {} }; return { mount() { host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); } }; }\n",
                "host broker contract",
            ),
            (
                "rpc-in-helper-with-shadowed-host-parameter",
                lambda value: None,
                "export function activate(host) { function load(host) { host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); } load({ request() {} }); return {}; }\n",
                "host broker contract",
            ),
            (
                "rpc-in-activation-with-shadowed-host-local",
                lambda value: None,
                "export function activate(host) { var host = { request() {} }; host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); return {}; }\n",
                "host broker contract",
            ),
            (
                "rpc-after-destructuring-host-write",
                lambda value: None,
                "export function activate(host) { ({ host } = { host: { request() {} } }); host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); return {}; }\n",
                "host broker contract",
            ),
            (
                "rpc-after-template-host-write",
                lambda value: None,
                "export function activate(host) { `${host = { request() {} }}`; host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); return {}; }\n",
                "unsupported executable template interpolation",
            ),
            (
                "rpc-after-escaped-host-write",
                lambda value: None,
                "export function activate(host) { h\\u006fst = { request() {} }; host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); return {}; }\n",
                "must not contain Unicode escape sequences",
            ),
            (
                "rpc-after-hoisted-helper-host-write",
                lambda value: None,
                "export function activate(host) { poison(); host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); function poison() { host = { request() {} }; } return {}; }\n",
                "host broker contract",
            ),
            (
                "rpc-in-statically-false-branch",
                lambda value: None,
                "export function activate(host) { if (false) Promise.all([host.request(\"xsec.approvals.list\", {}), host.request(\"xsec.approvals.statistics\", {})]); return {}; }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-in-newline-statically-false-branch",
                lambda value: None,
                "export function activate(host) { if (false)\n host.request(\"xsec.approvals.list\", {}); if (true)\n undefined;\n else\n host.request(\"xsec.approvals.statistics\", {}); return {}; }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-in-newline-continued-statically-false-branch",
                lambda value: None,
                "export function activate(host) { if (false) void\n host.request(\"xsec.approvals.list\", {}); if (false) void\n host.request(\"xsec.approvals.statistics\", {}); return {}; }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-in-statically-true-else-branch",
                lambda value: None,
                "export function activate(host) { if (true) {} else { host.request(\"xsec.approvals.list\", {}); } if (true) undefined; else host.request(\"xsec.approvals.statistics\", {}); return {}; }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-in-statically-false-loop",
                lambda value: None,
                "export function activate(host) { while (false)\n host.request(\"xsec.approvals.list\", {}); for (; false;) { host.request(\"xsec.approvals.statistics\", {}); } return {}; }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-in-statically-false-for-update",
                lambda value: None,
                "export function activate(host) { for (; false; host.request(\"xsec.approvals.list\", {}), host.request(\"xsec.approvals.statistics\", {})) {} return {}; }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-after-false-short-circuit",
                lambda value: None,
                "export function activate(host) { false && host.request(\"xsec.approvals.list\", {}); false && host.request(\"xsec.approvals.statistics\", {}); return {}; }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-in-false-ternary-consequent",
                lambda value: None,
                "export function activate(host) { false ? host.request(\"xsec.approvals.list\", {}) : undefined; false ? host.request(\"xsec.approvals.statistics\", {}) : undefined; return {}; }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-after-true-short-circuit",
                lambda value: None,
                "export function activate(host) { true || host.request(\"xsec.approvals.list\", {}); true || host.request(\"xsec.approvals.statistics\", {}); return {}; }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-in-true-ternary-alternate",
                lambda value: None,
                "export function activate(host) { true ? undefined : host.request(\"xsec.approvals.list\", {}); true ? undefined : host.request(\"xsec.approvals.statistics\", {}); return {}; }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-after-direct-eval",
                lambda value: None,
                "export function activate(host) { eval(\"host = { request() {} }\"); host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); return {}; }\n",
                "host broker contract",
            ),
            (
                "rpc-after-function-constructor",
                lambda value: None,
                "export function activate(host) { Function(\"return undefined\")(); host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); return {}; }\n",
                "host broker contract",
            ),
            (
                "rpc-in-shadowed-duplicate-helper",
                lambda value: None,
                "export function activate(host) { function load() { host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); } function load() {} load(); return {}; }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-in-helper-shadowed-by-lexical-declaration",
                lambda value: None,
                "export function activate(host) { function list() { host.request(\"xsec.approvals.list\", {}); } function statistics() { host.request(\"xsec.approvals.statistics\", {}); } { const list = () => {}; list(); } { statistics(); let statistics = () => {}; } return {}; }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-in-helper-shadowed-by-var-declaration",
                lambda value: None,
                "export function activate(host) { function load() { host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); } var load = () => {}; load(); return {}; }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-in-uncalled-helper-default-parameters",
                lambda value: None,
                "export function activate(host) { function dead(value = Promise.all([host.request(\"xsec.approvals.list\", {}), host.request(\"xsec.approvals.statistics\", {})])) {} return {}; }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-in-uncalled-arrow-default-parameters",
                lambda value: None,
                "export function activate(host) { const dead = (value = Promise.all([host.request(\"xsec.approvals.list\", {}), host.request(\"xsec.approvals.statistics\", {})])) => {}; return {}; }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-in-uncalled-method-default-parameters",
                lambda value: None,
                "export function activate(host) { const dead = { load(value = Promise.all([host.request(\"xsec.approvals.list\", {}), host.request(\"xsec.approvals.statistics\", {})])) {} }; return {}; }\n",
                "declared approvals RPC requests",
            ),
            (
                "missing-function-body",
                lambda value: None,
                "export function activate(host)\nhost.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {});\n",
                "valid executable ESM syntax",
            ),
            (
                "wrong-method-capability",
                lambda value: value["extensions"]["com.xsec.desktop"]["frontendApi"]["methods"]["xsec.approvals.list"].update({"capability": "workspace.session.write"}),
                source,
                "session read capability",
            ),
            (
                "wrong-method-binding",
                lambda value: value["extensions"]["com.xsec.desktop"]["frontendApi"]["methods"]["xsec.approvals.statistics"].update({"binding": "workspace"}),
                source,
                "session read capability",
            ),
            (
                "unexpected-method",
                lambda value: value["extensions"]["com.xsec.desktop"]["frontendApi"]["methods"].update({"xsec.approvals.extra": {"capability": "workspace.session.read", "binding": "session"}}),
                source,
                "approvals read RPC methods",
            ),
        ):
            with self.subTest(label=label), tempfile.TemporaryDirectory(prefix=f"xsec-market-approvals-{label}-") as directory:
                candidate = json.loads(json.dumps(manifest))
                change_manifest(candidate)
                artifact = Path(directory) / f"{label}.xsec-plugin"
                with zipfile.ZipFile(artifact, "w") as archive:
                    archive.writestr("plugin.json", json.dumps(candidate))
                    archive.writestr(entrypoint, archive_source)
                with self.assertRaises(MarketplaceValidationError) as raised:
                    validate_archive(artifact, plugin_id, manifest["version"])
                self.assertTrue(
                    message in str(raised.exception)
                    or "approved official approvals frontend structure" in str(raised.exception),
                    str(raised.exception),
                )

    def test_unsafe_zip_member_is_rejected_before_manifest_read(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-zip-test-") as directory:
            artifact = Path(directory) / "unsafe.xsec-plugin"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("../plugin.json", '{"name":"com.xsec.test","version":"1.0.0"}')
            with self.assertRaisesRegex(MarketplaceValidationError, "unsafe entry path"):
                validate_archive(artifact, "com.xsec.test", "1.0.0")

    def test_case_insensitive_zip_member_collision_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-case-collision-") as directory:
            artifact = Path(directory) / "collision.xsec-plugin"
            manifest = '{"name":"com.xsec.test","version":"1.0.0"}'
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("plugin.json", manifest)
                archive.writestr("Plugin.json", manifest)
            with self.assertRaisesRegex(MarketplaceValidationError, "target-filesystem collision"):
                validate_archive(artifact, "com.xsec.test", "1.0.0")

    def test_windows_normalized_zip_member_collisions_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-windows-collision-") as directory:
            manifest = '{"name":"com.xsec.test","version":"1.0.0"}'
            for label, first, second in (
                ("trailing-dot", "frontend/foo./bar.js", "frontend/foo/bar.js"),
                ("unicode", "frontend/café.js", "frontend/cafe\u0301.js"),
            ):
                with self.subTest(label=label):
                    artifact = Path(directory) / f"{label}.xsec-plugin"
                    with zipfile.ZipFile(artifact, "w") as archive:
                        archive.writestr("plugin.json", manifest)
                        archive.writestr(first, "first")
                        archive.writestr(second, "second")
                    with self.assertRaisesRegex(MarketplaceValidationError, "target-filesystem collision"):
                        validate_archive(artifact, "com.xsec.test", "1.0.0")

    def test_symbolic_link_zip_member_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-link-test-") as directory:
            artifact = Path(directory) / "link.xsec-plugin"
            link = zipfile.ZipInfo("plugin.json")
            link.external_attr = 0o120777 << 16
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr(link, "plugin.json")
            with self.assertRaisesRegex(MarketplaceValidationError, "symbolic link"):
                validate_archive(artifact, "com.xsec.test", "1.0.0")

    def test_windows_reserved_and_forbidden_zip_components_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-windows-components-") as directory:
            manifest = '{"name":"com.xsec.test","version":"1.0.0"}'
            for label, member, message in (
                ("reserved", "frontend/CON.js", "reserved device-name"),
                ("reserved-superscript-one", "frontend/COM¹.js", "reserved device-name"),
                ("reserved-superscript-two", "frontend/LPT².js", "reserved device-name"),
                ("reserved-superscript-three", "frontend/COM³.js", "reserved device-name"),
                ("forbidden", "frontend/foo?.js", "Windows-forbidden character"),
            ):
                with self.subTest(label=label):
                    artifact = Path(directory) / f"{label}.xsec-plugin"
                    with zipfile.ZipFile(artifact, "w") as archive:
                        archive.writestr("plugin.json", manifest)
                        archive.writestr(member, "entrypoint")
                    with self.assertRaisesRegex(MarketplaceValidationError, message):
                        validate_archive(artifact, "com.xsec.test", "1.0.0")

    def test_windows_normalized_file_directory_prefix_collisions_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-prefix-collision-") as directory:
            manifest = '{"name":"com.xsec.test","version":"1.0.0"}'
            for label, first, second in (
                ("file-then-descendant", "frontend/Foo", "frontend/foo/bar.js"),
                ("descendant-then-file", "frontend/foo/bar.js", "frontend/Foo"),
                ("explicit-directory-then-file", "frontend/Foo/", "frontend/foo"),
            ):
                with self.subTest(label=label):
                    artifact = Path(directory) / f"{label}.xsec-plugin"
                    with zipfile.ZipFile(artifact, "w") as archive:
                        archive.writestr("plugin.json", manifest)
                        archive.writestr(first, "first")
                        archive.writestr(second, "second")
                    with self.assertRaisesRegex(MarketplaceValidationError, "file/directory target-filesystem collision|target-filesystem collision"):
                        validate_archive(artifact, "com.xsec.test", "1.0.0")

    def test_source_entrypoints_must_be_regular_files_below_the_plugin_root(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-source-entrypoint-") as directory:
            plugin_dir = Path(directory) / "com.xsec.test"
            entrypoint = plugin_dir / "com.xsec.desktop" / "frontend" / "index.js"
            entrypoint.parent.mkdir(parents=True)
            manifest = {
                "name": "com.xsec.test",
                "version": "1.0.0",
                "extensions": {
                    "com.xsec.desktop": {
                        "engines": {"xsec": ">=1", "pluginApi": "^1"},
                        "entrypoints": {"frontend": "./com.xsec.desktop/frontend/index.js"},
                    },
                },
            }
            (plugin_dir / "plugin.json").write_text(json.dumps(manifest), encoding="utf-8")

            with self.subTest("missing"):
                with self.assertRaisesRegex(MarketplaceValidationError, "regular file"):
                    validate_source_manifest("com.xsec.test", plugin_dir)

            entrypoint.write_text("export {};\n", encoding="utf-8")
            validate_source_manifest("com.xsec.test", plugin_dir)

            with self.subTest("escape"):
                manifest["extensions"]["com.xsec.desktop"]["entrypoints"]["frontend"] = "../escape.js"
                (plugin_dir / "plugin.json").write_text(json.dumps(manifest), encoding="utf-8")
                with self.assertRaisesRegex(MarketplaceValidationError, "must not escape"):
                    validate_source_manifest("com.xsec.test", plugin_dir)

            with self.subTest("directory"):
                manifest["extensions"]["com.xsec.desktop"]["entrypoints"]["frontend"] = "./com.xsec.desktop/frontend"
                (plugin_dir / "plugin.json").write_text(json.dumps(manifest), encoding="utf-8")
                with self.assertRaisesRegex(MarketplaceValidationError, "regular file"):
                    validate_source_manifest("com.xsec.test", plugin_dir)

            with self.subTest("symbolic-link"):
                manifest["extensions"]["com.xsec.desktop"]["entrypoints"]["frontend"] = "./com.xsec.desktop/frontend/index.js"
                (plugin_dir / "plugin.json").write_text(json.dumps(manifest), encoding="utf-8")
                with patch.object(validate_market, "is_link", side_effect=lambda path: path == entrypoint):
                    with self.assertRaisesRegex(MarketplaceValidationError, "symbolic links"):
                        validate_source_manifest("com.xsec.test", plugin_dir)

    def test_archive_entrypoints_must_be_packed_regular_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-archive-entrypoint-") as directory:
            manifest = json.dumps({
                "name": "com.xsec.test",
                "version": "1.0.0",
                "extensions": {
                    "com.xsec.desktop": {
                        "entrypoints": {"frontend": "./com.xsec.desktop/frontend/index.js"},
                    },
                },
            })
            for label, build, message in (
                ("missing", lambda archive: None, "does not include XSEC Desktop entrypoint"),
                ("directory", lambda archive: archive.writestr("com.xsec.desktop/frontend/index.js/", ""), "must be a regular file"),
                ("symbolic-link", self.write_symbolic_link_entrypoint, "symbolic link"),
            ):
                with self.subTest(label=label):
                    artifact = Path(directory) / f"{label}.xsec-plugin"
                    with zipfile.ZipFile(artifact, "w") as archive:
                        archive.writestr("plugin.json", manifest)
                        build(archive)
                    with self.assertRaisesRegex(MarketplaceValidationError, message):
                        validate_archive(artifact, "com.xsec.test", "1.0.0")

    @staticmethod
    def write_symbolic_link_entrypoint(archive: zipfile.ZipFile) -> None:
        entrypoint = zipfile.ZipInfo("com.xsec.desktop/frontend/index.js")
        entrypoint.external_attr = 0o120777 << 16
        archive.writestr(entrypoint, "outside.js")

    def test_builder_marks_generated_entrypoints_as_regular_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-builder-entrypoint-") as directory:
            plugin_dir = Path(directory) / "com.xsec.test"
            entrypoint = plugin_dir / "com.xsec.desktop" / "frontend" / "index.js"
            entrypoint.parent.mkdir(parents=True)
            (plugin_dir / "plugin.json").write_text(json.dumps({
                "name": "com.xsec.test",
                "version": "1.0.0",
                "extensions": {
                    "com.xsec.desktop": {
                        "entrypoints": {"frontend": "./com.xsec.desktop/frontend/index.js"},
                    },
                },
            }), encoding="utf-8")
            entrypoint.write_text("export {};\n", encoding="utf-8")
            artifact = Path(directory) / "com.xsec.test.xsec-plugin"

            build_market.write_zip(plugin_dir, artifact)
            validate_archive(artifact, "com.xsec.test", "1.0.0")
            with zipfile.ZipFile(artifact) as archive:
                info = archive.getinfo("com.xsec.desktop/frontend/index.js")
            self.assertEqual(info.external_attr >> 16, 0o100644)

    def test_builder_normalizes_utf8_text_line_endings_without_changing_binary_members(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-line-endings-") as directory:
            root = Path(directory)
            windows_plugin = root / "windows" / "com.xsec.test"
            unix_plugin = root / "unix" / "com.xsec.test"
            for plugin_dir, line_ending in ((windows_plugin, "\r\n"), (unix_plugin, "\n")):
                entrypoint = plugin_dir / "com.xsec.desktop" / "frontend" / "index.js"
                entrypoint.parent.mkdir(parents=True)
                (plugin_dir / "plugin.json").write_bytes(
                    (json.dumps({"name": "com.xsec.test", "version": "1.0.0"}) + line_ending).encode("utf-8")
                )
                entrypoint.write_bytes(f"export const platform = 'test';{line_ending}".encode("utf-8"))
                (plugin_dir / "asset.pdf").write_bytes(b"%PDF-1.7\r\nstream\r\n%%EOF\r\n")

            windows_artifact = root / "windows.xsec-plugin"
            unix_artifact = root / "unix.xsec-plugin"
            build_market.write_zip(windows_plugin, windows_artifact)
            build_market.write_zip(unix_plugin, unix_artifact)

            self.assertEqual(windows_artifact.read_bytes(), unix_artifact.read_bytes())
            with zipfile.ZipFile(windows_artifact) as archive:
                self.assertEqual(archive.read("com.xsec.desktop/frontend/index.js"), b"export const platform = 'test';\n")
                self.assertEqual(archive.read("asset.pdf"), b"%PDF-1.7\r\nstream\r\n%%EOF\r\n")

    def test_manual_publish_is_rejected_outside_main_before_signing(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")
        self.assertIn("enforce-publish-ref:", workflow)
        self.assertIn('EVENT_NAME: ${{ github.event_name }}', workflow)
        self.assertIn('REF: ${{ github.ref }}', workflow)
        self.assertIn('REF_PROTECTED: ${{ github.ref_protected }}', workflow)
        self.assertIn('[ "$EVENT_NAME" = "workflow_dispatch" ] && [ "$REF" != "refs/heads/main" ]', workflow)
        self.assertIn('[ "$REF_PROTECTED" != "true" ]', workflow)
        classify_job = workflow.split("  classify-generated-main-change:\n", 1)[1].split("  sign-and-publish:\n", 1)[0]
        # GitHub skips a job whose dependency was skipped, regardless of the
        # downstream condition.  A protected-main manual dispatch must give
        # the classifier a successful, explicit non-generated result so the
        # external Beta/Stable request can reach the signing gate.  Pushes
        # remain the only event that classifies a main merge range.
        self.assertIn("github.event_name == 'workflow_dispatch'", classify_job)
        self.assertIn("if: ${{ github.event_name == 'push' }}", classify_job)
        self.assertIn('EVENT_NAME: ${{ github.event_name }}', classify_job)
        self.assertIn('[ "$EVENT_NAME" = "workflow_dispatch" ]', classify_job)
        self.assertIn('echo "generated=false" >> "$GITHUB_OUTPUT"', classify_job)
        self.assertLess(
            classify_job.index('[ "$EVENT_NAME" = "workflow_dispatch" ]'),
            classify_job.index('[[ "$BEFORE" =~ ^[a-f0-9]{40}$'),
        )
        signing_job = workflow.split("  sign-and-publish:\n", 1)[1].split("    runs-on:", 1)[0]
        self.assertIn("needs: [enforce-publish-ref, classify-generated-main-change]", signing_job)
        self.assertIn("needs.enforce-publish-ref.result == 'success'", signing_job)
        self.assertNotIn("needs.require_publish_token.result == 'success'", signing_job)
        self.assertIn("needs.classify-generated-main-change.outputs.generated != 'true'", signing_job)
        self.assertNotIn("github.event.head_commit.message", signing_job)
        steps = workflow.split("  sign-and-publish:\n", 1)[1].split("    steps:\n", 1)[1]
        self.assertLess(
            steps.index("Require the protected marketplace publication token before checkout or KMS"),
            steps.index("actions/checkout@v4"),
        )

    def test_disposable_build_rejects_nested_plugin_link_before_copytree(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-copy-link-") as directory:
            source_root = Path(directory) / "source"
            plugin_root = source_root / "plugins"
            plugin_dir = plugin_root / "com.xsec.test"
            nested_link = plugin_dir / "linked"
            outside = source_root / "outside"
            destination = Path(directory) / "destination"
            marketplace = source_root / ".agents" / "plugins" / "marketplace.json"
            plugin_dir.mkdir(parents=True)
            outside.mkdir()
            try:
                nested_link.symlink_to(outside, target_is_directory=True)
                link_check = nullcontext()
            except OSError:
                # Some Windows developer machines cannot create symlinks. The
                # CI test uses a real link; retain a local regression check of
                # the same detection branch when this capability is absent.
                nested_link.mkdir()
                link_check = patch.object(build_market, "is_link", side_effect=lambda path: path == nested_link)
            marketplace.parent.mkdir(parents=True)
            marketplace.write_text('{"plugins": []}\n', encoding="utf-8")

            with (
                patch.object(build_market, "PLUGIN_ROOT", plugin_root),
                patch.object(build_market, "MARKETPLACE", marketplace),
                patch.object(build_market.shutil, "copytree") as copytree,
                link_check,
            ):
                with self.assertRaisesRegex(ValueError, "plugin source tree must not contain symbolic links"):
                    build_market.copy_source_tree(destination)
                copytree.assert_not_called()

    def test_disposable_build_rejects_linked_plugin_root_before_traversal(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-root-link-") as directory:
            source_root = Path(directory) / "source"
            plugin_root = source_root / "plugins"
            destination = Path(directory) / "destination"
            plugin_root.mkdir(parents=True)

            with (
                patch.object(build_market, "PLUGIN_ROOT", plugin_root),
                patch.object(build_market, "is_link", side_effect=lambda path: path == plugin_root),
                patch.object(Path, "iterdir") as iterdir,
                patch.object(build_market.shutil, "copytree") as copytree,
            ):
                with self.assertRaisesRegex(ValueError, "plugin root must not be a symbolic link"):
                    build_market.copy_source_tree(destination)
                iterdir.assert_not_called()
                copytree.assert_not_called()

    def test_disposable_build_rejects_linked_marketplace_before_copy(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-index-link-") as directory:
            source_root = Path(directory) / "source"
            plugin_root = source_root / "plugins"
            marketplace = source_root / ".agents" / "plugins" / "marketplace.json"
            destination = Path(directory) / "destination"
            plugin_root.mkdir(parents=True)
            marketplace.parent.mkdir(parents=True)
            marketplace.write_text('{"plugins": []}\n', encoding="utf-8")

            for linked_path in (marketplace, marketplace.parent):
                with self.subTest(linked_path=linked_path):
                    with (
                        patch.object(build_market, "PLUGIN_ROOT", plugin_root),
                        patch.object(build_market, "MARKETPLACE", marketplace),
                        patch.object(build_market, "is_link", side_effect=lambda path: path == linked_path),
                        patch.object(build_market.shutil, "copyfile") as copyfile,
                    ):
                        with self.assertRaisesRegex(ValueError, "marketplace metadata path must not contain symbolic links"):
                            build_market.copy_source_tree(destination)
                        copyfile.assert_not_called()

    def test_build_rejects_manifest_path_components_before_writing_artifact(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-artifact-name-") as directory:
            root = Path(directory)
            source_plugin_dir = root / "source-plugin"
            source_plugin_dir.mkdir()
            output_plugin_dir = root / "output-plugin"
            base_manifest = {
                "name": "com.xsec.test",
                "version": "1.0.0",
                "extensions": {"com.xsec.desktop": {"engines": {"xsec": ">=1", "pluginApi": "^1"}}},
            }
            for field, invalid_value in (("name", "C:\\runner"), ("version", "../outside")):
                with self.subTest(field=field, invalid_value=invalid_value):
                    manifest = dict(base_manifest)
                    manifest[field] = invalid_value
                    (source_plugin_dir / "plugin.json").write_text(json.dumps(manifest), encoding="utf-8")
                    with patch.object(build_market, "write_zip") as write_zip:
                        with self.assertRaisesRegex(ValueError, "safe filename component"):
                            build_market.build_plugin(source_plugin_dir, output_plugin_dir)
                        write_zip.assert_not_called()

    def test_cleanup_rejects_linked_plugin_root_before_traversal(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-clean-link-") as directory:
            output_root = Path(directory) / "output"
            output_plugins = output_root / build_market.SNAPSHOT_ROOT_RELATIVE_PATH
            output_plugins.mkdir(parents=True)

            with (
                patch.object(build_market, "is_link", side_effect=lambda path: path == output_plugins),
                patch.object(Path, "exists") as exists,
                patch.object(Path, "iterdir") as iterdir,
            ):
                with self.assertRaisesRegex(ValueError, "generated plugin root must not be a symbolic link"):
                    build_market.clean_generated_output(output_root)
                exists.assert_not_called()
                iterdir.assert_not_called()

    def test_cleanup_rejects_linked_plugin_directory_before_cleanup(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-clean-child-link-") as directory:
            output_root = Path(directory) / "output"
            output_plugins = output_root / build_market.SNAPSHOT_ROOT_RELATIVE_PATH
            linked_plugin = output_plugins / "com.xsec.test"
            linked_plugin.mkdir(parents=True)

            with (
                patch.object(build_market, "is_link", side_effect=lambda path: path == linked_plugin),
            ):
                with self.assertRaisesRegex(ValueError, "generated plugin directory must not be a symbolic link"):
                    build_market.clean_generated_output(output_root)


if __name__ == "__main__":
    unittest.main()
