from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import build_market  # noqa: E402
import external_source_factory as factory  # noqa: E402
import promote_release  # noqa: E402


PLUGIN_ID = "com.example.external"
BETA_SHA = "a" * 40
STABLE_SHA = "b" * 40


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


class ExternalSourceFactoryTests(unittest.TestCase):
    maxDiff = None

    def registry_entry(self, *, status: str = "active", repository: str = "acme/external-plugin", path: str = "package") -> dict[str, object]:
        return {
            "pluginId": PLUGIN_ID,
            "source": {
                "repository": repository,
                "path": path,
                "refs": {"beta": "refs/heads/beta", "stable": "refs/heads/main"},
            },
            "policy": {"installation": "AVAILABLE", "authentication": "ON_INSTALL"},
            "category": "Security",
            "status": status,
        }

    def make_factory(self, root: Path, *entries: dict[str, object]) -> None:
        write_json(
            root / ".agents" / "plugins" / "marketplace.json",
            {"name": "xsec-official", "interface": {"displayName": "Test"}, "plugins": []},
        )
        write_json(root / ".xsec-factory" / "official-registry.json", {"schemaVersion": 1, "plugins": list(entries)})

    def make_source(self, root: Path, *, version: str = "1.0.0", source_path: str = "package") -> Path:
        plugin = root / source_path
        plugin.mkdir(parents=True)
        write_json(
            plugin / "plugin.json",
            {
                "name": PLUGIN_ID,
                "version": version,
                "extensions": {
                    "com.xsec.desktop": {
                        "engines": {"xsec": ">=1", "pluginApi": "^1"},
                        "entrypoints": {"frontend": "frontend.js"},
                    }
                },
            },
        )
        (plugin / "frontend.js").write_text("export function activate() {}\n", encoding="utf-8")
        return root

    def stage_and_record_beta(self, root: Path, source_root: Path, *, source_sha: str = BETA_SHA) -> str:
        factory.stage_beta(root, PLUGIN_ID, source_root)
        snapshot = root / "plugins" / PLUGIN_ID
        build_market.build_plugin(snapshot, snapshot)
        factory.record_beta(root, PLUGIN_ID, source_sha, "test-publisher")
        _, record = factory.current_beta_record(root, PLUGIN_ID)
        return str(record["releaseId"])

    def test_registry_rejects_unsafe_external_repository_and_path(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-external-registry-") as directory:
            root = Path(directory)
            invalid_cases = (
                self.registry_entry(repository="acme/../outside"),
                self.registry_entry(repository="acme/repo.git"),
                self.registry_entry(path="../package"),
                self.registry_entry(path="package\\windows"),
            )
            for entry in invalid_cases:
                with self.subTest(entry=entry):
                    self.make_factory(root, entry)
                    with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "GitHub slug|below the checked-out|forward-slash"):
                        factory.load_registry(root)

    def test_registry_rejects_the_desktop_owned_plugin_namespace(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-external-reserved-plugin-") as directory:
            root = Path(directory)
            for plugin_id in ("com.xsec.system-terminal", "com.xsec.external-example", "com.xsec"):
                with self.subTest(plugin_id=plugin_id):
                    entry = self.registry_entry()
                    entry["pluginId"] = plugin_id
                    self.make_factory(root, entry)
                    with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "reserved for the Desktop namespace"):
                        factory.load_registry(root)

    def test_registry_matches_the_desktop_plugin_id_grammar(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-external-id-grammar-") as directory:
            root = Path(directory)
            for plugin_id in (
                "Com.example.plugin",
                "com_example.plugin",
                "com..example",
                "com--example",
                "com.example-",
                "a" * 65,
            ):
                with self.subTest(plugin_id=plugin_id):
                    entry = self.registry_entry()
                    entry["pluginId"] = plugin_id
                    self.make_factory(root, entry)
                    with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "safe plugin identifier"):
                        factory.load_registry(root)

    def test_active_registration_may_exist_before_its_first_beta_snapshot(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-external-empty-") as directory:
            root = Path(directory)
            self.make_factory(root, self.registry_entry())
            factory.validate_registry_and_snapshots(root)

    def test_beta_snapshot_generates_discoverable_marketplace_entry_and_provenance(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-external-beta-") as directory:
            root = Path(directory)
            source = self.make_source(root / "source")
            self.make_factory(root, self.registry_entry())

            release_id = self.stage_and_record_beta(root, source)

            marketplace = json.loads((root / ".agents" / "plugins" / "marketplace.json").read_text(encoding="utf-8"))
            self.assertEqual(marketplace["plugins"], [factory.marketplace_entry(factory.registration_for(root, PLUGIN_ID))])
            evidence = json.loads(factory.publication_path(root, PLUGIN_ID).read_text(encoding="utf-8"))
            self.assertEqual(evidence["events"][0]["channel"], "beta")
            self.assertEqual(evidence["events"][0]["releaseId"], release_id)
            self.assertEqual(evidence["events"][0]["source"]["sha"], BETA_SHA)
            factory.validate_registry_and_snapshots(root)

    def test_registry_cannot_claim_a_preexisting_marketplace_entry_or_snapshot(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-external-ownership-") as directory:
            root = Path(directory)
            source = self.make_source(root / "source")
            self.make_factory(root, self.registry_entry())
            entry = factory.marketplace_entry(factory.registration_for(root, PLUGIN_ID))
            write_json(
                root / ".agents" / "plugins" / "marketplace.json",
                {"name": "xsec-official", "interface": {"displayName": "Test"}, "plugins": [entry]},
            )
            (root / "plugins" / PLUGIN_ID).mkdir(parents=True)

            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "cannot claim existing plugin"):
                factory.stage_beta(root, PLUGIN_ID, source)

    def test_snapshot_replacement_preserves_existing_immutable_release_history(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-external-history-") as directory:
            root = Path(directory)
            source = self.make_source(root / "source")
            self.make_factory(root, self.registry_entry())
            original_release_id = self.stage_and_record_beta(root, source)

            source_plugin = source / "package"
            (source_plugin / "frontend.js").write_text("export function activate() { return 'next'; }\n", encoding="utf-8")
            manifest = json.loads((source_plugin / "plugin.json").read_text(encoding="utf-8"))
            manifest["version"] = "1.1.0"
            write_json(source_plugin / "plugin.json", manifest)
            factory.stage_beta(root, PLUGIN_ID, source)

            history = json.loads(factory.release_path(root, PLUGIN_ID).read_text(encoding="utf-8"))
            self.assertEqual(history["releases"][0]["releaseId"], original_release_id)
            build_market.build_plugin(root / "plugins" / PLUGIN_ID, root / "plugins" / PLUGIN_ID)
            self.assertEqual(len(json.loads(factory.release_path(root, PLUGIN_ID).read_text(encoding="utf-8"))["releases"]), 2)

    def test_changed_bytes_with_the_same_semver_are_rejected_by_existing_market_builder(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-external-version-") as directory:
            root = Path(directory)
            source = self.make_source(root / "source")
            self.make_factory(root, self.registry_entry())
            self.stage_and_record_beta(root, source)

            (source / "package" / "frontend.js").write_text("export function activate() { return 'changed'; }\n", encoding="utf-8")
            factory.stage_beta(root, PLUGIN_ID, source)
            with self.assertRaisesRegex(ValueError, "already contains immutable content for version 1.0.0"):
                build_market.build_plugin(root / "plugins" / PLUGIN_ID, root / "plugins" / PLUGIN_ID)

    def test_stable_requires_exactly_the_selected_beta_content_and_records_main_evidence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-external-stable-") as directory:
            root = Path(directory)
            source = self.make_source(root / "source")
            self.make_factory(root, self.registry_entry())
            release_id = self.stage_and_record_beta(root, source)

            verified = factory.verify_stable(root, PLUGIN_ID, source, release_id)
            self.assertEqual(verified["release_id"], release_id)
            self.assertTrue(promote_release.promote_stable(root, PLUGIN_ID, release_id))
            factory.record_stable(root, PLUGIN_ID, STABLE_SHA, release_id, "test-publisher")
            factory.validate_registry_and_snapshots(root)

            events = json.loads(factory.publication_path(root, PLUGIN_ID).read_text(encoding="utf-8"))["events"]
            self.assertEqual(events[-1]["channel"], "stable")
            self.assertEqual(events[-1]["source"]["sha"], STABLE_SHA)

    def test_committed_node_modules_do_not_break_beta_to_stable_content_identity(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-external-node-modules-") as directory:
            root = Path(directory)
            source = self.make_source(root / "source")
            dependency = source / "package" / "node_modules" / "fixture" / "index.js"
            dependency.parent.mkdir(parents=True)
            dependency.write_text("module.exports = 'not a package input';\n", encoding="utf-8")
            self.make_factory(root, self.registry_entry())
            release_id = self.stage_and_record_beta(root, source)

            self.assertFalse((root / "plugins" / PLUGIN_ID / "node_modules").exists())
            self.assertEqual(factory.verify_stable(root, PLUGIN_ID, source, release_id)["release_id"], release_id)

    def test_external_source_rejects_nonportable_desktop_package_paths(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-external-portable-paths-") as directory:
            root = Path(directory)
            source = self.make_source(root / "source")
            self.make_factory(root, self.registry_entry())
            (source / "package" / "café.js").write_text("export const label = 'café';\n", encoding="utf-8")

            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "portable ASCII"):
                factory.stage_beta(root, PLUGIN_ID, source)

            package = source / "package"
            # These paths need not coexist on a case-insensitive developer
            # filesystem for the preflight to prove its Desktop contract.
            with self.assertRaisesRegex(ValueError, "collide on case-insensitive"):
                build_market.require_portable_package_paths(
                    package,
                    [package / "frontend" / "Foo.js", package / "frontend" / "foo.js"],
                )
            with self.assertRaisesRegex(ValueError, "file/directory collision"):
                build_market.require_portable_package_paths(
                    package,
                    [package / "Foo", package / "foo" / "child.js"],
                )
            for relative, message in (
                ("trailing. ", "trailing-dot or trailing-space"),
                ("stream:ads.js", "NTFS stream"),
                ("bad?.js", "Windows-forbidden"),
                ("back\\slash.js", "Windows-forbidden"),
                ("CON.txt", "reserved device name"),
                ("COM\u00b2.txt", "portable ASCII"),
            ):
                with self.subTest(relative=relative):
                    with self.assertRaisesRegex(ValueError, message):
                        build_market.portable_target_filesystem_path(relative)

    def test_external_source_is_bounded_before_snapshot_or_packaging(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-external-bounded-source-") as directory:
            root = Path(directory)
            source = self.make_source(root / "source")
            self.make_factory(root, self.registry_entry())
            # Lower the shared preflight bound so this regression is fast and
            # demonstrates failure before copytree/ZIP work.
            with patch.object(build_market, "MAX_PACKAGE_FILE_BYTES", 1):
                with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "file is too large"):
                    factory.stage_beta(root, PLUGIN_ID, source)

    def test_stable_rejects_different_source_bytes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-external-stable-mismatch-") as directory:
            root = Path(directory)
            source = self.make_source(root / "source")
            self.make_factory(root, self.registry_entry())
            release_id = self.stage_and_record_beta(root, source)

            (source / "package" / "frontend.js").write_text("export function activate() { return 'not beta'; }\n", encoding="utf-8")
            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "does not deterministically rebuild"):
                factory.verify_stable(root, PLUGIN_ID, source, release_id)

    def test_external_source_rejects_desktop_reserved_workspace_and_mcp_contributions(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-external-reserved-contribution-") as directory:
            root = Path(directory)
            source = self.make_source(root / "source")
            self.make_factory(root, self.registry_entry())
            manifest_path = source / "package" / "plugin.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            desktop = manifest["extensions"]["com.xsec.desktop"]
            desktop["contributes"] = {
                "workspaceTools": {"system-terminal": {"title": "Imposter"}},
                "agentTools": {"xsec_browser_navigate": {"title": "Imposter"}},
            }
            desktop["activationEvents"] = ["onWorkspaceTool:system-terminal", "onAgentTool:xsec_browser_navigate"]
            write_json(manifest_path, manifest)

            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "reserved official workspace contribution"):
                factory.stage_beta(root, PLUGIN_ID, source)

            desktop["contributes"] = {"agentTools": {"plugin.attack-path.tree_list": {"title": "Imposter"}}}
            desktop["activationEvents"] = ["onAgentTool:plugin.attack-path.tree_list"]
            write_json(manifest_path, manifest)
            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "reserved Desktop MCP tool"):
                factory.stage_beta(root, PLUGIN_ID, source)

    def test_external_source_rejects_every_desktop_owned_route_navigation_and_settings_surface(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-external-reserved-surfaces-") as directory:
            root = Path(directory)
            source = self.make_source(root / "source")
            self.make_factory(root, self.registry_entry())
            manifest_path = source / "package" / "plugin.json"
            base = json.loads(manifest_path.read_text(encoding="utf-8"))
            cases = (
                (
                    {"navigation": {"items": {"asset-discovery": {"route": "external"}}}},
                    [],
                ),
                (
                    {"navigation": {"items": {"external-navigation": {"route": "asset-discovery"}}}},
                    [],
                ),
                (
                    {"navigation": {"items": {"external-navigation": {"route": "new-session"}}}},
                    [],
                ),
                (
                    {"navigation": {"items": {"external-navigation": {"route": "external", "parent": "project.assets"}}}},
                    [],
                ),
                (
                    {"routes": {"external-route": {"path": "/asset-discovery", "page": "external"}}},
                    [],
                ),
                (
                    {"routes": {"external-route": {"path": "external", "page": "project-overview"}}},
                    [],
                ),
                (
                    {"settingsPages": {"asset-discovery": {"page": "external"}}},
                    [],
                ),
                (
                    {"settingsPages": {"external-settings": {"page": "settings-system"}}},
                    [],
                ),
                ({}, ["onRoute:asset-discovery"]),
                ({}, ["onSettingsPage:settings-system"]),
            )
            for contributes, activation_events in cases:
                with self.subTest(contributes=contributes, activation_events=activation_events):
                    manifest = json.loads(json.dumps(base))
                    desktop = manifest["extensions"]["com.xsec.desktop"]
                    desktop["contributes"] = contributes
                    desktop["activationEvents"] = activation_events
                    write_json(manifest_path, manifest)
                    with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "reserved official Desktop surface"):
                        factory.stage_beta(root, PLUGIN_ID, source)

    def test_external_source_cannot_turn_official_marketplace_trust_into_high_privileges(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-external-capability-") as directory:
            root = Path(directory)
            source = self.make_source(root / "source")
            self.make_factory(root, self.registry_entry())
            manifest_path = source / "package" / "plugin.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            desktop = manifest["extensions"]["com.xsec.desktop"]
            desktop["permissions"] = {"workspace.project.read": {}, "network.request": {}}
            write_json(manifest_path, manifest)
            factory.stage_beta(root, PLUGIN_ID, source)

            # Reset to a fresh Factory because the first successful stage owns
            # its snapshot and requires evidence before it may be replaced.
            root = Path(directory) / "forbidden"
            source = self.make_source(root / "source")
            self.make_factory(root, self.registry_entry())
            manifest_path = source / "package" / "plugin.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["extensions"]["com.xsec.desktop"]["permissions"] = {"process.spawn": {}}
            write_json(manifest_path, manifest)
            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "not permitted for an automatic official Factory grant"):
                factory.stage_beta(root, PLUGIN_ID, source)

    def test_disabled_registry_entry_cannot_be_prepared_or_staged(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-external-disabled-") as directory:
            root = Path(directory)
            source = self.make_source(root / "source")
            self.make_factory(root, self.registry_entry(status="disabled"))
            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "is disabled"):
                factory.prepare(root, PLUGIN_ID, "beta", BETA_SHA)
            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "is disabled"):
                factory.stage_beta(root, PLUGIN_ID, source)

    def test_published_external_plugin_cannot_be_deregistered_into_an_ordinary_official_package(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-external-deregister-") as directory:
            root = Path(directory)
            source = self.make_source(root / "source")
            self.make_factory(root, self.registry_entry())
            self.stage_and_record_beta(root, source)

            # Removing the allowlist and evidence must not make a previously
            # external marketplace entry eligible for the generic signed path.
            # The operator must keep a disabled registration for a withdrawn
            # external package instead.
            write_json(root / ".xsec-factory" / "official-registry.json", {"schemaVersion": 1, "plugins": []})
            factory.publication_path(root, PLUGIN_ID).unlink()
            manifest_path = root / "plugins" / PLUGIN_ID / "plugin.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["extensions"]["com.xsec.desktop"]["permissions"] = {"process.spawn": {}}
            write_json(manifest_path, manifest)

            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "neither Desktop-owned nor registered"):
                factory.validate_registry_and_snapshots(root)

            # The same ownership rule also rejects an orphaned snapshot if a
            # deregistration PR removes its marketplace entry at the same time.
            write_json(root / ".agents" / "plugins" / "marketplace.json", {"name": "xsec-official", "interface": {"displayName": "Test"}, "plugins": []})
            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "neither Desktop-owned nor registered"):
                factory.validate_registry_and_snapshots(root)

    def test_snapshot_root_rejects_symlink_entries_before_ownership_checks(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-external-snapshot-link-") as directory:
            root = Path(directory)
            self.make_factory(root)
            snapshot = root / "plugins" / "com.xsec.asset-discovery"
            snapshot.mkdir(parents=True)

            # Keep the regression deterministic on Windows machines where
            # creating a real symlink requires Developer Mode or elevation.
            with patch.object(factory, "is_link", side_effect=lambda path: Path(path) == snapshot):
                with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "must not contain symbolic links"):
                    factory.validate_registry_and_snapshots(root)

    def test_legacy_stable_workflow_guard_rejects_any_registered_external_plugin(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-external-legacy-stable-") as directory:
            root = Path(directory)
            self.make_factory(root, self.registry_entry())
            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "must use publish.yml"):
                factory.reject_legacy_stable_promotion(root, PLUGIN_ID)
            self.assertEqual(
                factory.reject_legacy_stable_promotion(root, "com.example.unregistered"),
                {"plugin_id": "com.example.unregistered", "legacy_stable_allowed": "true"},
            )

    def test_official_external_source_workflow_pins_git_transport_to_canonical_github_https(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")
        self.assertIn("github-server-url: https://github.com", workflow)
        self.assertIn("SOURCE_REPOSITORY: ${{ steps.external-request.outputs.source_repository }}", workflow)
        self.assertIn('source_git_url="https://github.com/${SOURCE_REPOSITORY}.git"', workflow)
        self.assertIn("remote.origin.url", workflow)
        self.assertIn("canonical GitHub HTTPS origin", workflow)
        self.assertIn("GIT_CONFIG_NOSYSTEM=1", workflow)
        self.assertIn("GIT_CONFIG_GLOBAL=/dev/null", workflow)
        self.assertIn("GIT_ALLOW_PROTOCOL=https", workflow)
        self.assertIn("GIT_TERMINAL_PROMPT=0", workflow)
        self.assertIn("http.sslVerify=true", workflow)
        self.assertIn("http.followRedirects=false", workflow)
        self.assertIn("credential.helper=", workflow)
        self.assertIn("protocol.allow=never", workflow)
        self.assertIn("protocol.https.allow=always", workflow)
        self.assertIn("refs/remotes/xsec-factory-source/verified", workflow)
        self.assertIn("--no-includes", workflow)
        self.assertIn("insteadof", workflow)
        self.assertIn("uploadpack|receivepack|vcs|proxy", workflow)
        self.assertIn("^http\\..*\\.extraheader$", workflow)
        self.assertNotIn("http://github.com", workflow)
        self.assertNotIn("fetch --no-tags origin", workflow)
        self.assertNotIn("ls-remote origin", workflow)
        self.assertLess(workflow.index("unset SOURCE_TOKEN"), workflow.index('fetch --no-tags "$source_git_url"'))

    def test_tampered_provenance_is_rejected_before_signing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-external-provenance-") as directory:
            root = Path(directory)
            source = self.make_source(root / "source")
            self.make_factory(root, self.registry_entry())
            self.stage_and_record_beta(root, source)

            evidence_path = factory.publication_path(root, PLUGIN_ID)
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            evidence["events"][0]["artifact"]["sha256"] = "0" * 64
            write_json(evidence_path, evidence)
            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "artifact does not match"):
                factory.validate_registry_and_snapshots(root)

    def test_snapshot_engine_drift_is_rejected_before_signing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-external-engine-drift-") as directory:
            root = Path(directory)
            source = self.make_source(root / "source")
            self.make_factory(root, self.registry_entry())
            self.stage_and_record_beta(root, source)

            manifest_path = root / "plugins" / PLUGIN_ID / "plugin.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["extensions"]["com.xsec.desktop"]["engines"] = {"xsec": ">=2", "pluginApi": "^2"}
            write_json(manifest_path, manifest)

            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "snapshot engines do not match"):
                factory.validate_registry_and_snapshots(root)

    def test_same_external_beta_retry_is_idempotent_across_publishers(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-external-retry-") as directory:
            root = Path(directory)
            source = self.make_source(root / "source")
            self.make_factory(root, self.registry_entry())
            self.stage_and_record_beta(root, source)

            factory.record_beta(root, PLUGIN_ID, BETA_SHA, "a-different-actor")

            events = json.loads(factory.publication_path(root, PLUGIN_ID).read_text(encoding="utf-8"))["events"]
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["publisher"], "test-publisher")
            factory.validate_registry_and_snapshots(root)

    def test_staging_is_static_and_never_executes_source_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-external-static-") as directory:
            root = Path(directory)
            source = self.make_source(root / "source")
            marker = root / "executed.txt"
            (source / "package" / "postinstall.py").write_text(
                f"from pathlib import Path\nPath({marker.as_posix()!r}).write_text('executed')\n",
                encoding="utf-8",
            )
            write_json(source / "package" / "package.json", {"scripts": {"postinstall": "python postinstall.py"}})
            self.make_factory(root, self.registry_entry())

            self.stage_and_record_beta(root, source)

            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
