from __future__ import annotations

import base64
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import build_market  # noqa: E402
import external_source_factory as factory  # noqa: E402
import kms_marketplace_publisher as publisher  # noqa: E402
import promote_release  # noqa: E402


PLUGIN_ID = "com.example.external"
BETA_SHA = "a" * 40
STABLE_SHA = "b" * 40
TEST_KMS_KID = "external-history-test-key"
TEST_KMS_PUBLIC_KEY_X = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
TEST_KMS_PRIVATE_KEY_D = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
TEST_KMS_JWKS = json.dumps(
    {
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": TEST_KMS_PUBLIC_KEY_X,
                "kid": TEST_KMS_KID,
                "alg": "EdDSA",
                "use": "sig",
            }
        ]
    },
    separators=(",", ":"),
).encode("utf-8")

NODE_ED25519_SIGN_PROGRAM = f"""
import {{ createPrivateKey, sign }} from "node:crypto";
import {{ readFileSync }} from "node:fs";

const key = createPrivateKey({{
  key: {{
    kty: "OKP",
    crv: "Ed25519",
    x: "{TEST_KMS_PUBLIC_KEY_X}",
    d: "{TEST_KMS_PRIVATE_KEY_D}",
  }},
  format: "jwk",
}});
const signingInput = Buffer.from(readFileSync(0, "utf8"), "base64");
process.stdout.write(sign(null, signingInput, key).toString("base64url"));
"""


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def sign_test_ed25519(signing_input: bytes) -> bytes:
    node = shutil.which("node")
    if node is None:
        raise AssertionError("Node.js is required by the KMS sidecar verifier tests")
    completed = subprocess.run(
        [node, "--input-type=module", "--eval", NODE_ED25519_SIGN_PROGRAM],
        input=base64.b64encode(signing_input),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    return base64.urlsafe_b64decode(completed.stdout + b"=" * (-len(completed.stdout) % 4))


def verify_test_historical_sidecar(
    sidecar_bytes: bytes,
    document: publisher.MarketplaceDocument,
) -> str:
    return publisher.verify_historical_sidecar_signature(
        sidecar_bytes,
        document,
        jwks_bytes=TEST_KMS_JWKS,
    )


def write_historical_release_sidecar(root: Path, plugin_id: str, *, source_revision: str = BETA_SHA) -> Path:
    """Write a real signed release sidecar without needing a test KMS broker."""

    release = factory.release_path(root, plugin_id)
    subject = f"plugins/{plugin_id}/.xsec-market/releases.json"
    envelope = {
        "schema_version": 1,
        "purpose": "xsec.plugin-marketplace.release",
        "subject": subject,
        "content_sha256": hashlib.sha256(release.read_bytes()).hexdigest(),
        "source_revision": source_revision,
        "issued_at": int(time.time()),
    }
    envelope_bytes = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
    protected = base64url(
        json.dumps(
            {"alg": "EdDSA", "kid": TEST_KMS_KID, "iss": publisher.OFFICIAL_MARKETPLACE_KMS_ISSUER_URL},
            separators=(",", ":"),
        ).encode("utf-8")
    )
    signature = sign_test_ed25519(protected.encode("ascii") + b"." + base64url(envelope_bytes).encode("ascii"))
    sidecar = {
        "schema_version": 1,
        "envelope_b64": base64url(envelope_bytes),
        "jws": {"protected": protected, "payload": base64url(envelope_bytes), "signature": base64url(signature)},
    }
    destination = release.with_name(release.name + ".sig.jws.json")
    destination.write_text(json.dumps(sidecar, separators=(",", ":")), encoding="utf-8")
    return destination


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

    def test_disabled_external_plugin_must_retain_its_immutable_publication_history(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-external-disabled-history-") as directory:
            root = Path(directory)
            source = self.make_source(root / "source")
            self.make_factory(root, self.registry_entry())
            self.stage_and_record_beta(root, source)

            # Retain more than the selected Beta release to prove withdrawal
            # checks every archived artifact, not just the current package.
            source_plugin = source / "package"
            manifest_path = source_plugin / "plugin.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["version"] = "1.1.0"
            write_json(manifest_path, manifest)
            (source_plugin / "frontend.js").write_text("export function activate() { return 'v2'; }\n", encoding="utf-8")
            self.stage_and_record_beta(root, source, source_sha="c" * 40)
            sidecar = write_historical_release_sidecar(root, PLUGIN_ID)
            historical_verifier = patch.object(
                factory,
                "verify_historical_sidecar_signature",
                verify_test_historical_sidecar,
            )
            historical_verifier.start()
            self.addCleanup(historical_verifier.stop)

            # Withdrawing an already published plugin removes only discovery;
            # the generated snapshot, releases.json, and provenance remain.
            self.make_factory(root, self.registry_entry(status="disabled"))
            write_json(
                root / ".agents" / "plugins" / "marketplace.json",
                {"name": "xsec-official", "interface": {"displayName": "Test"}, "plugins": []},
            )
            factory.validate_registry_and_snapshots(root)
            build_market.clean_generated_output(root)
            self.assertTrue(sidecar.is_file())
            factory.validate_registry_and_snapshots(root)

            snapshot = root / "plugins" / PLUGIN_ID
            artifacts = sorted((snapshot / ".xsec-market" / "artifacts").glob("*.xsec-plugin"))
            self.assertEqual(len(artifacts), 2)

            # A withdrawn package is no longer in marketplace.json, so the
            # external bridge itself must reject missing historical artifacts.
            historical = artifacts[0]
            historical_bytes = historical.read_bytes()
            historical.unlink()
            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "artifact 0 is unavailable"):
                factory.validate_registry_and_snapshots(root)
            historical.write_bytes(historical_bytes)

            current = artifacts[-1]
            current_bytes = current.read_bytes()
            current.write_bytes(current_bytes + b"tampered")
            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "SHA-256 does not match"):
                factory.validate_registry_and_snapshots(root)
            current.write_bytes(current_bytes)

            frontend = snapshot / "frontend.js"
            frontend_bytes = frontend.read_bytes()
            frontend.write_bytes(frontend_bytes + b"// retained snapshot drift\n")
            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "does not reproduce its immutable Beta artifact"):
                factory.validate_registry_and_snapshots(root)
            frontend.write_bytes(frontend_bytes)
            factory.validate_registry_and_snapshots(root)

            sidecar.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "KMS release sidecar is invalid"):
                factory.validate_registry_and_snapshots(root)
            sidecar = write_historical_release_sidecar(root, PLUGIN_ID)

            forged = json.loads(sidecar.read_text(encoding="utf-8"))
            forged["jws"]["signature"] = base64url(b"f" * 64)
            sidecar.write_text(json.dumps(forged, separators=(",", ":")), encoding="utf-8")
            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "KMS release sidecar is invalid"):
                factory.validate_registry_and_snapshots(root)
            sidecar = write_historical_release_sidecar(root, PLUGIN_ID)

            shutil.rmtree(root / "plugins" / PLUGIN_ID)
            factory.publication_path(root, PLUGIN_ID).unlink()
            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "must retain its immutable snapshot"):
                factory.validate_registry_and_snapshots(root)

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

    def test_trusted_baseline_rejects_complete_deletion_of_a_published_external_plugin(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-external-baseline-history-") as directory:
            workspace = Path(directory)
            root = workspace / "current"
            source = self.make_source(root / "source")
            self.make_factory(root, self.registry_entry())
            self.stage_and_record_beta(root, source)

            # The protected CI base has a complete immutable publication. A
            # PR can otherwise delete all four current-tree references and
            # make a later same-SemVer publication look brand new.
            baseline = workspace / "trusted-baseline"
            shutil.copytree(root, baseline)
            write_json(root / ".xsec-factory" / "official-registry.json", {"schemaVersion": 1, "plugins": []})
            write_json(
                root / ".agents" / "plugins" / "marketplace.json",
                {"name": "xsec-official", "interface": {"displayName": "Test"}, "plugins": []},
            )
            shutil.rmtree(root / "plugins" / PLUGIN_ID)
            factory.publication_path(root, PLUGIN_ID).unlink()

            with self.assertRaisesRegex(
                factory.ExternalSourceFactoryError,
                "cannot be removed from the registry",
            ):
                factory.validate_registry_and_snapshots(root, baseline_root=baseline)

    def test_trusted_baseline_rejects_source_identity_rewrite_for_published_external_plugin(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-external-baseline-source-identity-") as directory:
            workspace = Path(directory)
            root = workspace / "current"
            source = self.make_source(root / "source")
            self.make_factory(root, self.registry_entry())
            self.stage_and_record_beta(root, source)

            baseline = workspace / "trusted-baseline"
            shutil.copytree(root, baseline)
            rewritten = self.registry_entry(repository="acme/replacement-plugin", path="replacement")
            write_json(
                root / ".xsec-factory" / "official-registry.json",
                {"schemaVersion": 1, "plugins": [rewritten]},
            )

            with self.assertRaisesRegex(
                factory.ExternalSourceFactoryError,
                "cannot change its registered source identity",
            ):
                factory.validate_registry_and_snapshots(root, baseline_root=baseline)

    def test_trusted_baseline_requires_published_external_release_history_to_remain_in_order(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-external-baseline-release-order-") as directory:
            workspace = Path(directory)
            root = workspace / "current"
            source = self.make_source(root / "source")
            self.make_factory(root, self.registry_entry())
            self.stage_and_record_beta(root, source)

            source_plugin = source / "package"
            (source_plugin / "frontend.js").write_text("export function activate() { return 'next'; }\n", encoding="utf-8")
            manifest_path = source_plugin / "plugin.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["version"] = "1.1.0"
            write_json(manifest_path, manifest)
            self.stage_and_record_beta(root, source, source_sha=STABLE_SHA)
            factory.validate_registry_and_snapshots(root)

            baseline = workspace / "trusted-baseline"
            shutil.copytree(root, baseline)
            release_path = factory.release_path(root, PLUGIN_ID)
            release = json.loads(release_path.read_text(encoding="utf-8"))
            release["releases"].reverse()
            write_json(release_path, release)
            with self.assertRaisesRegex(
                factory.ExternalSourceFactoryError,
                "must retain every immutable release",
            ):
                factory.validate_registry_and_snapshots(root, baseline_root=baseline)

    def test_trusted_baseline_rejects_rewriting_published_external_evidence_events(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-external-baseline-evidence-") as directory:
            workspace = Path(directory)
            root = workspace / "current"
            source = self.make_source(root / "source")
            self.make_factory(root, self.registry_entry())
            self.stage_and_record_beta(root, source)

            baseline = workspace / "trusted-baseline"
            shutil.copytree(root, baseline)
            evidence_path = factory.publication_path(root, PLUGIN_ID)
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            evidence["events"][0]["source"]["sha"] = "c" * 40
            write_json(evidence_path, evidence)
            with self.assertRaisesRegex(
                factory.ExternalSourceFactoryError,
                "must retain every immutable publication evidence event",
            ):
                factory.validate_registry_and_snapshots(root, baseline_root=baseline)

            evidence["events"][0]["source"]["sha"] = BETA_SHA
            evidence["events"][0]["publisher"] = "rewritten-publisher"
            write_json(evidence_path, evidence)
            with self.assertRaisesRegex(
                factory.ExternalSourceFactoryError,
                "must retain every immutable publication evidence event",
            ):
                factory.validate_registry_and_snapshots(root, baseline_root=baseline)

    def test_trusted_baseline_requires_published_external_evidence_events_to_remain_in_order(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-external-baseline-evidence-order-") as directory:
            workspace = Path(directory)
            root = workspace / "current"
            source = self.make_source(root / "source")
            self.make_factory(root, self.registry_entry())
            release_id = self.stage_and_record_beta(root, source)

            baseline = workspace / "trusted-baseline"
            shutil.copytree(root, baseline)
            factory.verify_stable(root, PLUGIN_ID, source, release_id)
            self.assertTrue(promote_release.promote_stable(root, PLUGIN_ID, release_id))
            factory.record_stable(root, PLUGIN_ID, STABLE_SHA, release_id, "test-publisher")
            # Appending the Stable event is valid.
            factory.validate_registry_and_snapshots(root, baseline_root=baseline)

            evidence_path = factory.publication_path(root, PLUGIN_ID)
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            evidence["events"].reverse()
            write_json(evidence_path, evidence)
            with self.assertRaisesRegex(
                factory.ExternalSourceFactoryError,
                "must retain every immutable publication evidence event",
            ):
                factory.validate_registry_and_snapshots(root, baseline_root=baseline)

    def test_trusted_baseline_without_a_factory_allows_its_first_published_registration(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-external-first-factory-") as directory:
            workspace = Path(directory)
            root = workspace / "current"
            source = self.make_source(root / "source")
            self.make_factory(root, self.registry_entry())
            self.stage_and_record_beta(root, source)

            # The protected main revision can predate the Factory entirely.
            # It supplies no publication history, so first publication stays
            # valid while all later revisions use append-only continuity.
            baseline = workspace / "pre-factory-baseline"
            baseline.mkdir()
            factory.validate_registry_and_snapshots(root, baseline_root=baseline)

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
