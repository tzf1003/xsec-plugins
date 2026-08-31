from __future__ import annotations

import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch


TEMPLATE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TEMPLATE / "scripts"))

from factory_core import (  # noqa: E402
    FactoryError,
    load_release_document,
    load_registry,
    portable_target_filesystem_path,
    require_portable_package_paths,
    safe_plugin_id,
    safe_repository,
    SNAPSHOT_ROOT_RELATIVE_PATH,
    write_marketplace_index,
)
from factory_publish import beta_publish, registry_prepare, stable_promote  # noqa: E402
from factory_validate import validate_factory  # noqa: E402
import factory_attestation  # noqa: E402


def snapshot_dir(factory: Path) -> Path:
    return factory / SNAPSHOT_ROOT_RELATIVE_PATH / "com.example.sample"


class MarketplaceFactoryTests(unittest.TestCase):
    maxDiff = None

    def make_source(self, root: Path, value: str = "1") -> Path:
        plugin = root / "source-plugin"
        frontend = plugin / "frontend" / "index.js"
        frontend.parent.mkdir(parents=True)
        (plugin / "plugin.json").write_text(
            json.dumps(
                {
                    "name": "com.example.sample",
                    "version": "1.0.0",
                    "extensions": {
                        "com.xsec.desktop": {
                            "engines": {"xsec": ">=1.0.0", "pluginApi": "^1.0.0"},
                            "entrypoints": {"frontend": "./frontend/index.js"},
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        frontend.write_text(f"export const value = {value};\n", encoding="utf-8")
        return plugin

    def configure_registry(self, factory: Path, *, status: str = "active") -> None:
        registry = {
            "schemaVersion": 1,
            "marketplace": {"name": "sample-market", "displayName": "Sample Marketplace"},
            "plugins": [
                {
                    "pluginId": "com.example.sample",
                    "source": {
                        "repository": "example/source-plugin",
                        "path": ".",
                        "refs": {"beta": "refs/heads/beta", "stable": "refs/heads/main"},
                    },
                    "policy": {"installation": "AVAILABLE", "authentication": "ON_INSTALL"},
                    "category": "Development",
                    "status": status,
                }
            ],
        }
        (factory / ".xsec-factory" / "registry.json").write_text(json.dumps(registry), encoding="utf-8")
        (factory / ".agents" / "plugins" / "marketplace.json").write_text(
            json.dumps({"name": "sample-market", "interface": {"displayName": "Sample Marketplace"}, "plugins": []}),
            encoding="utf-8",
        )

    def test_beta_snapshot_is_desktop_compatible_and_stable_reuses_it(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-factory-test-") as directory:
            root = Path(directory)
            factory = root / "factory"
            shutil.copytree(TEMPLATE, factory)
            source = self.make_source(root)
            self.configure_registry(factory)

            prepared = registry_prepare(factory, "com.example.sample", "beta", "a" * 40)
            self.assertEqual(prepared["source_ref"], "refs/heads/beta")
            built = beta_publish(
                factory,
                "com.example.sample",
                source,
                "a" * 40,
                "example/factory",
                root / "artifacts",
            )
            snapshot = snapshot_dir(factory)
            self.assertTrue((snapshot / "plugin.json").is_file())
            self.assertTrue((snapshot / "frontend" / "index.js").is_file())
            self.assertTrue((snapshot / ".xsec-market" / "releases.json").is_file())
            index = json.loads((factory / ".agents" / "plugins" / "marketplace.json").read_text(encoding="utf-8"))
            self.assertEqual(index["plugins"][0]["source"], {"source": "local", "path": "./.xsec-factory/snapshots/com.example.sample"})
            release = load_release_document(snapshot / ".xsec-market" / "releases.json", "com.example.sample")
            self.assertEqual(release["channels"]["beta"]["releaseId"], built["release_id"])
            self.assertIsNone(release["channels"]["stable"])
            validate_factory(factory, "example/factory")

            evidence_path = factory / ".xsec-factory" / "publications" / "com.example.sample.json"
            before_beta_retry = evidence_path.read_bytes()
            beta_retry = beta_publish(
                factory,
                "com.example.sample",
                source,
                "a" * 40,
                "example/factory",
                root / "artifacts",
                publisher="another-authorized-releaser",
            )
            self.assertEqual(beta_retry["release_id"], built["release_id"])
            self.assertEqual(evidence_path.read_bytes(), before_beta_retry)
            validate_factory(factory, "example/factory")

            promoted = stable_promote(
                factory,
                "com.example.sample",
                source,
                "b" * 40,
                built["release_id"],
                "example/factory",
            )
            self.assertEqual(promoted["changed"], "true")
            self.assertEqual(promoted["release_tag"], built["release_tag"])
            self.assertEqual(promoted["artifact_name"], built["artifact_name"])
            self.assertEqual(promoted["artifact_sha256"], built["artifact_sha256"])
            release = load_release_document(snapshot / ".xsec-market" / "releases.json", "com.example.sample")
            self.assertEqual(release["channels"]["stable"], {"releaseId": built["release_id"]})
            validate_factory(factory, "example/factory")

            before_retry = evidence_path.read_bytes()
            retried = stable_promote(
                factory,
                "com.example.sample",
                source,
                "c" * 40,
                built["release_id"],
                "example/factory",
            )
            self.assertEqual(retried["changed"], "false")
            self.assertEqual(evidence_path.read_bytes(), before_retry)

    def test_strict_validation_allows_a_fresh_factory_without_a_proof_root(self) -> None:
        """A new Factory has no historical GitHub Release proof to download."""

        with tempfile.TemporaryDirectory(prefix="xsec-factory-fresh-strict-test-") as directory:
            root = Path(directory)
            factory = root / "factory"
            shutil.copytree(TEMPLATE, factory)
            self.configure_registry(factory)
            write_marketplace_index(factory, load_registry(factory))

            validate_factory(
                factory,
                "example/factory",
                require_publication_attestations=True,
            )

    def test_strict_validation_requires_a_proof_root_after_first_publication(self) -> None:
        """Historical evidence cannot be locally trusted without its Release asset."""

        with tempfile.TemporaryDirectory(prefix="xsec-factory-published-strict-test-") as directory:
            root = Path(directory)
            factory = root / "factory"
            shutil.copytree(TEMPLATE, factory)
            source = self.make_source(root)
            self.configure_registry(factory)
            beta_publish(factory, "com.example.sample", source, "a" * 40, "example/factory", root / "artifacts")

            with self.assertRaisesRegex(FactoryError, "publication attestation root is required"):
                validate_factory(
                    factory,
                    "example/factory",
                    require_publication_attestations=True,
                )

    def test_strict_provenance_download_covers_every_historical_event_including_disabled_plugins(self) -> None:
        """A source gate cannot accept only the newest event's Release asset."""

        with tempfile.TemporaryDirectory(prefix="xsec-factory-attestation-history-test-") as directory:
            root = Path(directory)
            factory = root / "factory"
            shutil.copytree(TEMPLATE, factory)
            source = self.make_source(root)
            self.configure_registry(factory)

            first_beta = beta_publish(factory, "com.example.sample", source, "a" * 40, "example/factory", root / "artifacts")
            stable_promote(
                factory,
                "com.example.sample",
                source,
                "b" * 40,
                first_beta["release_id"],
                "example/factory",
            )
            manifest_path = source / "plugin.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["version"] = "1.1.0"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            (source / "frontend" / "index.js").write_text("export const value = 2;\n", encoding="utf-8")
            beta_publish(factory, "com.example.sample", source, "c" * 40, "example/factory", root / "artifacts")

            # Disabled packages retain their immutable history and therefore
            # their proof requirements.  A source gate must not omit it.
            self.configure_registry(factory, status="disabled")
            write_marketplace_index(factory, load_registry(factory))
            events = factory_attestation.publication_events(factory)
            self.assertEqual(len(events), 3)
            self.assertTrue(all(registration.status == "disabled" for registration, *_ in events))

            evidence = json.loads(
                (factory / ".xsec-factory" / "publications" / "com.example.sample.json").read_text(encoding="utf-8")
            )
            first_event = evidence["events"][0]
            incomplete_root = root / "incomplete-proofs"
            factory_attestation.materialize(
                factory,
                "com.example.sample",
                str(first_event["channel"]),
                str(first_event["releaseId"]),
                str(first_event["source"]["sha"]),
                incomplete_root,
            )
            with self.assertRaisesRegex(FactoryError, "attestation.*unavailable"):
                validate_factory(
                    factory,
                    "example/factory",
                    publication_attestation_root=incomplete_root,
                    require_publication_attestations=True,
                )

            expected_assets: dict[str, tuple[str, bytes]] = {}
            for registration, event, _, _, _ in events:
                tag, filename, payload, _ = factory_attestation.attestation_spec(registration, event)
                expected_assets[filename] = (tag, payload)
            calls: list[tuple[str, str, str]] = []

            def download(repository: str, tag: str, filename: str, destination: Path) -> None:
                calls.append((repository, tag, filename))
                expected_tag, payload = expected_assets[filename]
                self.assertEqual(repository, "example/factory")
                self.assertEqual(tag, expected_tag)
                (destination / filename).write_bytes(payload)

            complete_root = root / "complete-proofs"
            with patch.object(factory_attestation, "gh_download", side_effect=download):
                result = factory_attestation.download_all(factory, "example/factory", complete_root)
            self.assertEqual(result["attestation_count"], "3")
            self.assertEqual({filename for _, _, filename in calls}, set(expected_assets))
            self.assertEqual({path.name for path in complete_root.iterdir()}, set(expected_assets))
            validate_factory(
                factory,
                "example/factory",
                publication_attestation_root=complete_root,
                require_publication_attestations=True,
            )

    def test_factory_validation_rejects_snapshot_engine_drift(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-factory-engine-drift-test-") as directory:
            root = Path(directory)
            factory = root / "factory"
            shutil.copytree(TEMPLATE, factory)
            source = self.make_source(root)
            self.configure_registry(factory)
            beta_publish(factory, "com.example.sample", source, "a" * 40, "example/factory", root / "artifacts")

            manifest_path = snapshot_dir(factory) / "plugin.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["extensions"]["com.xsec.desktop"]["engines"]["xsec"] = ">=999.0.0"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            with self.assertRaisesRegex(FactoryError, "does not describe its beta release engines"):
                validate_factory(factory, "example/factory")

    def test_factory_validation_rejects_full_snapshot_manifest_drift(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-factory-manifest-drift-test-") as directory:
            root = Path(directory)
            factory = root / "factory"
            shutil.copytree(TEMPLATE, factory)
            source = self.make_source(root)
            self.configure_registry(factory)
            beta_publish(factory, "com.example.sample", source, "a" * 40, "example/factory", root / "artifacts")

            manifest_path = snapshot_dir(factory) / "plugin.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            # This leaves the name, SemVer, and engines untouched, but changes
            # discovery/runtime metadata that is also inside the archive.
            manifest["extensions"]["com.xsec.desktop"]["permissions"] = {"network.request": {}}
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            with self.assertRaisesRegex(FactoryError, "does not reproduce its immutable beta release artifact"):
                validate_factory(factory, "example/factory")

    def test_factory_rejects_entrypoints_excluded_from_the_published_archive(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-factory-excluded-entrypoint-test-") as directory:
            root = Path(directory)
            factory = root / "factory"
            shutil.copytree(TEMPLATE, factory)
            source = self.make_source(root)
            self.configure_registry(factory)
            manifest_path = source / "plugin.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            for excluded in ("node_modules", ".git", "__pycache__", ".xsec-market"):
                with self.subTest(excluded=excluded):
                    entrypoint = source / excluded / "entry.js"
                    entrypoint.parent.mkdir(parents=True, exist_ok=True)
                    entrypoint.write_text("export function activate() {}\n", encoding="utf-8")
                    manifest["extensions"]["com.xsec.desktop"]["entrypoints"] = {"frontend": f"{excluded}/entry.js"}
                    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                    with self.assertRaisesRegex(FactoryError, "cannot point into excluded package content"):
                        beta_publish(factory, "com.example.sample", source, "a" * 40, "example/factory", root / "artifacts")

    def test_new_content_at_a_published_version_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-factory-version-test-") as directory:
            root = Path(directory)
            factory = root / "factory"
            shutil.copytree(TEMPLATE, factory)
            source = self.make_source(root)
            self.configure_registry(factory)
            beta_publish(factory, "com.example.sample", source, "a" * 40, "example/factory", root / "artifacts")
            (source / "frontend" / "index.js").write_text("export const value = 2;\n", encoding="utf-8")
            with self.assertRaisesRegex(FactoryError, "bump plugin.json.version"):
                beta_publish(factory, "com.example.sample", source, "b" * 40, "example/factory", root / "artifacts")

    def test_stable_rejects_main_that_does_not_rebuild_the_selected_beta(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-factory-main-mismatch-test-") as directory:
            root = Path(directory)
            factory = root / "factory"
            shutil.copytree(TEMPLATE, factory)
            source = self.make_source(root)
            self.configure_registry(factory)
            beta = beta_publish(factory, "com.example.sample", source, "a" * 40, "example/factory", root / "artifacts")
            (source / "frontend" / "index.js").write_text("export const value = 2;\n", encoding="utf-8")
            with self.assertRaisesRegex(FactoryError, "does not rebuild"):
                stable_promote(
                    factory,
                    "com.example.sample",
                    source,
                    "b" * 40,
                    beta["release_id"],
                    "example/factory",
                )

    def test_registry_rejects_a_silent_default_install_policy(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-factory-policy-test-") as directory:
            root = Path(directory)
            factory = root / "factory"
            shutil.copytree(TEMPLATE, factory)
            self.configure_registry(factory)
            registry_path = factory / ".xsec-factory" / "registry.json"
            registry = json.loads(registry_path.read_text(encoding="utf-8"))
            registry["plugins"][0]["policy"]["installation"] = "INSTALLED_BY_DEFAULT"
            registry_path.write_text(json.dumps(registry), encoding="utf-8")
            with self.assertRaisesRegex(FactoryError, "AVAILABLE"):
                registry_prepare(factory, "com.example.sample", "beta", "a" * 40)

    def test_factory_rejects_a_non_semver_plugin_version_before_packaging(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-factory-semver-test-") as directory:
            root = Path(directory)
            factory = root / "factory"
            shutil.copytree(TEMPLATE, factory)
            source = self.make_source(root)
            self.configure_registry(factory)
            manifest_path = source / "plugin.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["version"] = "preview"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(FactoryError, "valid SemVer"):
                beta_publish(factory, "com.example.sample", source, "a" * 40, "example/factory", root / "artifacts")

    def test_factory_validation_binds_release_urls_to_the_canonical_release_asset(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-factory-url-test-") as directory:
            root = Path(directory)
            factory = root / "factory"
            shutil.copytree(TEMPLATE, factory)
            source = self.make_source(root)
            self.configure_registry(factory)
            beta_publish(factory, "com.example.sample", source, "a" * 40, "example/factory", root / "artifacts")
            release_path = snapshot_dir(factory) / ".xsec-market" / "releases.json"
            release = json.loads(release_path.read_text(encoding="utf-8"))
            release["releases"][0]["artifacts"][0]["url"] = "https://github.com/example/factory/releases/download/other/other.xsec-plugin"
            release_path.write_text(json.dumps(release), encoding="utf-8")
            with self.assertRaisesRegex(FactoryError, "points outside"):
                validate_factory(factory, "example/factory")

    def test_disabled_registration_cannot_publish(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-factory-disabled-test-") as directory:
            root = Path(directory)
            factory = root / "factory"
            shutil.copytree(TEMPLATE, factory)
            source = self.make_source(root)
            self.configure_registry(factory, status="disabled")
            with self.assertRaisesRegex(FactoryError, "disabled"):
                beta_publish(factory, "com.example.sample", source, "a" * 40, "example/factory", root / "artifacts")

    def test_disabled_published_plugin_must_retain_snapshot_history_and_evidence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-factory-disabled-history-test-") as directory:
            root = Path(directory)
            factory = root / "factory"
            shutil.copytree(TEMPLATE, factory)
            source = self.make_source(root)
            self.configure_registry(factory)
            beta_publish(factory, "com.example.sample", source, "a" * 40, "example/factory", root / "artifacts")

            # Withdrawal hides discovery only; generated package state and
            # provenance stay append-only so re-enable cannot reuse SemVer.
            self.configure_registry(factory, status="disabled")
            write_marketplace_index(factory, load_registry(factory))
            validate_factory(factory, "example/factory")

            shutil.rmtree(snapshot_dir(factory))
            (factory / ".xsec-factory" / "publications" / "com.example.sample.json").unlink()
            with self.assertRaisesRegex(FactoryError, "disabled plugin com.example.sample must retain"):
                validate_factory(factory, "example/factory")

    def test_trusted_baseline_rejects_complete_deletion_of_a_published_registration(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-factory-baseline-history-test-") as directory:
            root = Path(directory)
            factory = root / "current"
            shutil.copytree(TEMPLATE, factory)
            source = self.make_source(root)
            self.configure_registry(factory)
            beta_publish(factory, "com.example.sample", source, "a" * 40, "example/factory", root / "artifacts")

            # A protected CI baseline keeps the fact of publication even when
            # this PR tries to delete every current-tree reference to it.
            baseline = root / "trusted-baseline"
            shutil.copytree(factory, baseline)
            registry_path = factory / ".xsec-factory" / "registry.json"
            registry = json.loads(registry_path.read_text(encoding="utf-8"))
            registry["plugins"] = []
            registry_path.write_text(json.dumps(registry), encoding="utf-8")
            write_marketplace_index(factory, load_registry(factory))
            shutil.rmtree(snapshot_dir(factory))
            (factory / ".xsec-factory" / "publications" / "com.example.sample.json").unlink()

            with self.assertRaisesRegex(FactoryError, "cannot be removed from the registry"):
                validate_factory(factory, "example/factory", baseline_root=baseline)

    def test_trusted_baseline_rejects_source_identity_rewrite_for_published_registration(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-factory-baseline-source-identity-test-") as directory:
            root = Path(directory)
            factory = root / "current"
            shutil.copytree(TEMPLATE, factory)
            source = self.make_source(root)
            self.configure_registry(factory)
            beta_publish(factory, "com.example.sample", source, "a" * 40, "example/factory", root / "artifacts")

            baseline = root / "trusted-baseline"
            shutil.copytree(factory, baseline)
            registry_path = factory / ".xsec-factory" / "registry.json"
            registry = json.loads(registry_path.read_text(encoding="utf-8"))
            registry["plugins"][0]["source"]["repository"] = "example/replacement-plugin"
            registry_path.write_text(json.dumps(registry), encoding="utf-8")

            with self.assertRaisesRegex(FactoryError, "cannot change its registered source identity"):
                validate_factory(factory, "example/factory", baseline_root=baseline)

    def test_trusted_baseline_requires_published_release_history_to_remain_in_order(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-factory-baseline-release-order-test-") as directory:
            root = Path(directory)
            factory = root / "current"
            shutil.copytree(TEMPLATE, factory)
            source = self.make_source(root)
            self.configure_registry(factory)
            beta_publish(factory, "com.example.sample", source, "a" * 40, "example/factory", root / "artifacts")

            frontend = source / "frontend" / "index.js"
            frontend.write_text("export const value = 2;\n", encoding="utf-8")
            manifest_path = source / "plugin.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["version"] = "1.1.0"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            beta_publish(factory, "com.example.sample", source, "b" * 40, "example/factory", root / "artifacts")
            validate_factory(factory, "example/factory")

            baseline = root / "trusted-baseline"
            shutil.copytree(factory, baseline)
            release_path = snapshot_dir(factory) / ".xsec-market" / "releases.json"
            release = json.loads(release_path.read_text(encoding="utf-8"))
            release["releases"].reverse()
            release_path.write_text(json.dumps(release), encoding="utf-8")
            with self.assertRaisesRegex(FactoryError, "must retain every immutable release"):
                validate_factory(factory, "example/factory", baseline_root=baseline)

    def test_unpublished_registration_rejects_preseeded_or_unregistered_publication_evidence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-factory-unpublished-evidence-test-") as directory:
            root = Path(directory)
            factory = root / "factory"
            shutil.copytree(TEMPLATE, factory)
            self.configure_registry(factory)

            publication_root = factory / ".xsec-factory" / "publications"
            publication_root.mkdir(parents=True)
            unregistered = publication_root / "com.example.other.json"
            unregistered.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(FactoryError, "publication evidence directory has an unregistered entry"):
                validate_factory(factory, "example/factory")

            unregistered.unlink()
            preseeded = publication_root / "com.example.sample.json"
            preseeded.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "pluginId": "com.example.sample",
                        "events": [],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(FactoryError, "unpublished plugin com.example.sample must not have publication evidence"):
                validate_factory(factory, "example/factory")

    def test_trusted_baseline_rejects_rewriting_published_evidence_events(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-factory-baseline-evidence-test-") as directory:
            root = Path(directory)
            factory = root / "current"
            shutil.copytree(TEMPLATE, factory)
            source = self.make_source(root)
            self.configure_registry(factory)
            beta_publish(factory, "com.example.sample", source, "a" * 40, "example/factory", root / "artifacts")

            baseline = root / "trusted-baseline"
            shutil.copytree(factory, baseline)
            evidence_path = factory / ".xsec-factory" / "publications" / "com.example.sample.json"
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            evidence["events"][0]["source"]["sha"] = "b" * 40
            evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
            with self.assertRaisesRegex(FactoryError, "must retain every immutable publication evidence event"):
                validate_factory(factory, "example/factory", baseline_root=baseline)

            evidence["events"][0]["source"]["sha"] = "a" * 40
            evidence["events"][0]["publisher"] = "rewritten-publisher"
            evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
            with self.assertRaisesRegex(FactoryError, "must retain every immutable publication evidence event"):
                validate_factory(factory, "example/factory", baseline_root=baseline)

    def test_trusted_baseline_requires_published_evidence_events_to_remain_in_order(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-factory-baseline-evidence-order-test-") as directory:
            root = Path(directory)
            factory = root / "current"
            shutil.copytree(TEMPLATE, factory)
            source = self.make_source(root)
            self.configure_registry(factory)
            beta = beta_publish(factory, "com.example.sample", source, "a" * 40, "example/factory", root / "artifacts")

            baseline = root / "trusted-baseline"
            shutil.copytree(factory, baseline)
            stable_promote(
                factory,
                "com.example.sample",
                source,
                "b" * 40,
                beta["release_id"],
                "example/factory",
            )
            # Appending the Stable event is valid.
            validate_factory(factory, "example/factory", baseline_root=baseline)

            evidence_path = factory / ".xsec-factory" / "publications" / "com.example.sample.json"
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            evidence["events"].reverse()
            evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
            with self.assertRaisesRegex(FactoryError, "must retain every immutable publication evidence event"):
                validate_factory(factory, "example/factory", baseline_root=baseline)

    def test_trusted_baseline_without_a_factory_allows_its_first_published_registration(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-factory-first-publication-test-") as directory:
            root = Path(directory)
            factory = root / "current"
            shutil.copytree(TEMPLATE, factory)
            source = self.make_source(root)
            self.configure_registry(factory)
            beta_publish(factory, "com.example.sample", source, "a" * 40, "example/factory", root / "artifacts")

            # A repository may adopt the Factory template after its protected
            # main history already exists. An absent old registry is a valid
            # empty publication history, not a corrupted baseline.
            baseline = root / "pre-factory-baseline"
            baseline.mkdir()
            validate_factory(factory, "example/factory", baseline_root=baseline)

    def test_registry_repository_slug_rejects_path_like_components(self) -> None:
        for repository in ("../plugin", "team/..", ".team/plugin", "team/plugin..backup"):
            with self.assertRaisesRegex(FactoryError, "owner/repository"):
                safe_repository(repository)

    def test_factory_plugin_ids_match_the_desktop_catalog_grammar(self) -> None:
        self.assertEqual(safe_plugin_id("com.example.sample"), "com.example.sample")
        for plugin_id in (
            "Com.example.sample",
            "com_example.sample",
            "com..example",
            "com--example",
            "com.example.",
            "-com.example",
            "a" * 65,
            "con",
            "nul",
            "lpt1",
            "com1.foo",
        ):
            with self.subTest(plugin_id=plugin_id):
                with self.assertRaisesRegex(FactoryError, "safe plugin identifier|Windows reserved device name"):
                    safe_plugin_id(plugin_id)

        for plugin_id in ("com.xsec", "com.xsec.external-example"):
            with self.subTest(plugin_id=plugin_id):
                with self.assertRaisesRegex(FactoryError, "reserved for the Desktop namespace"):
                    safe_plugin_id(plugin_id)

    def test_factory_rejects_nonportable_desktop_package_paths_before_publication(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-factory-portable-paths-") as directory:
            root = Path(directory)
            factory = root / "factory"
            shutil.copytree(TEMPLATE, factory)
            source = self.make_source(root)
            self.configure_registry(factory)
            (source / "café.js").write_text("export const label = 'café';\n", encoding="utf-8")

            with self.assertRaisesRegex(FactoryError, "portable ASCII"):
                beta_publish(factory, "com.example.sample", source, "a" * 40, "example/factory", root / "artifacts")

            with self.assertRaisesRegex(FactoryError, "collide on case-insensitive"):
                require_portable_package_paths(
                    source,
                    [source / "frontend" / "Foo.js", source / "frontend" / "foo.js"],
                )
            with self.assertRaisesRegex(FactoryError, "file/directory collision"):
                require_portable_package_paths(
                    source,
                    [source / "Foo", source / "foo" / "child.js"],
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
                    with self.assertRaisesRegex(FactoryError, message):
                        portable_target_filesystem_path(relative)

    def test_release_workflows_require_reviewer_gated_production_and_clear_source_reader_credentials(self) -> None:
        workflows = TEMPLATE / ".github" / "workflows"
        readme = (TEMPLATE / "README.md").read_text(encoding="utf-8")
        validate_workflow = (workflows / "validate.yml").read_text(encoding="utf-8")
        self.assertIn('factory_validate.py --root . --factory-repository "$GITHUB_REPOSITORY"', validate_workflow)
        self.assertIn("permissions:\n  contents: read", validate_workflow)
        self.assertIn("Download and verify the complete immutable publication provenance set", validate_workflow)
        self.assertIn('GH_TOKEN: ${{ github.token }}', validate_workflow)
        self.assertIn('factory_attestation.py --github-output "$GITHUB_OUTPUT" download', validate_workflow)
        self.assertIn('--publication-attestation-root "$ATTESTATION_ROOT"', validate_workflow)
        self.assertNotIn("--allow-unsigned-publication-attestations", validate_workflow)
        self.assertIn("fetch-depth: 0", validate_workflow)
        self.assertIn("Materialize trusted pre-change Factory baseline", validate_workflow)
        self.assertIn("PULL_REQUEST_BASE_SHA", validate_workflow)
        self.assertIn("PUSH_BEFORE_SHA", validate_workflow)
        self.assertIn("git worktree add --detach", validate_workflow)
        self.assertIn("--baseline-root", validate_workflow)
        self.assertIn("`production` with **required reviewers limited to release maintainers**", readme)
        self.assertIn("prevent self-review", readme)
        self.assertIn("Do not treat protected-branch status as dispatcher\n   authorization", readme)
        for name, channel in (("publish-beta.yml", "beta"), ("promote-stable.yml", "stable")):
            source = (workflows / name).read_text(encoding="utf-8")
            with self.subTest(workflow=name):
                job_name = "publish" if name == "publish-beta.yml" else "promote"
                job = source.split(f"  {job_name}:\n", 1)[1].split("    steps:\n", 1)[0]
                self.assertIn("environment: production", job)
                self.assertIn("github.ref_protected", source)
                self.assertIn('REF_PROTECTED" = "true"', source)
                self.assertIn("FACTORY_GITHUB_APP_ID", source)
                self.assertIn("FACTORY_GITHUB_APP_PRIVATE_KEY", source)
                self.assertIn("actions/create-github-app-token@v2", source)
                self.assertIn("permission-contents: read", source)
                self.assertIn("persist-credentials: false", source)
                self.assertIn("submodules: false", source)
                self.assertIn("lfs: false", source)
                self.assertIn('SOURCE_TOKEN: ${{ steps.source-token.outputs.token }}', source)
                self.assertIn("github-server-url: https://github.com", source)
                self.assertIn('SOURCE_REPOSITORY: ${{ steps.prepare.outputs.source_repository }}', source)
                self.assertIn('source_git_url="https://github.com/${SOURCE_REPOSITORY}.git"', source)
                self.assertIn("canonical GitHub HTTPS origin", source)
                self.assertIn("GIT_CONFIG_NOSYSTEM=1", source)
                self.assertIn("GIT_CONFIG_GLOBAL=/dev/null", source)
                self.assertIn("GIT_ALLOW_PROTOCOL=https", source)
                self.assertIn("GIT_TERMINAL_PROMPT=0", source)
                self.assertIn("http.sslVerify=true", source)
                self.assertIn("http.followRedirects=false", source)
                self.assertIn("credential.helper=", source)
                self.assertIn("protocol.allow=never", source)
                self.assertIn("protocol.https.allow=always", source)
                self.assertIn("refs/remotes/xsec-factory-source/verified", source)
                self.assertIn("--no-includes", source)
                self.assertIn("insteadof", source)
                self.assertIn("uploadpack|receivepack|vcs|proxy", source)
                self.assertIn("^http\\..*\\.extraheader$", source)
                self.assertIn('-c "http.https://github.com/.extraheader=AUTHORIZATION: basic $token_header"', source)
                self.assertIn("unset token_header", source)
                self.assertLess(source.index("unset SOURCE_TOKEN"), source.index('fetch --no-tags "$source_git_url"'))
                self.assertNotIn("http://github.com", source)
                self.assertNotIn("fetch --no-tags origin", source)
                self.assertNotIn("ls-remote origin", source)
                self.assertIn(f"--channel {channel}", source)
                self.assertIn("--allow-unsigned-publication-attestations", source)
                self.assertIn("Download and verify the complete immutable provenance set", source)
                self.assertIn('factory_attestation.py --github-output "$GITHUB_OUTPUT" download', source)
                self.assertIn('ATTESTATION_ROOT: ${{ steps.attestation-proofs.outputs.attestation_root }}', source)
                self.assertIn('--publication-attestation-root "$ATTESTATION_ROOT"', source)
                self.assertLess(
                    source.index("Download and verify the complete immutable provenance set"),
                    source.index("Strictly validate the complete immutable provenance set"),
                )
                if name == "promote-stable.yml":
                    self.assertIn("Materialize the exact immutable Stable provenance attestation", source)
                    self.assertIn("Verify the immutable Beta package and publish the Stable provenance attestation", source)
                    self.assertIn('gh release download "$RELEASE_TAG" --repo "$release_repo" --pattern "$ARTIFACT_NAME"', source)
                    self.assertIn("sha256sum \"$asset_path\"", source)
                    self.assertLess(
                        source.index("Strictly validate the complete immutable provenance set before moving Stable"),
                        source.index("Commit the stable channel pointer and immutable promotion evidence"),
                    )
                else:
                    self.assertIn("Materialize the exact immutable Beta provenance attestation", source)
                    self.assertIn("Create or verify the immutable GitHub Release asset", source)
        self.assertIn("GitHub.com only", readme)
        self.assertIn("Git transport redirection", readme)


if __name__ == "__main__":
    unittest.main()
