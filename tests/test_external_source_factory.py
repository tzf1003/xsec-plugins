from __future__ import annotations

import base64
import io
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path, PurePosixPath
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


def git(root: Path, *arguments: str) -> None:
    subprocess.run(["git", *arguments], cwd=root, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


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


def write_historical_sidecar(
    document: publisher.MarketplaceDocument,
    destination: Path,
    *,
    source_revision: str = BETA_SHA,
) -> Path:
    """Write one real KMS sidecar without needing a test Cloud broker."""

    envelope = {
        "schema_version": 1,
        "purpose": document.purpose,
        "subject": document.subject,
        "content_sha256": hashlib.sha256(document.path.read_bytes()).hexdigest(),
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
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(sidecar, separators=(",", ":")), encoding="utf-8")
    return destination


def write_historical_release_sidecar(root: Path, plugin_id: str, *, source_revision: str = BETA_SHA) -> Path:
    """Write a real signed release sidecar without needing a test KMS broker."""

    release = factory.release_path(root, plugin_id)
    return write_historical_sidecar(
        publisher.MarketplaceDocument(
            "xsec.plugin-marketplace.release",
            f".xsec-factory/snapshots/{plugin_id}/.xsec-market/releases.json",
            release,
        ),
        release.with_name(release.name + ".sig.jws.json"),
        source_revision=source_revision,
    )


def snapshot_dir(root: Path, plugin_id: str) -> Path:
    return root / build_market.SNAPSHOT_ROOT_RELATIVE_PATH / plugin_id


def write_publication_proof(root: Path, plugin_id: str, *, source_revision: str = BETA_SHA) -> Path:
    """Write a test KMS proof for the exact Factory evidence bytes."""

    document = factory.official_publication_provenance_document(root, plugin_id)
    return write_historical_sidecar(
        document,
        publisher.sidecar_path_for(document),
        source_revision=source_revision,
    )


class ExternalSourceFactoryTests(unittest.TestCase):
    maxDiff = None

    def setUp(self) -> None:
        # Unit fixtures create deterministic local KMS proofs. Production
        # always fetches the fixed issuer JWKS, but tests must not depend on
        # that network endpoint to exercise the strict default validator.
        proof_verifier = patch.object(factory, "verify_historical_sidecar_signature", verify_test_historical_sidecar)
        proof_verifier.start()
        self.addCleanup(proof_verifier.stop)

    def test_first_party_subprojects_require_exact_gitlinks_and_sources(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-first-party-subprojects-") as directory:
            root = Path(directory)
            plugin_id = "com.xsec.workspace.browser"
            repository = factory.FIRST_PARTY_APPROVED_SOURCES[plugin_id]
            path = f"plugins/{plugin_id}"
            (root / ".gitmodules").write_text(
                f'[submodule "{path}"]\n\tpath = {path}\n\turl = https://github.com/{repository}.git\n\tbranch = beta\n',
                encoding="utf-8",
            )
            git(root, "init", "--quiet", "--initial-branch=main")
            git(root, "config", "user.name", "Factory Test")
            git(root, "config", "user.email", "factory-test@example.invalid")
            git(root, "add", ".gitmodules")
            git(root, "update-index", "--add", "--cacheinfo", f"160000,{'a' * 40},{path}")
            git(root, "commit", "--quiet", "-m", "test: add first-party subproject")
            registration = factory.Registration(
                plugin_id=plugin_id,
                trust_tier="first-party",
                repository=repository,
                source_path=PurePosixPath(path),
                beta_ref="refs/heads/beta",
                stable_ref="refs/heads/main",
                installation="INSTALLED_BY_DEFAULT",
                authentication="ON_INSTALL",
                category="Security",
                status="active",
            )

            factory.validate_first_party_subprojects(root, (registration,))

            git(root, "update-index", "--add", "--cacheinfo", f"160000,{'b' * 40},tooling/unreviewed-submodule")
            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "do not match"):
                factory.validate_first_party_subprojects(root, (registration,))
            git(root, "update-index", "--force-remove", "tooling/unreviewed-submodule")

            (root / ".gitmodules").write_text(
                f'[submodule "{path}"]\n\tpath = {path}\n\turl = https://github.com/{repository}.git\n\tbranch = main\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "source is invalid"):
                factory.validate_first_party_subprojects(root, (registration,))

            (root / ".gitmodules").write_text(
                f'[submodule "{path}"]\n\tpath = {path}\n\turl = https://github.com/{repository}.git\n\tbranch = beta\n\tupdate = none\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "unsupported field"):
                factory.validate_first_party_subprojects(root, (registration,))

            (root / ".gitmodules").unlink()
            (root / build_market.SNAPSHOT_ROOT_RELATIVE_PATH).mkdir(parents=True)
            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "manifest is unavailable"):
                factory.validate_first_party_subprojects(root, (registration,))

    def registry_entry(self, *, status: str = "active", repository: str = "acme/external-plugin", path: str = "package") -> dict[str, object]:
        return {
            "pluginId": PLUGIN_ID,
            "trustTier": "external",
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
        write_json(root / ".xsec-factory" / "official-registry.json", {"schemaVersion": 2, "plugins": list(entries)})

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

    def first_party_entry(
        self,
        *,
        repository: str = "tzf1003/xsec-plugin-sub-agent",
        status: str = "pending-adoption",
        installation: str = "INSTALLED_BY_DEFAULT",
    ) -> dict[str, object]:
        plugin_id = "com.xsec.workspace.sub-agent"
        return {
            "pluginId": plugin_id,
            "trustTier": "first-party",
            "source": {
                "repository": repository,
                "path": f"plugins/{plugin_id}",
                "refs": {"beta": "refs/heads/beta", "stable": "refs/heads/main"},
            },
            "policy": {"installation": installation, "authentication": "ON_INSTALL"},
            "category": "Security",
            "status": status,
        }

    def make_first_party_adoption(self, root: Path) -> str:
        plugin_id = "com.xsec.workspace.sub-agent"
        self.make_factory(root, self.first_party_entry())
        snapshot = snapshot_dir(root, plugin_id)
        snapshot.mkdir(parents=True)
        write_json(
            snapshot / "plugin.json",
            {
                "name": plugin_id,
                "version": "1.0.0",
                "extensions": {
                    "com.xsec.desktop": {
                        "engines": {"xsec": ">=1", "pluginApi": "^1"},
                        "entrypoints": {"frontend": "frontend.js"},
                        "permissions": {"process.spawn": {}},
                        "contributes": {"workspaceTools": {"sub-agent": {"title": "Sub agent"}}},
                    }
                },
            },
        )
        (snapshot / "frontend.js").write_text("export function activate() {}\n", encoding="utf-8")
        build_market.build_plugin(snapshot, snapshot)
        registration = factory.registration_for(root, plugin_id, active=False)
        write_json(
            root / ".agents" / "plugins" / "marketplace.json",
            {
                "name": "xsec-official",
                "interface": {"displayName": "Test"},
                "plugins": [factory.marketplace_entry(registration)],
            },
        )
        write_historical_release_sidecar(root, plugin_id)
        factory.create_adoption(
            root,
            plugin_id,
            beta_sha=BETA_SHA,
            stable_sha=STABLE_SHA,
            factory_revision="c" * 40,
        )
        document = publisher.official_adoption_provenance_document(root, plugin_id)
        write_historical_sidecar(document, publisher.sidecar_path_for(document))
        factory.activate_first_party(root, plugin_id)
        _, beta = factory.current_beta_record(root, plugin_id)
        return str(beta["releaseId"])

    def stage_and_record_beta(
        self,
        root: Path,
        source_root: Path,
        *,
        source_sha: str = BETA_SHA,
        write_proof: bool = True,
    ) -> str:
        factory.stage_beta(root, PLUGIN_ID, source_root)
        snapshot = snapshot_dir(root, PLUGIN_ID)
        build_market.build_plugin(snapshot, snapshot)
        factory.record_beta(root, PLUGIN_ID, source_sha, "test-publisher")
        if write_proof:
            write_publication_proof(root, PLUGIN_ID)
        _, record = factory.current_beta_record(root, PLUGIN_ID)
        return str(record["releaseId"])

    def test_staged_first_party_adoption_requires_exact_heads_and_cannot_activate_unsigned(self) -> None:
        """The protected staging phase is useful evidence, never trust by itself."""

        with tempfile.TemporaryDirectory(prefix="xsec-staged-first-party-adoption-") as directory:
            root = Path(directory)
            plugin_id = "com.xsec.workspace.sub-agent"
            self.make_first_party_adoption(root)

            registry_path = root / ".xsec-factory" / "official-registry.json"
            registry = json.loads(registry_path.read_text(encoding="utf-8"))
            registry["plugins"][0]["status"] = "pending-adoption"
            write_json(registry_path, registry)
            (root / factory.ADOPTION_PROOFS_RELATIVE_PATH / f"{plugin_id}.json").unlink()

            baseline = Path(f"{directory}-trusted-pre-staging-baseline")
            self.addCleanup(shutil.rmtree, baseline, ignore_errors=True)
            shutil.copytree(root, baseline)
            (baseline / factory.ADOPTIONS_RELATIVE_PATH / f"{plugin_id}.json").unlink()

            staged = factory.prepare_staged_adoption(
                root,
                plugin_id,
                baseline_root=baseline,
                factory_revision="c" * 40,
            )
            self.assertEqual(staged["adoption"], "staged")
            self.assertEqual(staged["beta_sha"], BETA_SHA)
            self.assertEqual(staged["stable_sha"], STABLE_SHA)
            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "KMS adoption proof is unavailable"):
                factory.activate_first_party(root, plugin_id)

            proof_path = root / factory.ADOPTIONS_RELATIVE_PATH / f"{plugin_id}.json"
            forged = json.loads(proof_path.read_text(encoding="utf-8"))
            forged["legacy"]["factoryRevision"] = "d" * 40
            factory.stable_write(root, proof_path, forged, "forged first-party adoption proof")
            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "does not exactly match"):
                factory.prepare_staged_adoption(
                    root,
                    plugin_id,
                    baseline_root=baseline,
                    factory_revision="c" * 40,
                )

    def test_staged_first_party_adoption_requires_the_exact_pre_staging_revision(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-staged-first-party-adoption-revision-") as directory:
            root = Path(directory)
            plugin_id = "com.xsec.workspace.sub-agent"
            self.make_first_party_adoption(root)

            registry_path = root / ".xsec-factory" / "official-registry.json"
            registry = json.loads(registry_path.read_text(encoding="utf-8"))
            registry["plugins"][0]["status"] = "pending-adoption"
            write_json(registry_path, registry)
            (root / factory.ADOPTION_PROOFS_RELATIVE_PATH / f"{plugin_id}.json").unlink()
            baseline = Path(f"{directory}-trusted-pre-staging-baseline")
            self.addCleanup(shutil.rmtree, baseline, ignore_errors=True)
            shutil.copytree(root, baseline)
            (baseline / factory.ADOPTIONS_RELATIVE_PATH / f"{plugin_id}.json").unlink()

            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "does not exactly match"):
                factory.prepare_staged_adoption(
                    root,
                    plugin_id,
                    baseline_root=baseline,
                    factory_revision="d" * 40,
                )

    def test_staged_adoption_remains_canonical_after_later_factory_main_work(self) -> None:
        """A reviewed proof retains its own baseline through a later rebase."""

        with tempfile.TemporaryDirectory(prefix="xsec-staged-first-party-adoption-rebased-") as directory:
            root = Path(directory)
            plugin_id = "com.xsec.workspace.sub-agent"
            self.make_first_party_adoption(root)

            registry_path = root / ".xsec-factory" / "official-registry.json"
            registry = json.loads(registry_path.read_text(encoding="utf-8"))
            registry["plugins"][0]["status"] = "pending-adoption"
            write_json(registry_path, registry)
            (root / factory.ADOPTION_PROOFS_RELATIVE_PATH / f"{plugin_id}.json").unlink()
            baseline = Path(f"{directory}-original-staging-baseline")
            self.addCleanup(shutil.rmtree, baseline, ignore_errors=True)
            shutil.copytree(root, baseline)
            (baseline / factory.ADOPTIONS_RELATIVE_PATH / f"{plugin_id}.json").unlink()

            # Model unrelated protected-main work landing while the unsigned
            # staging PR is updated for its final protected merge.
            (root / "protected-main-advanced.txt").write_text("unrelated main work\n", encoding="utf-8")
            staged = factory.prepare_staged_adoption(
                root,
                plugin_id,
                baseline_root=baseline,
                factory_revision="c" * 40,
            )
            self.assertEqual(staged["adoption"], "staged")

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
                "con",
                "nul",
                "lpt1",
                "com1.foo",
            ):
                with self.subTest(plugin_id=plugin_id):
                    entry = self.registry_entry()
                    entry["pluginId"] = plugin_id
                    self.make_factory(root, entry)
                    with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "safe plugin identifier|Windows reserved device name"):
                        factory.load_registry(root)

    def test_active_registration_may_exist_before_its_first_beta_snapshot(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-external-empty-") as directory:
            root = Path(directory)
            self.make_factory(root, self.registry_entry())
            factory.validate_registry_and_snapshots(root)

    def test_cli_non_validate_command_does_not_read_validate_only_options(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-external-cli-options-") as directory:
            root = Path(directory)
            self.make_factory(root, self.registry_entry())
            with patch.object(
                sys,
                "argv",
                [
                    "external_source_factory.py",
                    "--root",
                    str(root),
                    "prepare",
                    "--plugin-id",
                    PLUGIN_ID,
                    "--channel",
                    "beta",
                    "--source-sha",
                    BETA_SHA,
                ],
            ):
                factory.main()

    def test_cli_can_emit_a_canonical_json_main_rebuild_result(self) -> None:
        """Workflow consumers must not parse the legacy human-readable output as JSON."""
        with tempfile.TemporaryDirectory(prefix="xsec-external-cli-json-") as directory:
            root = Path(directory)
            source = self.make_source(root / "source")
            self.make_factory(root, self.registry_entry())
            self.stage_and_record_beta(root, source)
            output = io.StringIO()
            with patch.object(
                sys,
                "argv",
                [
                    "external_source_factory.py",
                    "--root",
                    str(root),
                    "--json",
                    "check-main-rebuild",
                    "--plugin-id",
                    PLUGIN_ID,
                    "--source-root",
                    str(source),
                ],
            ), redirect_stdout(output):
                factory.main()
            result = json.loads(output.getvalue())
            self.assertEqual(result["plugin_id"], PLUGIN_ID)
            self.assertIn(result["state"], {"waiting_for_beta", "waiting_for_smoke"})

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
            snapshot_dir(root, PLUGIN_ID).mkdir(parents=True)

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
            build_market.build_plugin(snapshot_dir(root, PLUGIN_ID), snapshot_dir(root, PLUGIN_ID))
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
                build_market.build_plugin(snapshot_dir(root, PLUGIN_ID), snapshot_dir(root, PLUGIN_ID))

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
            write_publication_proof(root, PLUGIN_ID)
            factory.validate_registry_and_snapshots(root)

            events = json.loads(factory.publication_path(root, PLUGIN_ID).read_text(encoding="utf-8"))["events"]
            self.assertEqual(events[-1]["channel"], "stable")
            self.assertEqual(events[-1]["source"]["sha"], STABLE_SHA)

    def test_first_party_main_rebuild_gate_waits_without_mutating_release_history_or_evidence(self) -> None:
        """A split main behind Beta is an auditable wait, never a failed Stable release."""

        with tempfile.TemporaryDirectory(prefix="xsec-first-party-main-rebuild-gate-") as directory:
            workspace = Path(directory)
            root = workspace / "factory"
            plugin_id = "com.xsec.workspace.sub-agent"
            release_id = self.make_first_party_adoption(root)
            source_root = workspace / "source-main"
            shutil.copytree(
                snapshot_dir(root, plugin_id),
                source_root / "plugins" / plugin_id,
                ignore=shutil.ignore_patterns(".xsec-market"),
            )

            matching = factory.check_main_rebuild(root, plugin_id, source_root)
            self.assertEqual(matching["beta_release_id"], release_id)
            self.assertEqual(matching["state"], "waiting_for_smoke")
            self.assertEqual(matching["smoke_ready"], "true")

            # A first-party Beta may point at an adopted immutable release.
            # Its readable wait state still needs the exact signed Beta event.
            factory.record_beta(root, plugin_id, BETA_SHA, "test-publisher")
            write_publication_proof(root, plugin_id)
            release_before = factory.release_path(root, plugin_id).read_bytes()
            evidence_before = factory.publication_path(root, plugin_id).read_bytes()
            (source_root / "plugins" / plugin_id / "frontend.js").write_text(
                "export function activate() { return 'main-behind-beta'; }\n",
                encoding="utf-8",
            )

            waiting = factory.check_main_rebuild(root, plugin_id, source_root)
            self.assertEqual(waiting["state"], "waiting_for_beta")
            self.assertEqual(waiting["smoke_ready"], "false")
            # The classifier is deliberately read-only: no Stable evidence or
            # pointer may appear merely because main has not caught up yet.
            self.assertEqual(factory.release_path(root, plugin_id).read_bytes(), release_before)
            self.assertEqual(factory.publication_path(root, plugin_id).read_bytes(), evidence_before)

            factory.record_status(
                root,
                plugin_id,
                beta_sha=BETA_SHA,
                stable_sha=None,
                state="waiting_for_beta",
                delivery_id="main-behind-beta",
            )
            factory.validate_registry_and_snapshots(root)
            baseline = workspace / "trusted-waiting-for-beta"
            shutil.copytree(root, baseline)

            # A later main commit that exactly rebuilds the same Beta may only
            # reopen smoke for the existing source/release tuple. Reverting
            # to waiting_for_beta remains equally bound to that tuple.
            factory.record_status(
                root,
                plugin_id,
                beta_sha=BETA_SHA,
                stable_sha=None,
                state="waiting_for_smoke",
                delivery_id="main-caught-up",
            )
            factory.validate_registry_and_snapshots(root, baseline_root=baseline)
            factory.record_status(
                root,
                plugin_id,
                beta_sha=BETA_SHA,
                stable_sha=None,
                state="waiting_for_beta",
                delivery_id="main-moved-again",
            )
            factory.validate_registry_and_snapshots(root, baseline_root=baseline)

    def test_stable_rejects_a_smoke_selected_historical_beta_after_a_newer_beta_exists(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-external-stale-stable-") as directory:
            root = Path(directory)
            source = self.make_source(root / "source")
            self.make_factory(root, self.registry_entry())
            historical_release_id = self.stage_and_record_beta(root, source)
            historical_source = root / "historical-source"
            shutil.copytree(source, historical_source)
            manifest_path = source / "package" / "plugin.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["version"] = "1.0.1"
            write_json(manifest_path, manifest)
            (source / "package" / "frontend.js").write_text("export function activate() { return 'new-beta'; }\n", encoding="utf-8")
            self.stage_and_record_beta(root, source, source_sha=STABLE_SHA)

            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "does not match the current Beta pointer"):
                factory.verify_stable(root, PLUGIN_ID, historical_source, historical_release_id)

    def test_stable_rechecks_the_smoke_verified_beta_source_sha_inside_the_publish_slot(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-external-stale-beta-sha-") as directory:
            root = Path(directory)
            source = self.make_source(root / "source")
            self.make_factory(root, self.registry_entry())
            release_id = self.stage_and_record_beta(root, source)
            factory.record_status(
                root,
                PLUGIN_ID,
                beta_sha=BETA_SHA,
                stable_sha=None,
                state="waiting_for_smoke",
                delivery_id="beta-a",
            )
            self.assertEqual(
                factory.verify_stable(root, PLUGIN_ID, source, release_id, expected_beta_sha=BETA_SHA)["release_id"],
                release_id,
            )
            # A later Beta source commit can have exactly the same artifact
            # and releaseId. Its status SHA, not the releaseId, tells Stable
            # that the prior Desktop smoke callback is no longer current.
            factory.record_status(
                root,
                PLUGIN_ID,
                beta_sha=STABLE_SHA,
                stable_sha=None,
                state="waiting_for_smoke",
                delivery_id="beta-b-same-release",
            )
            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "must match immutable Beta provenance"):
                factory.verify_stable(root, PLUGIN_ID, source, release_id, expected_beta_sha=BETA_SHA)

    def test_committed_node_modules_do_not_break_beta_to_stable_content_identity(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-external-node-modules-") as directory:
            root = Path(directory)
            source = self.make_source(root / "source")
            dependency = source / "package" / "node_modules" / "fixture" / "index.js"
            dependency.parent.mkdir(parents=True)
            dependency.write_text("module.exports = 'not a package input';\n", encoding="utf-8")
            self.make_factory(root, self.registry_entry())
            release_id = self.stage_and_record_beta(root, source)

            self.assertFalse((snapshot_dir(root, PLUGIN_ID) / "node_modules").exists())
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

            snapshot = snapshot_dir(root, PLUGIN_ID)
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

            shutil.rmtree(snapshot_dir(root, PLUGIN_ID))
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
            write_json(root / ".xsec-factory" / "official-registry.json", {"schemaVersion": 2, "plugins": []})
            factory.publication_path(root, PLUGIN_ID).unlink()
            manifest_path = snapshot_dir(root, PLUGIN_ID) / "plugin.json"
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
            write_json(root / ".xsec-factory" / "official-registry.json", {"schemaVersion": 2, "plugins": []})
            write_json(
                root / ".agents" / "plugins" / "marketplace.json",
                {"name": "xsec-official", "interface": {"displayName": "Test"}, "plugins": []},
            )
            shutil.rmtree(snapshot_dir(root, PLUGIN_ID))
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
                {"schemaVersion": 2, "plugins": [rewritten]},
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
            write_publication_proof(root, PLUGIN_ID)
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

    def test_trusted_baseline_accepts_then_preserves_append_only_smoke_outcomes(self) -> None:
        """The first terminal smoke outcome extends a legacy evidence record."""

        with tempfile.TemporaryDirectory(prefix="xsec-external-baseline-smoke-outcome-") as directory:
            workspace = Path(directory)
            root = workspace / "current"
            source = self.make_source(root / "source")
            self.make_factory(root, self.registry_entry())
            release_id = self.stage_and_record_beta(root, source)
            factory.record_status(
                root,
                PLUGIN_ID,
                beta_sha=BETA_SHA,
                stable_sha=None,
                state="waiting_for_smoke",
                delivery_id="beta-delivery",
            )
            self.assertTrue(promote_release.promote_stable(root, PLUGIN_ID, release_id))
            factory.record_stable(root, PLUGIN_ID, STABLE_SHA, release_id, "test-publisher")
            write_publication_proof(root, PLUGIN_ID)
            baseline = workspace / "trusted-before-smoke"
            shutil.copytree(root, baseline)

            # A pending Desktop callback requires this source/release binding
            # to remain present. Without it, complete_smoke_status cannot
            # prove that the callback belongs to the current Beta.
            pending_status_path = factory.status_path(root, PLUGIN_ID)
            pending_status = pending_status_path.read_bytes()
            pending_status_path.unlink()
            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "retain its smoke-gated Factory status"):
                factory.validate_registry_and_snapshots(
                    root,
                    baseline_root=baseline,
                    require_publication_proofs=False,
                )
            pending_status_path.write_bytes(pending_status)

            # The only same-Beta lifecycle advance is waiting -> promoting;
            # promoting must never be rewritten back to waiting by a PR.
            pending = json.loads(pending_status_path.read_text(encoding="utf-8"))
            pending["publication"]["state"] = "promoting_stable"
            write_json(pending_status_path, pending)
            factory.validate_trusted_baseline_continuity(
                root,
                factory.load_registry(root),
                baseline,
            )
            promoting_baseline = workspace / "trusted-promoting-smoke"
            shutil.copytree(root, promoting_baseline)
            pending["publication"]["state"] = "waiting_for_smoke"
            write_json(pending_status_path, pending)
            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "unless an exact new Beta smoke cycle"):
                factory.validate_trusted_baseline_continuity(
                    root,
                    factory.load_registry(root),
                    promoting_baseline,
                )
            pending_status_path.write_bytes(pending_status)

            factory.complete_smoke_status(
                root,
                PLUGIN_ID,
                beta_release_id=release_id,
                stable_sha=STABLE_SHA,
                delivery_id="smoke-delivery",
                smoke_run_url="https://github.com/tzf1003/xSecDesktop/actions/runs/200",
                marketplace_revision="c" * 40,
            )
            write_publication_proof(root, PLUGIN_ID)
            factory.validate_registry_and_snapshots(root, baseline_root=baseline)

            terminal_baseline = workspace / "trusted-terminal-smoke"
            shutil.copytree(root, terminal_baseline)
            status_path = factory.status_path(root, PLUGIN_ID)
            original_status = status_path.read_bytes()
            status_path.unlink()
            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "must retain its terminal published status"):
                factory.validate_registry_and_snapshots(
                    root,
                    baseline_root=terminal_baseline,
                    require_publication_proofs=False,
                )

            status_path.write_bytes(original_status)
            status = json.loads(status_path.read_text(encoding="utf-8"))
            status["publication"]["state"] = "waiting_for_smoke"
            write_json(status_path, status)
            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "must retain its terminal published status"):
                factory.validate_registry_and_snapshots(
                    root,
                    baseline_root=terminal_baseline,
                    require_publication_proofs=False,
                )

            status_path.write_bytes(original_status)
            evidence_path = factory.publication_path(root, PLUGIN_ID)
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            evidence["smokeOutcomes"][0]["smoke"]["marketplaceRevision"] = "d" * 40
            write_json(evidence_path, evidence)
            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "must retain every immutable smoke outcome"):
                factory.validate_registry_and_snapshots(
                    root,
                    baseline_root=terminal_baseline,
                    require_publication_proofs=False,
                )

    def test_strict_gate_rejects_a_complete_preseeded_first_publication_without_kms_proof(self) -> None:
        """A PR cannot manufacture snapshot/release/evidence in its first change."""

        with tempfile.TemporaryDirectory(prefix="xsec-external-preseeded-first-publication-") as directory:
            root = Path(directory)
            source = self.make_source(root / "source")
            self.make_factory(root, self.registry_entry())
            self.stage_and_record_beta(root, source, write_proof=False)

            # This is deliberately a complete syntactically-valid Factory
            # publication. Its only absent input is the KMS proof that the
            # protected workflow signs after checking external reachability.
            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "KMS provenance proof is unavailable"):
                factory.validate_registry_and_snapshots(root, require_publication_proofs=True)

            write_publication_proof(root, PLUGIN_ID)
            with patch.object(factory, "verify_historical_sidecar_signature", verify_test_historical_sidecar):
                factory.validate_registry_and_snapshots(root, require_publication_proofs=True)

    def test_strict_gate_rejects_an_unsigned_append_to_existing_source_evidence(self) -> None:
        """A previous release sidecar cannot authenticate a later fake source SHA."""

        with tempfile.TemporaryDirectory(prefix="xsec-external-forged-provenance-append-") as directory:
            root = Path(directory)
            source = self.make_source(root / "source")
            self.make_factory(root, self.registry_entry())
            self.stage_and_record_beta(root, source)
            write_publication_proof(root, PLUGIN_ID)

            registration = factory.registration_for(root, PLUGIN_ID)
            _, record = factory.current_beta_record(root, PLUGIN_ID)
            factory.append_evidence(
                root,
                registration,
                factory.publication_event(registration, "beta", STABLE_SHA, record, "forged-pr-author"),
            )

            with patch.object(factory, "verify_historical_sidecar_signature", verify_test_historical_sidecar):
                with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "KMS provenance proof is invalid"):
                    factory.validate_registry_and_snapshots(root, require_publication_proofs=True)

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

    def test_trusted_baseline_accepts_legacy_v1_external_registry_during_the_v2_upgrade(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-external-v1-baseline-") as directory:
            workspace = Path(directory)
            root = workspace / "current"
            source = self.make_source(root / "source")
            self.make_factory(root, self.registry_entry())
            self.stage_and_record_beta(root, source)
            baseline = workspace / "trusted-v1-baseline"
            shutil.copytree(root, baseline)
            legacy_entry = self.registry_entry()
            legacy_entry.pop("trustTier")
            write_json(
                baseline / ".xsec-factory" / "official-registry.json",
                {"schemaVersion": 1, "plugins": [legacy_entry]},
            )

            factory.validate_registry_and_snapshots(root, baseline_root=baseline)

    def test_trusted_pending_first_party_baseline_can_be_activated_only_with_its_adoption(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-first-party-pending-baseline-") as directory:
            workspace = Path(directory)
            root = workspace / "current"
            self.make_first_party_adoption(root)
            baseline = workspace / "trusted-pending-baseline"
            shutil.copytree(root, baseline)
            pending = self.first_party_entry(status="pending-adoption")
            write_json(
                baseline / ".xsec-factory" / "official-registry.json",
                {"schemaVersion": 2, "plugins": [pending]},
            )
            factory.adoption_path(baseline, "com.xsec.workspace.sub-agent").unlink()
            (baseline / factory.ADOPTION_PROOFS_RELATIVE_PATH / "com.xsec.workspace.sub-agent.json").unlink()

            factory.validate_registry_and_snapshots(root, baseline_root=baseline)

            # The staging PR itself remains pending and contains no sidecar;
            # it must validate against an equally pending trusted baseline.
            write_json(root / ".xsec-factory" / "official-registry.json", {"schemaVersion": 2, "plugins": [pending]})
            factory.adoption_path(root, "com.xsec.workspace.sub-agent").unlink()
            (root / factory.ADOPTION_PROOFS_RELATIVE_PATH / "com.xsec.workspace.sub-agent.json").unlink()
            factory.validate_registry_and_snapshots(root, baseline_root=baseline)

            disabled = self.first_party_entry(status="disabled")
            write_json(root / ".xsec-factory" / "official-registry.json", {"schemaVersion": 2, "plugins": [disabled]})
            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "must remain pending or be activated"):
                factory.validate_registry_and_snapshots(root, baseline_root=baseline)

    def test_snapshot_root_rejects_symlink_entries_before_ownership_checks(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-external-snapshot-link-") as directory:
            root = Path(directory)
            self.make_factory(root)
            snapshot = snapshot_dir(root, "com.xsec.asset-discovery")
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

            manifest_path = snapshot_dir(root, PLUGIN_ID) / "plugin.json"
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

    def test_first_party_registry_is_closed_to_the_exact_approved_repository(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-first-party-registry-") as directory:
            root = Path(directory)
            entry = self.first_party_entry(repository="tzf1003/looks-like-sub-agent")
            self.make_factory(root, entry)
            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "does not match the approved first-party source"):
                factory.load_registry(root)

            entry = self.first_party_entry()
            entry["trustTier"] = "external"
            self.make_factory(root, entry)
            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "reserved for the Desktop namespace"):
                factory.load_registry(root)

            self.make_factory(root, self.first_party_entry())
            self.assertEqual(factory.load_registry(root)[0].installation, "INSTALLED_BY_DEFAULT")

            self.make_factory(root, self.first_party_entry(installation="AVAILABLE"))
            self.assertEqual(factory.load_registry(root)[0].installation, "AVAILABLE")

            entry = self.registry_entry()
            entry["status"] = "pending-adoption"
            self.make_factory(root, entry)
            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "invalid for its trust tier"):
                factory.load_registry(root)

    def test_signed_first_party_adoption_binds_history_source_heads_and_channel_pointers(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-first-party-adoption-") as directory:
            root = Path(directory)
            release_id = self.make_first_party_adoption(root)
            factory.validate_registry_and_snapshots(root)

            adoption_path = factory.adoption_path(root, "com.xsec.workspace.sub-agent")
            adoption = json.loads(adoption_path.read_text(encoding="utf-8"))
            original_adoption = json.loads(json.dumps(adoption))
            adoption["source"]["betaSha"] = "d" * 40
            write_json(adoption_path, adoption)
            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "KMS adoption proof is invalid"):
                factory.validate_registry_and_snapshots(root)

            # Restore the signed payload, then demonstrate that a pointer
            # rewrite is detected before any new source can be accepted.
            write_json(adoption_path, original_adoption)
            adoption = json.loads(adoption_path.read_text(encoding="utf-8"))
            adoption["channels"]["beta"] = {"releaseId": "sha256-" + "0" * 64}
            write_json(adoption_path, adoption)
            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "channel pointer is not historical"):
                factory.validate_registry_and_snapshots(root)
            self.assertTrue(release_id.startswith("sha256-"))

    def test_pre_kms_staging_allows_only_missing_active_first_party_release_sidecars(self) -> None:
        """The protected publisher may replace sidecars, but cannot mask a bad one."""

        with tempfile.TemporaryDirectory(prefix="xsec-first-party-pre-kms-sidecars-") as directory:
            root = Path(directory)
            self.make_first_party_adoption(root)
            plugin_id = "com.xsec.workspace.sub-agent"
            sidecar = factory.release_path(root, plugin_id).with_name("releases.json.sig.jws.json")
            sidecar.unlink()

            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "KMS release sidecar is unavailable"):
                factory.validate_registry_and_snapshots(root)
            factory.validate_registry_and_snapshots(
                root,
                require_publication_proofs=False,
                require_active_release_sidecars=False,
            )

            sidecar.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "KMS release sidecar is invalid"):
                factory.validate_registry_and_snapshots(
                    root,
                    require_publication_proofs=False,
                    require_active_release_sidecars=False,
                )

    def test_pre_kms_staging_allows_missing_pending_adoption_release_sidecar(self) -> None:
        """A discoverable pending adoption uses the same bounded KMS window."""

        with tempfile.TemporaryDirectory(prefix="xsec-pending-adoption-pre-kms-sidecars-") as directory:
            root = Path(directory)
            self.make_first_party_adoption(root)
            plugin_id = "com.xsec.workspace.sub-agent"
            registry_path = root / ".xsec-factory" / "official-registry.json"
            registry = json.loads(registry_path.read_text(encoding="utf-8"))
            registry["plugins"][0]["status"] = "pending-adoption"
            write_json(registry_path, registry)
            (root / factory.ADOPTION_PROOFS_RELATIVE_PATH / f"{plugin_id}.json").unlink()
            sidecar = factory.release_path(root, plugin_id).with_name("releases.json.sig.jws.json")
            sidecar.unlink()

            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "KMS release sidecar is unavailable"):
                factory.validate_registry_and_snapshots(root)
            factory.validate_registry_and_snapshots(
                root,
                require_publication_proofs=False,
                require_active_release_sidecars=False,
            )

            sidecar.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "KMS release sidecar is invalid"):
                factory.validate_registry_and_snapshots(
                    root,
                    require_publication_proofs=False,
                    require_active_release_sidecars=False,
                )

    def test_first_party_published_status_requires_signed_adoption_and_exact_release_pointers(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-first-party-status-") as directory:
            root = Path(directory)
            release_id = self.make_first_party_adoption(root)
            self.assertTrue(promote_release.promote_stable(root, "com.xsec.workspace.sub-agent", release_id))
            # The test moves the immutable pointer directly, so refresh the
            # release sidecar just as the protected Stable publisher would.
            write_historical_release_sidecar(root, "com.xsec.workspace.sub-agent")
            registration = factory.registration_for(root, "com.xsec.workspace.sub-agent")
            # A terminal status is not authenticated by adoption alone: the
            # protected smoke path appends a KMS-signed outcome tied to the
            # exact Beta/Stable source provenance before it writes Desktop's
            # readable status sidecar.
            factory.record_beta(root, "com.xsec.workspace.sub-agent", BETA_SHA, "test-publisher")
            factory.record_stable(root, "com.xsec.workspace.sub-agent", STABLE_SHA, release_id, "test-publisher")
            factory.append_smoke_outcome(
                root,
                registration,
                beta_release_id=release_id,
                stable_release_id=release_id,
                beta_sha=BETA_SHA,
                stable_sha=STABLE_SHA,
                smoke_run_url="https://github.com/tzf1003/xSecDesktop/actions/runs/42",
                marketplace_revision="c" * 40,
            )
            write_publication_proof(root, "com.xsec.workspace.sub-agent")
            factory.record_status(
                root,
                "com.xsec.workspace.sub-agent",
                beta_sha=BETA_SHA,
                stable_sha=STABLE_SHA,
                state="published",
                delivery_id="delivery-42",
                smoke_run_url="https://github.com/tzf1003/xSecDesktop/actions/runs/42",
                marketplace_revision="c" * 40,
            )
            factory.validate_registry_and_snapshots(root)
            status_path = factory.status_path(root, "com.xsec.workspace.sub-agent")
            status = json.loads(status_path.read_text(encoding="utf-8"))
            valid_status = json.loads(json.dumps(status))
            status["publication"]["smokeRunUrl"] = None
            write_json(status_path, status)
            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "must retain Desktop smoke evidence"):
                factory.validate_registry_and_snapshots(root)

            write_json(status_path, valid_status)
            status = json.loads(status_path.read_text(encoding="utf-8"))
            status["source"]["stableSha"] = None
            write_json(status_path, status)
            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "must retain both Beta and Stable source SHAs"):
                factory.validate_registry_and_snapshots(root)

            write_json(status_path, valid_status)
            status = json.loads(status_path.read_text(encoding="utf-8"))
            status["release"]["betaReleaseId"] = "sha256-" + "0" * 64
            write_json(status_path, status)
            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "release pointers do not match"):
                factory.validate_registry_and_snapshots(root)

            write_json(status_path, valid_status)
            status = json.loads(status_path.read_text(encoding="utf-8"))
            status["source"]["betaSha"] = "d" * 40
            write_json(status_path, status)
            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "does not match KMS-bound smoke evidence"):
                factory.validate_registry_and_snapshots(root)

            write_json(status_path, valid_status)
            status = json.loads(status_path.read_text(encoding="utf-8"))
            status["publication"]["marketplaceRevision"] = "d" * 40
            write_json(status_path, status)
            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "does not match KMS-bound smoke evidence"):
                factory.validate_registry_and_snapshots(root)
            self.assertTrue(release_id.startswith("sha256-"))

    def test_duplicate_status_delivery_keeps_the_original_audited_delivery_identity(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-factory-status-dedupe-") as directory:
            root = Path(directory)
            self.make_factory(root, self.registry_entry())
            first = factory.record_status(
                root,
                PLUGIN_ID,
                beta_sha=BETA_SHA,
                stable_sha=None,
                state="waiting_for_smoke",
                delivery_id="delivery-1",
            )
            duplicate = factory.record_status(
                root,
                PLUGIN_ID,
                beta_sha=BETA_SHA,
                stable_sha=None,
                state="waiting_for_smoke",
                delivery_id="delivery-2",
            )
            status = json.loads(factory.status_path(root, PLUGIN_ID).read_text(encoding="utf-8"))
            self.assertNotIn("unchanged", first)
            self.assertEqual(duplicate["unchanged"], "true")
            self.assertEqual(status["publication"]["deliveryId"], "delivery-1")

    def test_smoke_completion_marks_an_already_promoted_release_published_idempotently(self) -> None:
        """A late smoke callback must not leave Desktop at waiting_for_smoke."""

        with tempfile.TemporaryDirectory(prefix="xsec-factory-smoke-terminal-") as directory:
            root = Path(directory)
            self.make_factory(root, self.registry_entry())
            release_id = self.stage_and_record_beta(root, self.make_source(root / "source"))
            factory.record_status(
                root,
                PLUGIN_ID,
                beta_sha=BETA_SHA,
                stable_sha=None,
                state="waiting_for_smoke",
                delivery_id="beta-delivery",
                factory_run_url="https://github.com/acme/factory/actions/runs/100",
            )
            self.assertTrue(promote_release.promote_stable(root, PLUGIN_ID, release_id))
            factory.record_stable(root, PLUGIN_ID, STABLE_SHA, release_id, "test-publisher")
            # The documented manual recovery has no new Beta argument. It
            # must retain the source SHA that the pending smoke callback is
            # bound to, otherwise the later protected completion fails.
            factory.record_status(
                root,
                PLUGIN_ID,
                beta_sha=None,
                stable_sha=STABLE_SHA,
                state="promoting_stable",
                delivery_id="manual-recovery",
                factory_run_url="https://github.com/acme/factory/actions/runs/150",
            )
            recovered = json.loads(factory.status_path(root, PLUGIN_ID).read_text(encoding="utf-8"))
            self.assertEqual(recovered["source"]["betaSha"], BETA_SHA)

            completed = factory.complete_smoke_status(
                root,
                PLUGIN_ID,
                beta_release_id=release_id,
                stable_sha=STABLE_SHA,
                delivery_id="smoke-delivery",
                smoke_run_url="https://github.com/tzf1003/xSecDesktop/actions/runs/200",
                marketplace_revision="c" * 40,
            )
            duplicate = factory.complete_smoke_status(
                root,
                PLUGIN_ID,
                beta_release_id=release_id,
                stable_sha=STABLE_SHA,
                delivery_id="late-smoke-delivery",
                smoke_run_url="https://github.com/tzf1003/xSecDesktop/actions/runs/201",
                # A retained later Factory revision can re-run the Desktop
                # sweep for this already-published tuple. It must reuse the
                # original KMS-bound metadata rather than write a status
                # which has no matching immutable smoke outcome.
                marketplace_revision="d" * 40,
            )
            status = json.loads(factory.status_path(root, PLUGIN_ID).read_text(encoding="utf-8"))
            self.assertEqual(completed["state"], "published")
            self.assertEqual(duplicate["unchanged"], "true")
            self.assertEqual(status["source"]["betaSha"], BETA_SHA)
            self.assertEqual(status["source"]["stableSha"], STABLE_SHA)
            self.assertEqual(status["publication"]["state"], "published")
            self.assertEqual(status["publication"]["deliveryId"], "smoke-delivery")
            self.assertEqual(status["publication"]["factoryRunUrl"], "https://github.com/acme/factory/actions/runs/150")
            self.assertEqual(status["publication"]["smokeRunUrl"], "https://github.com/tzf1003/xSecDesktop/actions/runs/200")
            self.assertEqual(status["publication"]["marketplaceRevision"], "c" * 40)
            evidence = json.loads(factory.publication_path(root, PLUGIN_ID).read_text(encoding="utf-8"))
            self.assertEqual(len(evidence["smokeOutcomes"]), 1)
            self.assertEqual(evidence["smokeOutcomes"][0]["smoke"]["marketplaceRevision"], "c" * 40)
            write_publication_proof(root, PLUGIN_ID)
            factory.validate_registry_and_snapshots(root)
            duplicate_beta = factory.record_status(
                root,
                PLUGIN_ID,
                beta_sha=BETA_SHA,
                stable_sha=None,
                state="waiting_for_smoke",
                delivery_id="redelivered-beta",
                factory_run_url="https://github.com/acme/factory/actions/runs/300",
            )
            self.assertEqual(duplicate_beta, {"plugin_id": PLUGIN_ID, "state": "published", "unchanged": "true"})
            preserved = json.loads(factory.status_path(root, PLUGIN_ID).read_text(encoding="utf-8"))
            self.assertEqual(preserved, status)
            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "does not match the current Factory status"):
                factory.complete_smoke_status(
                    root,
                    PLUGIN_ID,
                    beta_release_id="sha256-" + "0" * 64,
                    stable_sha=STABLE_SHA,
                    delivery_id="wrong-release",
                    smoke_run_url="https://github.com/tzf1003/xSecDesktop/actions/runs/202",
                    marketplace_revision="c" * 40,
                )

    def test_in_flight_status_cannot_claim_unbound_stable_or_smoke_evidence(self) -> None:
        """Waiting and promoting sidecars must expose only their proven lifecycle fields."""

        with tempfile.TemporaryDirectory(prefix="xsec-factory-in-flight-status-fields-") as directory:
            root = Path(directory)
            self.make_factory(root, self.registry_entry())
            release_id = self.stage_and_record_beta(root, self.make_source(root / "source"))
            factory.record_status(
                root,
                PLUGIN_ID,
                beta_sha=BETA_SHA,
                stable_sha=None,
                state="waiting_for_smoke",
                delivery_id="beta-delivery",
            )
            waiting_path = factory.status_path(root, PLUGIN_ID)
            waiting = json.loads(waiting_path.read_text(encoding="utf-8"))
            forged_waiting = json.loads(json.dumps(waiting))
            forged_waiting["source"]["stableSha"] = STABLE_SHA
            forged_waiting["publication"]["smokeRunUrl"] = "https://github.com/tzf1003/xSecDesktop/actions/runs/600"
            forged_waiting["publication"]["marketplaceRevision"] = "c" * 40
            write_json(waiting_path, forged_waiting)
            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "waiting Factory status must not claim Stable or smoke evidence"):
                factory.validate_registry_and_snapshots(root)

            write_json(waiting_path, waiting)
            waiting_for_beta = json.loads(json.dumps(waiting))
            waiting_for_beta["publication"]["state"] = "waiting_for_beta"
            write_json(waiting_path, waiting_for_beta)
            factory.validate_registry_and_snapshots(root)
            forged_waiting_for_beta = json.loads(json.dumps(waiting_for_beta))
            forged_waiting_for_beta["source"]["stableSha"] = STABLE_SHA
            forged_waiting_for_beta["publication"]["smokeRunUrl"] = "https://github.com/tzf1003/xSecDesktop/actions/runs/602"
            forged_waiting_for_beta["publication"]["marketplaceRevision"] = "f" * 40
            write_json(waiting_path, forged_waiting_for_beta)
            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "waiting Factory status must not claim Stable or smoke evidence"):
                factory.validate_registry_and_snapshots(root)

            write_json(waiting_path, waiting)
            self.assertTrue(promote_release.promote_stable(root, PLUGIN_ID, release_id))
            factory.record_stable(root, PLUGIN_ID, STABLE_SHA, release_id, "test-publisher")
            write_publication_proof(root, PLUGIN_ID)
            factory.record_status(
                root,
                PLUGIN_ID,
                beta_sha=None,
                stable_sha=STABLE_SHA,
                state="promoting_stable",
                delivery_id="stable-delivery",
            )
            factory.validate_registry_and_snapshots(root)
            promoting_path = factory.status_path(root, PLUGIN_ID)
            promoting = json.loads(promoting_path.read_text(encoding="utf-8"))
            forged_promoting = json.loads(json.dumps(promoting))
            forged_promoting["source"]["stableSha"] = "d" * 40
            write_json(promoting_path, forged_promoting)
            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "promoting Factory status must match immutable Stable provenance"):
                factory.validate_registry_and_snapshots(root)

            forged_promoting = json.loads(json.dumps(promoting))
            forged_promoting["publication"]["smokeRunUrl"] = "https://github.com/tzf1003/xSecDesktop/actions/runs/601"
            forged_promoting["publication"]["marketplaceRevision"] = "e" * 40
            write_json(promoting_path, forged_promoting)
            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "promoting Factory status must not claim Desktop smoke evidence"):
                factory.validate_registry_and_snapshots(root)

    def test_promoting_status_cannot_pair_current_beta_with_historical_stable(self) -> None:
        """A signed historical Stable event cannot fabricate a new promotion."""

        with tempfile.TemporaryDirectory(prefix="xsec-factory-promoting-current-beta-") as directory:
            root = Path(directory)
            source = self.make_source(root / "source")
            self.make_factory(root, self.registry_entry())
            historical_release = self.stage_and_record_beta(root, source)
            self.assertTrue(promote_release.promote_stable(root, PLUGIN_ID, historical_release))
            factory.record_stable(root, PLUGIN_ID, STABLE_SHA, historical_release, "test-publisher")
            write_publication_proof(root, PLUGIN_ID)

            source_manifest = source / "package" / "plugin.json"
            manifest = json.loads(source_manifest.read_text(encoding="utf-8"))
            manifest["version"] = "1.0.1"
            write_json(source_manifest, manifest)
            (source / "package" / "frontend.js").write_text(
                "export function activate() { return 'new-beta'; }\n",
                encoding="utf-8",
            )
            current_beta_sha = "d" * 40
            current_release = self.stage_and_record_beta(root, source, source_sha=current_beta_sha)
            self.assertNotEqual(current_release, historical_release)
            # The immutable evidence now contains a valid current Beta event
            # and a valid historical Stable event, but Stable still points to
            # that old release. A normal PR must not stitch them into an
            # apparent promotion.
            factory.record_status(
                root,
                PLUGIN_ID,
                beta_sha=current_beta_sha,
                stable_sha=STABLE_SHA,
                state="promoting_stable",
                delivery_id="forged-historical-stable",
            )
            write_publication_proof(root, PLUGIN_ID, source_revision=current_beta_sha)
            with self.assertRaisesRegex(
                factory.ExternalSourceFactoryError,
                "promoting Factory status must promote the current Beta release",
            ):
                factory.validate_registry_and_snapshots(root)

    def test_published_baseline_cannot_roll_back_to_an_older_signed_smoke_outcome(self) -> None:
        """A later valid smoke result cannot be replaced by a prior terminal tuple."""

        with tempfile.TemporaryDirectory(prefix="xsec-factory-published-outcome-rollback-") as directory:
            workspace = Path(directory)
            root = workspace / "current"
            self.make_factory(root, self.registry_entry())
            release_id = self.stage_and_record_beta(root, self.make_source(root / "source"))
            factory.record_status(
                root,
                PLUGIN_ID,
                beta_sha=BETA_SHA,
                stable_sha=None,
                state="waiting_for_smoke",
                delivery_id="first-beta",
            )
            self.assertTrue(promote_release.promote_stable(root, PLUGIN_ID, release_id))
            factory.record_stable(root, PLUGIN_ID, STABLE_SHA, release_id, "test-publisher")
            write_publication_proof(root, PLUGIN_ID)
            factory.complete_smoke_status(
                root,
                PLUGIN_ID,
                beta_release_id=release_id,
                stable_sha=STABLE_SHA,
                delivery_id="first-smoke",
                smoke_run_url="https://github.com/tzf1003/xSecDesktop/actions/runs/700",
                marketplace_revision="c" * 40,
            )
            write_publication_proof(root, PLUGIN_ID)
            baseline = workspace / "trusted-first-outcome"
            shutil.copytree(root, baseline)
            first_status = factory.status_path(root, PLUGIN_ID).read_bytes()

            # A source-only Beta cycle may reproduce the same immutable
            # release. It still gets distinct Beta/Stable provenance and a
            # distinct KMS-bound smoke result.
            next_beta_sha = "d" * 40
            next_stable_sha = "e" * 40
            factory.record_beta(root, PLUGIN_ID, next_beta_sha, "test-publisher")
            factory.record_status(
                root,
                PLUGIN_ID,
                beta_sha=next_beta_sha,
                stable_sha=None,
                state="waiting_for_smoke",
                delivery_id="second-beta",
            )
            write_publication_proof(root, PLUGIN_ID, source_revision=next_beta_sha)
            factory.record_stable(root, PLUGIN_ID, next_stable_sha, release_id, "test-publisher")
            write_publication_proof(root, PLUGIN_ID, source_revision=next_stable_sha)
            factory.complete_smoke_status(
                root,
                PLUGIN_ID,
                beta_release_id=release_id,
                stable_sha=next_stable_sha,
                delivery_id="second-smoke",
                smoke_run_url="https://github.com/tzf1003/xSecDesktop/actions/runs/701",
                marketplace_revision="f" * 40,
            )
            write_publication_proof(root, PLUGIN_ID, source_revision=next_stable_sha)
            factory.validate_registry_and_snapshots(root, baseline_root=baseline)

            # Both smoke outcomes remain KMS-signed and valid, but the first
            # is not the current published result after the second was
            # appended. A normal PR cannot roll the readable sidecar back.
            factory.status_path(root, PLUGIN_ID).write_bytes(first_status)
            with self.assertRaisesRegex(
                factory.ExternalSourceFactoryError,
                "must retain its terminal published status unless an exact new Beta smoke cycle",
            ):
                factory.validate_registry_and_snapshots(root, baseline_root=baseline)

    def test_published_baseline_allows_a_distinct_beta_to_begin_its_next_smoke_cycle(self) -> None:
        """A terminal status protects its own tuple, not every future Beta."""

        with tempfile.TemporaryDirectory(prefix="xsec-factory-next-beta-") as directory:
            workspace = Path(directory)
            root = workspace / "current"
            source = self.make_source(root / "source")
            self.make_factory(root, self.registry_entry())
            initial_release = self.stage_and_record_beta(root, source)
            factory.record_status(
                root,
                PLUGIN_ID,
                beta_sha=BETA_SHA,
                stable_sha=None,
                state="waiting_for_smoke",
                delivery_id="initial-beta",
            )
            self.assertTrue(promote_release.promote_stable(root, PLUGIN_ID, initial_release))
            factory.record_stable(root, PLUGIN_ID, STABLE_SHA, initial_release, "test-publisher")
            write_publication_proof(root, PLUGIN_ID)
            factory.complete_smoke_status(
                root,
                PLUGIN_ID,
                beta_release_id=initial_release,
                stable_sha=STABLE_SHA,
                delivery_id="initial-smoke",
                smoke_run_url="https://github.com/tzf1003/xSecDesktop/actions/runs/400",
                marketplace_revision="c" * 40,
            )
            write_publication_proof(root, PLUGIN_ID)
            baseline = workspace / "trusted-terminal"
            shutil.copytree(root, baseline)

            # A status file is consumer-readable, not source provenance. A
            # normal PR cannot invent the next Beta cycle by changing only
            # this tuple while retaining the old signed evidence history.
            forged_status_path = factory.status_path(root, PLUGIN_ID)
            forged_status = json.loads(forged_status_path.read_text(encoding="utf-8"))
            forged_status["source"]["betaSha"] = "d" * 40
            forged_status["publication"]["state"] = "waiting_for_smoke"
            forged_status["publication"]["smokeRunUrl"] = None
            forged_status["publication"]["marketplaceRevision"] = None
            write_json(forged_status_path, forged_status)
            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "appended immutable provenance"):
                factory.validate_registry_and_snapshots(root, baseline_root=baseline)
            shutil.copy2(factory.status_path(baseline, PLUGIN_ID), forged_status_path)

            manifest_path = source / "package" / "plugin.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["version"] = "1.0.1"
            write_json(manifest_path, manifest)
            (source / "package" / "frontend.js").write_text(
                "export function activate() { return 'next-beta'; }\n",
                encoding="utf-8",
            )
            next_sha = "d" * 40
            next_release = self.stage_and_record_beta(root, source, source_sha=next_sha)
            self.assertNotEqual(next_release, initial_release)
            factory.record_status(
                root,
                PLUGIN_ID,
                beta_sha=next_sha,
                stable_sha=None,
                state="waiting_for_smoke",
                delivery_id="next-beta",
            )
            write_publication_proof(root, PLUGIN_ID, source_revision=next_sha)
            self.assertEqual(
                factory.needs_smoke_redispatch(
                    root,
                    PLUGIN_ID,
                    beta_sha=next_sha,
                    beta_release_id=next_release,
                ),
                {"redispatch": "true"},
            )
            self.assertEqual(
                factory.needs_smoke_redispatch(
                    root,
                    PLUGIN_ID,
                    beta_sha=BETA_SHA,
                    beta_release_id=next_release,
                ),
                {"redispatch": "false"},
            )
            self.assertEqual(
                factory.needs_smoke_redispatch(
                    root,
                    PLUGIN_ID,
                    beta_sha=next_sha,
                    beta_release_id=initial_release,
                ),
                {"redispatch": "false"},
            )
            # Workflow consumers parse redispatch as JSON. Preserve that
            # contract instead of accidentally accepting the CLI's default
            # human-readable key=value output.
            output = io.StringIO()
            with patch.object(
                sys,
                "argv",
                [
                    "external_source_factory.py",
                    "--root",
                    str(root),
                    "--json",
                    "needs-smoke-redispatch",
                    "--plugin-id",
                    PLUGIN_ID,
                    "--beta-sha",
                    next_sha,
                    "--beta-release-id",
                    next_release,
                ],
            ), redirect_stdout(output):
                factory.main()
            self.assertEqual(json.loads(output.getvalue()), {"redispatch": "true"})
            factory.validate_registry_and_snapshots(root, baseline_root=baseline)

    def test_first_party_beta_after_adoption_appends_history_without_rewriting_the_adopted_prefix(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-first-party-followup-beta-") as directory:
            root = Path(directory)
            old_release_id = self.make_first_party_adoption(root)
            plugin_id = "com.xsec.workspace.sub-agent"
            source = root / "source"
            shutil.copytree(snapshot_dir(root, plugin_id), source / "plugins" / plugin_id, ignore=shutil.ignore_patterns(".xsec-market"))
            source_manifest = source / "plugins" / plugin_id / "plugin.json"
            manifest = json.loads(source_manifest.read_text(encoding="utf-8"))
            manifest["version"] = "1.0.1"
            write_json(source_manifest, manifest)
            (source / "plugins" / plugin_id / "frontend.js").write_text("export function activate() { return 'next'; }\n", encoding="utf-8")

            factory.stage_beta(root, plugin_id, source)
            snapshot = snapshot_dir(root, plugin_id)
            build_market.build_plugin(snapshot, snapshot)
            factory.record_beta(root, plugin_id, "d" * 40, "test-publisher")
            write_historical_release_sidecar(root, plugin_id, source_revision="d" * 40)
            write_publication_proof(root, plugin_id, source_revision="d" * 40)
            factory.validate_registry_and_snapshots(root)

            releases = json.loads(factory.release_path(root, plugin_id).read_text(encoding="utf-8"))["releases"]
            self.assertEqual(releases[0]["releaseId"], old_release_id)
            self.assertEqual(len(releases), 2)

    def test_first_party_same_artifact_beta_sha_is_a_post_adoption_provenance_cycle(self) -> None:
        """A source-only change must not be hidden behind the adoption prefix."""

        with tempfile.TemporaryDirectory(prefix="xsec-first-party-same-artifact-beta-") as directory:
            workspace = Path(directory)
            root = workspace / "current"
            plugin_id = "com.xsec.workspace.sub-agent"
            release_id = self.make_first_party_adoption(root)

            # Complete one terminal cycle from the adopted artifact, so the
            # trusted baseline has a real KMS-bound publication history.
            factory.record_beta(root, plugin_id, BETA_SHA, "test-publisher")
            factory.record_status(
                root,
                plugin_id,
                beta_sha=BETA_SHA,
                stable_sha=None,
                state="waiting_for_smoke",
                delivery_id="adopted-beta",
            )
            self.assertTrue(promote_release.promote_stable(root, plugin_id, release_id))
            factory.record_stable(root, plugin_id, STABLE_SHA, release_id, "test-publisher")
            write_historical_release_sidecar(root, plugin_id)
            write_publication_proof(root, plugin_id)
            factory.complete_smoke_status(
                root,
                plugin_id,
                beta_release_id=release_id,
                stable_sha=STABLE_SHA,
                delivery_id="adopted-smoke",
                smoke_run_url="https://github.com/tzf1003/xSecDesktop/actions/runs/800",
                marketplace_revision="c" * 40,
            )
            write_publication_proof(root, plugin_id)
            factory.validate_registry_and_snapshots(root)
            baseline = workspace / "trusted-adopted-terminal"
            shutil.copytree(root, baseline)

            # A new source SHA may reproduce the exact adopted artifact (for
            # example an empty commit). It still gets a distinct immutable
            # Beta provenance event and must start a new smoke cycle.
            source = root / "source"
            shutil.copytree(
                snapshot_dir(root, plugin_id),
                source / "plugins" / plugin_id,
                ignore=shutil.ignore_patterns(".xsec-market"),
            )
            factory.stage_beta(root, plugin_id, source)
            snapshot = snapshot_dir(root, plugin_id)
            build_market.build_plugin(snapshot, snapshot)
            factory.record_beta(root, plugin_id, "d" * 40, "test-publisher")
            factory.record_status(
                root,
                plugin_id,
                beta_sha="d" * 40,
                stable_sha=None,
                state="waiting_for_smoke",
                delivery_id="same-artifact-beta",
            )
            write_publication_proof(root, plugin_id, source_revision="d" * 40)

            releases = json.loads(factory.release_path(root, plugin_id).read_text(encoding="utf-8"))["releases"]
            self.assertEqual([release["releaseId"] for release in releases], [release_id])
            self.assertTrue(factory.first_party_has_post_adoption_history(
                root,
                factory.registration_for(root, plugin_id),
                state_label="current Factory",
            ))
            factory.validate_registry_and_snapshots(root, baseline_root=baseline)

    def test_first_party_initial_in_flight_status_requires_exact_beta_provenance(self) -> None:
        """A first status file cannot manufacture an adopted plugin's Beta SHA."""

        with tempfile.TemporaryDirectory(prefix="xsec-first-party-in-flight-provenance-") as directory:
            root = Path(directory)
            plugin_id = "com.xsec.workspace.sub-agent"
            release_id = self.make_first_party_adoption(root)
            next_sha = "d" * 40
            factory.record_status(
                root,
                plugin_id,
                beta_sha=next_sha,
                stable_sha=None,
                state="waiting_for_smoke",
                delivery_id="forged-first-status",
            )
            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "in-flight Factory status must match immutable Beta provenance"):
                factory.validate_registry_and_snapshots(root)

            # The exact same status becomes valid only after a signed Beta
            # event for its current release/source tuple has been recorded.
            source = root / "source"
            shutil.copytree(
                snapshot_dir(root, plugin_id),
                source / "plugins" / plugin_id,
                ignore=shutil.ignore_patterns(".xsec-market"),
            )
            factory.stage_beta(root, plugin_id, source)
            snapshot = snapshot_dir(root, plugin_id)
            build_market.build_plugin(snapshot, snapshot)
            factory.record_beta(root, plugin_id, next_sha, "test-publisher")
            write_publication_proof(root, plugin_id, source_revision=next_sha)
            self.assertEqual(
                json.loads(factory.release_path(root, plugin_id).read_text(encoding="utf-8"))["channels"]["beta"]["releaseId"],
                release_id,
            )
            factory.validate_registry_and_snapshots(root)

    def test_first_party_post_adoption_evidence_is_required_and_append_only(self) -> None:
        """Adoption cannot be used to erase source provenance for newer releases."""

        with tempfile.TemporaryDirectory(prefix="xsec-first-party-followup-evidence-") as directory:
            workspace = Path(directory)
            root = workspace / "current"
            self.make_first_party_adoption(root)
            plugin_id = "com.xsec.workspace.sub-agent"
            source = root / "source"
            shutil.copytree(snapshot_dir(root, plugin_id), source / "plugins" / plugin_id, ignore=shutil.ignore_patterns(".xsec-market"))
            manifest_path = source / "plugins" / plugin_id / "plugin.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["version"] = "1.0.1"
            write_json(manifest_path, manifest)
            (source / "plugins" / plugin_id / "frontend.js").write_text(
                "export function activate() { return 'post-adoption'; }\n",
                encoding="utf-8",
            )

            factory.stage_beta(root, plugin_id, source)
            snapshot = snapshot_dir(root, plugin_id)
            build_market.build_plugin(snapshot, snapshot)
            factory.record_beta(root, plugin_id, "d" * 40, "test-publisher")
            write_historical_release_sidecar(root, plugin_id, source_revision="d" * 40)
            write_publication_proof(root, plugin_id, source_revision="d" * 40)
            factory.validate_registry_and_snapshots(root)

            baseline = workspace / "trusted-baseline"
            shutil.copytree(root, baseline)
            evidence_path = factory.publication_path(root, plugin_id)
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            evidence["events"][0]["publisher"] = "rewritten-publisher"
            write_json(evidence_path, evidence)
            with self.assertRaisesRegex(
                factory.ExternalSourceFactoryError,
                "must retain every immutable publication evidence event",
            ):
                factory.validate_registry_and_snapshots(root, baseline_root=baseline, require_publication_proofs=False)

            shutil.copy2(factory.publication_path(baseline, plugin_id), evidence_path)
            proof_document = factory.official_publication_provenance_document(root, plugin_id)
            publisher.sidecar_path_for(proof_document).unlink()
            evidence_path.unlink()
            with self.assertRaisesRegex(
                factory.ExternalSourceFactoryError,
                "must retain publication evidence after its adopted release history",
            ):
                factory.validate_registry_and_snapshots(root)

    def test_reconcile_payload_requires_the_current_registry_binding(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-reconcile-payload-") as directory:
            root = Path(directory)
            self.make_factory(root, self.registry_entry())
            accepted = factory.prepare_reconcile_source(
                root,
                delivery_key="delivery-42",
                plugin_id=PLUGIN_ID,
                source_repository="acme/external-plugin",
                source_ref="refs/heads/beta",
                source_sha=BETA_SHA,
            )
            self.assertEqual(accepted["channel"], "beta")
            self.assertEqual(accepted["beta_ref"], "refs/heads/beta")
            self.assertEqual(accepted["stable_ref"], "refs/heads/main")
            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "does not match a registered beta or stable branch"):
                factory.prepare_reconcile_source(
                    root,
                    delivery_key="delivery-43",
                    plugin_id=PLUGIN_ID,
                    source_repository="acme/external-plugin",
                    source_ref="refs/heads/old-beta",
                    source_sha=BETA_SHA,
                )
            with self.assertRaisesRegex(factory.ExternalSourceFactoryError, "workflow run identity is invalid"):
                factory.prepare_reconcile_smoke(
                    delivery_key="delivery-44",
                    marketplace_revision=BETA_SHA,
                    channel="beta",
                    smoke_workflow_run_id="not-a-run",
                    smoke_workflow_run_attempt="1",
                )

    def test_reconcile_workflows_fail_closed_on_actor_payload_and_stale_source_heads(self) -> None:
        source_workflow = (ROOT / ".github" / "workflows" / "reconcile-source.yml").read_text(encoding="utf-8")
        smoke_workflow = (ROOT / ".github" / "workflows" / "reconcile-smoke.yml").read_text(encoding="utf-8")
        # xsec-cloud has Actions-dispatch-only authority. It calls exactly this
        # workflow with the full string contract, and only this entrypoint
        # verifies the Dispatcher App actor and protected Factory main before
        # it can route a smoke callback into the reusable workflow.
        self.assertIn("workflow_dispatch:", source_workflow)
        self.assertNotIn("repository_dispatch:", source_workflow)
        self.assertIn("XSEC_FACTORY_DISPATCHER_ACTOR", source_workflow)
        self.assertIn("ACTOR: ${{ github.actor }}", source_workflow)
        self.assertIn('[ "$ACTOR" = "$EXPECTED_ACTOR" ]', source_workflow)
        self.assertIn('[ "$REF" = "refs/heads/main" ] && [ "$REF_PROTECTED" = "true" ]', source_workflow)
        self.assertIn("github.ref_protected", source_workflow)
        self.assertIn("uses: ./.github/workflows/reconcile-smoke.yml", source_workflow)
        for input_name in (
            "trigger_kind",
            "delivery_key",
            "plugin_id",
            "source_repository",
            "source_ref",
            "source_sha",
            "marketplace_revision",
            "channel",
            "smoke_workflow_run_id",
            "smoke_workflow_run_attempt",
        ):
            self.assertIn(f"{input_name}:", source_workflow)
            self.assertIn(f"inputs.{input_name}", source_workflow)
        self.assertIn("workflow_call:", smoke_workflow)
        self.assertNotIn("repository_dispatch:", smoke_workflow)
        self.assertNotIn("XSEC_FACTORY_DISPATCHER_ACTOR", smoke_workflow)
        self.assertIn("prepare-reconcile-source", source_workflow)
        self.assertIn("ls-remote", source_workflow)
        self.assertIn("Source delivery is stale", source_workflow)
        self.assertIn("publish.yml", source_workflow)
        # A registered-main recheck must not strand an already accepted Beta
        # behind its now-stale generated PR. The Dispatcher may close only a
        # cryptographically authenticated candidate for the same Registry
        # source/Beta tuple, then requests a fresh review-required candidate.
        for rule in (
            "pull-requests: write",
            "Controlled supersede of an obsolete same-plugin Beta candidate",
            "^xsec-marketplace/external-beta-[0-9]+-[0-9]+$",
            "candidate Registry entry is ambiguous",
            "candidate lacks exact Beta provenance",
            "--verify-active-marketplace-signatures",
            "KMS generation revision is not retained by protected Factory main",
            "does not descend from its KMS generation revision",
            "does not authenticate one generated plugin",
            "candidate_beta_sha",
            "issues/${number}/comments",
            '"repos/${GITHUB_REPOSITORY}/pulls/${number}"',
            "Controlled supersede: trusted dispatcher delivery ${DELIVERY_KEY}",
            "steps.supersede.outputs.dispatch == 'true'",
        ):
            with self.subTest(controlled_supersede_rule=rule):
                self.assertIn(rule, source_workflow)
        self.assertNotIn("gh pr merge", source_workflow)
        self.assertIn("prepare-reconcile-smoke", smoke_workflow)
        self.assertIn("merge-base --is-ancestor", smoke_workflow)
        self.assertIn("release_id=\"$current_beta\"", smoke_workflow)
        self.assertIn('[ "$smoke_status_state" = "waiting_for_smoke" ]', smoke_workflow)
        self.assertIn('[ "$current_status_state" = "waiting_for_smoke" ]', smoke_workflow)
        self.assertIn("SOURCE_BETA_REF: ${{ steps.request.outputs.beta_ref }}", source_workflow)
        self.assertIn("waiting_for_beta", source_workflow)
        publisher_workflow = (ROOT / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")
        self.assertIn("Record immutable external Stable provenance after verification", publisher_workflow)
        self.assertIn(
            "if: ${{ steps.request.outputs.external == 'true' && steps.request.outputs.channel == 'stable' }}",
            publisher_workflow,
        )
        self.assertNotIn("steps.external-stable.outputs.changed == 'true'", publisher_workflow)
        self.assertIn("duplicate source delivery", publisher_workflow)
        self.assertIn("git status --porcelain --untracked-files=all -- .agents/plugins .xsec-factory", publisher_workflow)
        self.assertIn("Record Factory Beta state", publisher_workflow)
        self.assertIn("check-main-rebuild", publisher_workflow)
        self.assertIn("SOURCE_STABLE_REF: ${{ steps.external-request.outputs.stable_ref }}", publisher_workflow)
        self.assertIn("refs/remotes/xsec-factory-source/registered-main", publisher_workflow)
        self.assertIn('main_gate_sha="$(git -C .xsec-factory-source rev-parse refs/remotes/xsec-factory-source/registered-main)"', publisher_workflow)
        self.assertIn("MAIN_GATE_SHA: ${{ steps.main-gate.outputs.main_gate_sha }}", publisher_workflow)
        self.assertIn('--main-gate-sha "$MAIN_GATE_SHA"', publisher_workflow)
        self.assertIn("Stable source does not yet deterministically rebuild Beta", (ROOT / ".github" / "workflows" / "dispatch-reviewed-marketplace-smoke.yml").read_text(encoding="utf-8"))
        self.assertIn("waiting_for_beta", (ROOT / ".github" / "workflows" / "dispatch-reviewed-marketplace-smoke.yml").read_text(encoding="utf-8"))
        self.assertIn("Factory status is not bound to the validated Beta source/release tuple", (ROOT / ".github" / "workflows" / "dispatch-reviewed-marketplace-smoke.yml").read_text(encoding="utf-8"))
        self.assertIn("complete-smoke-status", publisher_workflow)
        self.assertIn("--stable-sha \"$SOURCE_SHA\"", publisher_workflow)
        self.assertIn("expected_beta_sha", publisher_workflow)
        self.assertIn("already-published identical outcome idempotent", publisher_workflow)
        self.assertIn("does not match the current Beta pointer", (ROOT / "scripts" / "external_source_factory.py").read_text(encoding="utf-8"))
        self.assertIn("smoke_beta_sha", smoke_workflow)
        self.assertIn("smoke_marketplace_revision", publisher_workflow)
        self.assertIn("smoke_run_url", publisher_workflow)
        self.assertIn("still heads its registered branch", publisher_workflow)
        self.assertIn('verified_head="$(git -C .xsec-factory-source rev-parse refs/remotes/xsec-factory-source/verified)"', publisher_workflow)
        self.assertIn('[ "$verified_head" = "$SOURCE_SHA" ]', publisher_workflow)
        self.assertIn("no longer heads its registered branch", publisher_workflow)
        self.assertIn("smoke_marketplace_revision", smoke_workflow)
        self.assertIn("xSecDesktop/actions/runs/${SMOKE_RUN_ID}", smoke_workflow)
        adoption_workflow = (ROOT / ".github" / "workflows" / "adopt-first-party.yml").read_text(encoding="utf-8")
        self.assertIn("prepare-staged-adoption", adoption_workflow)
        self.assertNotIn("beta_sha:", adoption_workflow)
        self.assertNotIn("stable_sha:", adoption_workflow)
        self.assertIn("adopt-first-party", adoption_workflow)
        self.assertIn("activate-first-party", adoption_workflow)
        self.assertIn("XSEC_MARKETPLACE_SOURCE_REVISION", adoption_workflow)
        self.assertIn("--baseline-root \"$baseline_root\"", adoption_workflow)
        self.assertIn("--factory-revision \"$baseline_revision\"", adoption_workflow)
        self.assertIn("git worktree add --detach", adoption_workflow)
        self.assertNotIn("coderabbit", adoption_workflow.lower())
        self.assertNotIn('"repos/${GITHUB_REPOSITORY}/pulls/${pull_number}/merge"', adoption_workflow)


if __name__ == "__main__":
    unittest.main()
