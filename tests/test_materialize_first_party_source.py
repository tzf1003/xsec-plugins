import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import build_market  # noqa: E402
import materialize_first_party_source as materializer  # noqa: E402


PLUGIN_ID = "com.xsec.workspace.sub-agent"


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=str(root),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    return completed.stdout.decode("utf-8").strip()


class FirstPartySourceMaterializerTests(unittest.TestCase):
    maxDiff = None

    def setUp(self) -> None:
        verifier = patch.object(materializer, "verify_historical_sidecar_signature", return_value="a" * 40)
        verifier.start()
        self.addCleanup(verifier.stop)

    def manifest(self, version: str) -> dict[str, object]:
        return {
            "name": PLUGIN_ID,
            "version": version,
            "extensions": {
                "com.xsec.desktop": {
                    "engines": {"xsec": ">=1", "pluginApi": "^1"},
                    "entrypoints": {"frontend": "frontend.js"},
                }
            },
        }

    def archive(self, path: Path, version: str, *, traversal: bool = False) -> dict[str, object]:
        path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("plugin.json", json.dumps(self.manifest(version), separators=(",", ":")))
            archive.writestr(
                ".codex-plugin/plugin.json",
                json.dumps({"name": PLUGIN_ID, "version": version}, separators=(",", ":")),
            )
            archive.writestr("frontend.js", f"export function activate() {{ return '{version}'; }}\n")
            if traversal:
                archive.writestr("../escape.txt", "not allowed")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        artifact = {"os": "any", "arch": "any", "url": f"artifacts/{path.name}", "sha256": digest}
        return {
            "releaseId": build_market.release_id(version, {"xsec": ">=1", "pluginApi": "^1"}, [artifact]),
            "version": version,
            "engines": {"xsec": ">=1", "pluginApi": "^1"},
            "artifacts": [artifact],
        }

    def make_factory(self, root: Path, *, traversal: bool = False) -> tuple[dict[str, object], dict[str, object]]:
        plugin = root / "plugins" / PLUGIN_ID
        artifacts = plugin / ".xsec-market" / "artifacts"
        stable = self.archive(artifacts / "stable.xsec-plugin", "1.0.0")
        beta = self.archive(artifacts / "beta.xsec-plugin", "1.1.0", traversal=traversal)
        write_json(
            plugin / ".xsec-market" / "releases.json",
            {
                "schemaVersion": 2,
                "pluginId": PLUGIN_ID,
                "releases": [stable, beta],
                "channels": {
                    "beta": {"releaseId": beta["releaseId"]},
                    "stable": {"releaseId": stable["releaseId"]},
                },
            },
        )
        (plugin / ".xsec-market" / "releases.json.sig.jws.json").write_text("test-sidecar", encoding="utf-8")
        write_json(plugin / "plugin.json", self.manifest("1.1.0"))
        write_json(plugin / ".codex-plugin" / "plugin.json", {"name": PLUGIN_ID, "version": "1.1.0"})
        (plugin / "frontend.js").write_text("export function activate() {}\n", encoding="utf-8")
        # The history intentionally includes the Factory-only files that the
        # materializer must permanently remove before creating source branches.
        (plugin / ".xsec-market" / "old.sig.jws.json").write_text("signature", encoding="utf-8")
        (plugin / "legacy.xsec-plugin").write_text("artifact", encoding="utf-8")
        write_json(
            root / ".agents" / "plugins" / "marketplace.json",
            {
                "name": "xsec-official",
                "interface": {"displayName": "Test"},
                "plugins": [
                    {
                        "name": PLUGIN_ID,
                        "source": {"source": "local", "path": f"./plugins/{PLUGIN_ID}"},
                        "policy": {"installation": "INSTALLED_BY_DEFAULT", "authentication": "ON_INSTALL"},
                        "category": "Security",
                    }
                ],
            },
        )
        git(root, "init", "--quiet", "--initial-branch=main")
        git(root, "config", "user.name", "Factory Test")
        git(root, "config", "user.email", "factory-test@example.invalid")
        git(root, "remote", "add", "origin", materializer.TRUSTED_FACTORY_ORIGIN)
        git(root, "add", "--all")
        git(root, "commit", "--quiet", "-m", "feat: retain plugin source history")
        git(root, "update-ref", "refs/remotes/origin/main", "HEAD")
        return stable, beta

    def test_materializes_exact_stable_and_beta_source_branches_with_filtered_history(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-materializer-") as directory:
            factory = Path(directory) / "factory"
            factory.mkdir()
            self.make_factory(factory)
            output = Path(directory) / "source-repository"

            result = materializer.materialize_repository(factory, PLUGIN_ID, output)

            stable_manifest = json.loads(git(output, "show", f"main:plugins/{PLUGIN_ID}/plugin.json"))
            beta_manifest = json.loads(git(output, "show", f"beta:plugins/{PLUGIN_ID}/plugin.json"))
            self.assertEqual(stable_manifest["version"], "1.0.0")
            self.assertEqual(beta_manifest["version"], "1.1.0")
            self.assertEqual(git(output, "show", "main:README.md").splitlines()[0], f"# {PLUGIN_ID}")
            self.assertIn("plugins/com.xsec.workspace.sub-agent/plugin.json", git(output, "ls-tree", "-r", "--name-only", "beta"))
            history = git(output, "log", "--format=%s", "--all")
            self.assertIn("feat: retain plugin source history", history)
            source_paths = git(output, "rev-list", "--objects", "--all")
            self.assertNotIn(".xsec-market", source_paths)
            self.assertNotIn(".xsec-plugin", source_paths)
            self.assertNotIn(".sig.jws.json", source_paths)
            self.assertEqual(set(result), {"sourceCommits", "pendingAdoptionRegistry"})
            self.assertEqual(result["pendingAdoptionRegistry"]["status"], "pending-adoption")
            self.assertEqual(result["pendingAdoptionRegistry"]["source"]["repository"], "tzf1003/xsec-plugin-sub-agent")
            self.assertRegex(result["sourceCommits"]["stable"], r"^[a-f0-9]{40}$")

    def test_cli_dry_run_prints_only_commits_and_pending_registry(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-materializer-cli-") as directory:
            factory = Path(directory) / "factory"
            factory.mkdir()
            self.make_factory(factory)
            output = StringIO()
            errors = StringIO()
            with patch.object(sys, "argv", [str(SCRIPTS / "materialize_first_party_source.py"), "--root", str(factory), "--plugin-id", PLUGIN_ID]), redirect_stdout(output), redirect_stderr(errors):
                self.assertEqual(materializer.main(), 0)
            result = json.loads(output.getvalue())
            self.assertEqual(set(result), {"sourceCommits", "pendingAdoptionRegistry"})
            self.assertEqual(result["pendingAdoptionRegistry"]["status"], "pending-adoption")
            self.assertEqual(errors.getvalue(), "")

    def test_rejects_unsafe_artifact_member_before_extracting_source(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-materializer-traversal-") as directory:
            factory = Path(directory) / "factory"
            factory.mkdir()
            self.make_factory(factory, traversal=True)
            output = Path(directory) / "source-repository"

            with self.assertRaisesRegex(materializer.MaterializationError, "not safely extractable"):
                materializer.materialize_repository(factory, PLUGIN_ID, output)
            self.assertFalse((Path(directory) / "escape.txt").exists())
            self.assertFalse(output.exists())

    def test_push_target_is_closed_to_the_exact_first_party_mapping(self) -> None:
        expected = "https://github.com/tzf1003/xsec-plugin-sub-agent.git"
        self.assertEqual(len(materializer.FIRST_PARTY_APPROVED_SOURCES), 11)
        self.assertEqual(materializer.require_exact_target(PLUGIN_ID, expected), expected)
        with self.assertRaisesRegex(materializer.MaterializationError, "exact approved public GitHub repository"):
            materializer.require_exact_target(PLUGIN_ID, "https://github.com/tzf1003/xsec-plugin-approvals.git")
        script = (SCRIPTS / "materialize_first_party_source.py").read_text(encoding="utf-8")
        self.assertIn('"--atomic"', script)

    def test_rejects_an_artifact_that_no_longer_matches_the_retained_sha256(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-materializer-digest-") as directory:
            factory = Path(directory) / "factory"
            factory.mkdir()
            _, beta = self.make_factory(factory)
            artifact = factory / "plugins" / PLUGIN_ID / ".xsec-market" / beta["artifacts"][0]["url"]
            artifact.write_bytes(artifact.read_bytes() + b"changed")

            with self.assertRaisesRegex(materializer.MaterializationError, "SHA-256 does not match"):
                materializer.selected_release_artifact(factory, PLUGIN_ID, "beta")

    def test_filter_index_removes_factory_only_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-materializer-index-") as directory:
            root = Path(directory)
            plugin = root / "plugins" / PLUGIN_ID
            (plugin / ".xsec-market").mkdir(parents=True)
            (plugin / ".xsec-market" / "release.sig.jws.json").write_text("signature", encoding="utf-8")
            (plugin / "old.xsec-plugin").write_text("artifact", encoding="utf-8")
            (plugin / "frontend.js").write_text("source", encoding="utf-8")
            git(root, "init", "--quiet", "--initial-branch=main")
            git(root, "config", "user.name", "Factory Test")
            git(root, "config", "user.email", "factory-test@example.invalid")
            git(root, "add", "--all")
            git(root, "commit", "--quiet", "-m", "test")
            previous = Path.cwd()
            os.chdir(root)
            try:
                materializer.filter_index_paths(PLUGIN_ID)
            finally:
                os.chdir(previous)
            self.assertEqual(git(root, "ls-files"), f"plugins/{PLUGIN_ID}/frontend.js")

    def test_rejects_dirty_or_non_main_factory_input_before_reading_release_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-materializer-trusted-main-") as directory:
            factory = Path(directory) / "factory"
            factory.mkdir()
            self.make_factory(factory)
            (factory / "untrusted.txt").write_text("dirty", encoding="utf-8")
            with self.assertRaisesRegex(materializer.MaterializationError, "clean trusted Factory main"):
                materializer.materialize_repository(factory, PLUGIN_ID, Path(directory) / "source-repository")
            (factory / "untrusted.txt").unlink()
            git(factory, "checkout", "--quiet", "-b", "untrusted")
            (factory / "untrusted.txt").write_text("different commit", encoding="utf-8")
            git(factory, "add", "untrusted.txt")
            git(factory, "commit", "--quiet", "-m", "untrusted local main lookalike")
            with self.assertRaisesRegex(materializer.MaterializationError, "trusted Factory main commit"):
                materializer.materialize_repository(factory, PLUGIN_ID, Path(directory) / "source-repository")

    def test_rejects_a_clean_clone_with_an_untrusted_factory_origin(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-materializer-untrusted-origin-") as directory:
            factory = Path(directory) / "factory"
            factory.mkdir()
            self.make_factory(factory)
            git(factory, "remote", "set-url", "origin", "https://github.com/attacker/xsec-plugins.git")
            with self.assertRaisesRegex(materializer.MaterializationError, "canonical trusted xsec-plugins"):
                materializer.materialize_repository(factory, PLUGIN_ID, Path(directory) / "source-repository")

    def test_rejects_a_retained_release_index_without_a_valid_kms_sidecar(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-materializer-unverified-release-") as directory:
            factory = Path(directory) / "factory"
            factory.mkdir()
            self.make_factory(factory)
            with patch.object(
                materializer,
                "verify_historical_sidecar_signature",
                side_effect=materializer.MarketplaceKmsPublisherError("signature mismatch"),
            ):
                with self.assertRaisesRegex(materializer.MaterializationError, "retained release KMS sidecar is invalid"):
                    materializer.materialize_repository(factory, PLUGIN_ID, Path(directory) / "source-repository")


if __name__ == "__main__":
    unittest.main()
