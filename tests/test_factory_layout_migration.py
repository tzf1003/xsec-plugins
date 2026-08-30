from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path, PurePosixPath
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from verify_factory_layout_migration import (
    FactoryLayoutMigrationError,
    MIGRATION_SUPPORT_PATHS,
    expected_snapshot_index,
    plugin_ids,
    verify_transition_paths,
)


PLUGIN_ID = "com.example.sample"


def git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments], cwd=str(root), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True
    )
    return completed.stdout.decode("utf-8").strip()


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def commit(root: Path, message: str) -> str:
    git(root, "add", "--all")
    git(root, "commit", "--quiet", "-m", message)
    return git(root, "rev-parse", "HEAD")


def write_layout_transition(root: Path) -> None:
    write_json(
        root / ".agents/plugins/marketplace.json",
        {
            "name": "XSEC",
            "plugins": [
                {
                    "name": PLUGIN_ID,
                    "source": {"source": "local", "path": f"./.xsec-factory/snapshots/{PLUGIN_ID}"},
                }
            ],
        },
    )
    write_json(
        root / ".xsec-factory/layout-migration.json",
        {
            "schemaVersion": 1,
            "layout": "git-subprojects-with-release-snapshots",
            "pendingKmsSidecars": True,
        },
    )
    snapshot = root / f".xsec-factory/snapshots/{PLUGIN_ID}/plugin.json"
    snapshot.parent.mkdir(parents=True, exist_ok=True)
    snapshot.write_text('{"name": "sample"}\n', encoding="utf-8")
    sidecar = root / ".agents/plugins/marketplace.json.sig.jws.json"
    if sidecar.exists():
        sidecar.unlink()


class FactoryLayoutMigrationTests(unittest.TestCase):
    def test_rewrites_only_marketplace_source_paths(self) -> None:
        baseline = {
            "name": "XSEC",
            "plugins": [
                {
                    "name": "com.example.sample",
                    "source": {"source": "local", "path": "./plugins/com.example.sample"},
                }
            ],
        }

        migrated = expected_snapshot_index(baseline)

        self.assertEqual(
            plugin_ids(migrated, PurePosixPath(".xsec-factory/snapshots")),
            ("com.example.sample",),
        )
        self.assertEqual(
            migrated["plugins"][0]["source"]["path"],
            "./.xsec-factory/snapshots/com.example.sample",
        )
        self.assertEqual(baseline["plugins"][0]["source"]["path"], "./plugins/com.example.sample")

    def test_protected_workflow_re_signs_only_after_the_pending_marker(self) -> None:
        workflow = (ROOT / ".github/workflows/migrate-factory-layout-sidecars.yml").read_text(encoding="utf-8")

        self.assertIn("environment: production", workflow)
        self.assertIn("--exclude-official-status", workflow)
        self.assertIn("layout-migration.json", workflow)
        self.assertIn("xsec-marketplace/layout-signatures-", workflow)
        self.assertIn("PYTHONPATH=scripts python -", workflow)

    def test_final_gate_keeps_layout_signature_candidates_pending_until_revalidated(self) -> None:
        arm = (ROOT / ".github/workflows/arm-generated-marketplace-final-merge.yml").read_text(encoding="utf-8")
        final = (ROOT / ".github/workflows/final-merge-generated-marketplace-pr.yml").read_text(encoding="utf-8")
        verifier = (ROOT / "scripts/verify_factory_layout_migration.py").read_text(encoding="utf-8")

        self.assertIn("xsec-marketplace/layout-signatures-", arm)
        self.assertIn("xsec-marketplace/layout-signatures-*", final)
        self.assertIn('layout_migration="$(printf', arm)
        self.assertIn('if [ "$layout_migration" = "true" ] ||', arm)
        self.assertIn('echo "factory_generated=true"', arm)
        self.assertIn('if [ -e "$CANDIDATE/.xsec-factory/layout-migration.json" ]; then', final)
        self.assertIn('verify_factory_layout_migration.py --root "$CANDIDATE" --baseline-root . --before "$BEFORE" --after "$AFTER"', final)
        self.assertIn("MIGRATION_SUPPORT_PATHS", verifier)
        self.assertIn('"diff", "--name-only", "--no-renames", before, after', verifier)
        self.assertIn("Factory layout sidecars are not bound", final)
        self.assertIn("--verify-active-marketplace-signatures", final)

    def test_source_freshness_gate_skips_only_the_pending_layout_marker(self) -> None:
        workflow = (ROOT / ".github/workflows/verify-generated-marketplace-publication.yml").read_text(encoding="utf-8")

        self.assertEqual(workflow.count("Pending Factory layout migration has no source-freshness proof."), 2)
        self.assertIn(".xsec-factory/layout-migration.json", workflow)

    def test_pending_layout_marker_blocks_desktop_smoke_dispatch(self) -> None:
        workflow = (ROOT / ".github/workflows/dispatch-reviewed-marketplace-smoke.yml").read_text(encoding="utf-8")

        self.assertIn("Pending Factory layout migration cannot dispatch Desktop smoke.", workflow)
        self.assertIn('echo "eligible=false" >> "$GITHUB_OUTPUT"', workflow)

    def test_layout_support_paths_exclude_privileged_workflows_and_scripts(self) -> None:
        privileged = [path for path in MIGRATION_SUPPORT_PATHS if path.startswith((".github/", "scripts/", "factory-template/"))]
        self.assertEqual(privileged, [])

    def _baseline_repository(self, root: Path) -> str:
        write_json(
            root / ".agents/plugins/marketplace.json",
            {
                "name": "XSEC",
                "plugins": [
                    {
                        "name": PLUGIN_ID,
                        "source": {"source": "local", "path": f"./plugins/{PLUGIN_ID}"},
                    }
                ],
            },
        )
        (root / ".agents/plugins/marketplace.json.sig.jws.json").write_text("{}\n", encoding="utf-8")
        plugin = root / f"plugins/{PLUGIN_ID}/plugin.json"
        plugin.parent.mkdir(parents=True, exist_ok=True)
        plugin.write_text('{"name": "sample"}\n', encoding="utf-8")
        git(root, "init", "--quiet", "--initial-branch=main")
        git(root, "config", "user.name", "Layout Test")
        git(root, "config", "user.email", "layout@example.invalid")
        return commit(root, "baseline factory layout")

    def test_layout_migration_rejects_an_unrelated_workflow_edit(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-layout-extra-") as directory:
            root = Path(directory)
            before = self._baseline_repository(root)
            write_layout_transition(root)
            workflow = root / ".github/workflows/publish.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text("name: backdoor\n", encoding="utf-8")
            after = commit(root, "layout migration plus privileged workflow")
            baseline = Path(directory) / "baseline"
            git(root, "worktree", "add", "--detach", str(baseline), before)

            with self.assertRaisesRegex(FactoryLayoutMigrationError, "未授权路径"):
                verify_transition_paths(root, baseline, (PLUGIN_ID,), before, after)

    def test_layout_migration_allows_only_the_layout_transition_paths(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-layout-exact-") as directory:
            root = Path(directory)
            before = self._baseline_repository(root)
            write_layout_transition(root)
            after = commit(root, "exact layout migration")
            baseline = Path(directory) / "baseline"
            git(root, "worktree", "add", "--detach", str(baseline), before)

            verify_transition_paths(root, baseline, (PLUGIN_ID,), before, after)


if __name__ == "__main__":
    unittest.main()
