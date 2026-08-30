from __future__ import annotations

import unittest
import sys
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from verify_factory_layout_migration import expected_snapshot_index, plugin_ids


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
        self.assertIn("MIGRATION_SUPPORT_PLAN", verifier)
        self.assertIn("verify_support_hashes", verifier)
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

if __name__ == "__main__":
    unittest.main()
