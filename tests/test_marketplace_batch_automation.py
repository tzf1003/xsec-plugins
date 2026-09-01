"""Static contracts for the single-PR first-party source batch."""

from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BATCH_RECONCILE = ROOT / ".github" / "workflows" / "reconcile-marketplace-batch.yml"
BATCH_PUBLISH = ROOT / ".github" / "workflows" / "publish-marketplace-batch.yml"
AUTO_FINALIZER = ROOT / ".github" / "workflows" / "auto-finalize-generated-marketplace-pr.yml"
FINALIZER = ROOT / ".github" / "workflows" / "final-merge-generated-marketplace-pr.yml"


class MarketplaceBatchAutomationTests(unittest.TestCase):
    def test_active_registry_excludes_host_owned_project_management(self) -> None:
        registry = json.loads((ROOT / ".xsec-factory" / "official-registry.json").read_text(encoding="utf-8"))
        marketplace = json.loads((ROOT / ".agents" / "plugins" / "marketplace.json").read_text(encoding="utf-8"))
        statuses = {entry["pluginId"]: entry["status"] for entry in registry["plugins"]}
        active = [plugin_id for plugin_id, status in statuses.items() if status == "active"]
        market_ids = {entry["name"] for entry in marketplace["plugins"]}

        self.assertEqual(len([plugin_id for plugin_id in active if plugin_id != "com.xsec.project-workspace"]), 10)
        self.assertEqual(statuses["com.xsec.project-workspace"], "active")
        self.assertIn("com.xsec.project-workspace", market_ids)
        withdrawal = (ROOT / ".github" / "workflows" / "disable-host-owned-project-workspace.yml").read_text(encoding="utf-8")
        self.assertIn('.status = "disabled"', withdrawal)
        self.assertIn("--marketplace-index", withdrawal)

    def test_source_events_coalesce_before_building_one_complete_candidate(self) -> None:
        workflow = BATCH_RECONCILE.read_text(encoding="utf-8")
        publisher = BATCH_PUBLISH.read_text(encoding="utf-8")
        for rule in (
            "group: xsec-marketplace-source-batch",
            "Only the Cloud dispatcher App may reconcile Marketplace sources.",
            "prepare-reconcile-source",
            "uses: ./.github/workflows/publish-marketplace-batch.yml",
        ):
            with self.subTest(rule=rule):
                self.assertIn(rule, workflow)
        for rule in (
            "length == 10",
            "xsec-marketplace-publish-main",
            "permission-contents: read",
            "permission-checks: read",
            "python scripts/build_market.py --clean",
            "python scripts/kms_marketplace_publisher.py --root .",
            'branch="xsec-marketplace/batch-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"',
        ):
            with self.subTest(rule=rule):
                self.assertIn(rule, publisher)

    def test_only_successful_exact_generated_prs_enter_the_automatic_finalizer(self) -> None:
        workflow = AUTO_FINALIZER.read_text(encoding="utf-8")
        finalizer = FINALIZER.read_text(encoding="utf-8")
        for branch in (
            "xsec-marketplace/batch-*",
            "xsec-marketplace/external-beta-*",
            "xsec-marketplace/external-stable-*",
        ):
            self.assertIn(branch, workflow)
        self.assertIn("github.event.workflow_run.conclusion == 'success'", workflow)
        self.assertIn("expected one open exact-head generated PR", workflow)
        self.assertIn("workflow_call:", finalizer)
        self.assertIn("xsec-marketplace/batch-*", finalizer)


if __name__ == "__main__":
    unittest.main()
