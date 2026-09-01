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
SOURCE_PREFLIGHT = ROOT / ".github" / "workflows" / "first-party-source-preflight.yml"


class MarketplaceBatchAutomationTests(unittest.TestCase):
    def test_default_set_maintenance_is_automatic_and_source_batch_stays_ten_plugins(self) -> None:
        registry = json.loads((ROOT / ".xsec-factory" / "official-registry.json").read_text(encoding="utf-8"))
        marketplace = json.loads((ROOT / ".agents" / "plugins" / "marketplace.json").read_text(encoding="utf-8"))
        statuses = {entry["pluginId"]: entry["status"] for entry in registry["plugins"]}
        active = [plugin_id for plugin_id, status in statuses.items() if status == "active"]
        market_ids = {entry["name"] for entry in marketplace["plugins"]}

        self.assertEqual(len(active), 10)
        self.assertEqual(statuses["com.xsec.project-workspace"], "disabled")
        self.assertNotIn("com.xsec.project-workspace", market_ids)
        publish = (ROOT / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")
        self.assertFalse((ROOT / ".github" / "workflows" / "disable-host-owned-project-workspace.yml").exists())
        self.assertIn("push:\n    branches: [main]", publish)
        self.assertIn('[ "$EVENT_NAME" = "push" ]', publish)
        self.assertIn("maintenance=align_desktop_defaults", publish)
        self.assertIn("xsec-marketplace/default-set-", publish)

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
            "git status --porcelain --untracked-files=all",
            'source_revision="$(git rev-parse HEAD)"',
            '"$(git rev-parse origin/main)"',
            "XSEC_MARKETPLACE_SOURCE_REVISION: ${{ steps.current-main.outputs.source_revision }}",
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
            "xsec-marketplace/default-set-*",
            "xsec-marketplace/external-beta-*",
            "xsec-marketplace/external-stable-*",
        ):
            self.assertIn(branch, workflow)
        self.assertIn("github.event.workflow_run.conclusion == 'success'", workflow)
        self.assertIn("startsWith(github.event.workflow_run.head_branch, 'xsec-marketplace/batch-')", workflow)
        self.assertIn("needs.select-exact-generated-pr.result == 'success'", workflow)
        self.assertIn("expected one open exact-head generated PR", workflow)
        self.assertIn("workflow_call:", finalizer)
        self.assertIn("workflow_dispatch|workflow_call|workflow_run", finalizer)
        self.assertIn("xsec-marketplace/batch-*", finalizer)

    def test_shared_preflight_preserves_each_source_repositories_real_ci_contract(self) -> None:
        workflow = SOURCE_PREFLIGHT.read_text(encoding="utf-8")
        self.assertIn("Validate the registered source manifest, release identity, and whitespace", workflow)
        self.assertIn("git diff --check HEAD^", workflow)
        self.assertNotIn("pnpm install", workflow)
        self.assertNotIn("pnpm test", workflow)


if __name__ == "__main__":
    unittest.main()
