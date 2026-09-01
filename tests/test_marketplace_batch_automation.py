"""Static contracts for the single-PR first-party source batch."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
BATCH_RECONCILE = ROOT / ".github" / "workflows" / "reconcile-marketplace-batch.yml"
BATCH_PUBLISH = ROOT / ".github" / "workflows" / "publish-marketplace-batch.yml"
STALE_BATCH_RECOVERY = ROOT / ".github" / "workflows" / "rebuild-stale-marketplace-batch.yml"
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
            "cancel-in-progress: true",
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
            "python scripts/build_market.py --clean",
            "git status --porcelain --untracked-files=all",
            "':(exclude,glob)**/*.sig.jws.json'",
            'source_revision="$(git rev-parse HEAD)"',
            '"$(git rev-parse origin/main)"',
            "XSEC_MARKETPLACE_SOURCE_REVISION: ${{ steps.current-main.outputs.source_revision }}",
            'git update-index --add --cacheinfo "160000,${beta_sha},plugins/${plugin_id}"',
            "python scripts/kms_marketplace_publisher.py --root .",
            "git add -A .agents/plugins .xsec-factory plugins",
            'branch="xsec-marketplace/batch-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"',
        ):
            with self.subTest(rule=rule):
                self.assertIn(rule, publisher)
        self.assertNotIn("permission-checks: read", publisher)
        self.assertNotIn("| rg -v", publisher)
        self.assertNotIn("| grep -v", publisher)

    def test_batch_reconcile_forwards_the_validated_source_trigger_label(self) -> None:
        workflow = BATCH_RECONCILE.read_text(encoding="utf-8")

        self.assertIn("trigger_label: source-event:${{ steps.request.outputs.plugin_id }}", workflow)
        self.assertIn(
            "trigger_label: ${{ needs.validate-source-event.outputs.trigger_label }}",
            workflow,
        )
        self.assertNotIn("outputs.event_plugin_id", workflow)

    def test_batch_caller_grants_write_scope_only_to_the_publisher(self) -> None:
        """Keep write authority on the reusable publication job."""

        workflow = yaml.safe_load(BATCH_RECONCILE.read_text(encoding="utf-8"))

        self.assertEqual(workflow["permissions"], {"actions": "read", "contents": "read"})
        self.assertEqual(
            workflow["jobs"]["build-current-batch"]["permissions"],
            {"contents": "write", "id-token": "write", "pull-requests": "write"},
        )

    def test_stale_signed_batch_is_rebuilt_and_superseded_automatically(self) -> None:
        recovery = STALE_BATCH_RECOVERY.read_text(encoding="utf-8")
        publisher = BATCH_PUBLISH.read_text(encoding="utf-8")

        for rule in (
            "name: Rebuild stale generated Marketplace batch",
            "branches: [main]",
            "group: xsec-marketplace-stale-batch-recovery",
            "cancel-in-progress: false",
            'git/ref/heads/main" --jq .object.sha',
            'test("^xsec-marketplace/batch-[0-9]+-[0-9]+$")',
            "source-gate source-freshness-gate",
            'creator.login == "coderabbitai[bot]"',
            "reviewThreads(first:100,after:$endCursor)",
            "Verify the signed stale batch as data",
            "--verify-active-marketplace-signatures",
            "python scripts/external_source_factory.py --root \"$candidate\" validate",
            "uses: ./.github/workflows/publish-marketplace-batch.yml",
            "factory-stale-batch:",
            "Close unchanged stale batches replaced by the new candidate",
            'gh api --method PATCH "repos/${GITHUB_REPOSITORY}/pulls/${old_number}" -f state=closed',
        ):
            with self.subTest(rule=rule):
                self.assertIn(rule, recovery)
        self.assertIn("trigger_label:", publisher)
        self.assertIn("outputs:\n      pull_number:", publisher)
        self.assertIn('Factory trigger label is invalid.', publisher)
        self.assertIn('echo "pull_number=$pull_number" >> "$GITHUB_OUTPUT"', publisher)

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
        self.assertIn("Verify generated Marketplace publication merge", workflow)
        self.assertIn("pull_request_review:", workflow)
        self.assertIn("types: [submitted]", workflow)
        self.assertNotIn("pull_request_review:\n    branches:", workflow)
        self.assertIn("status:", workflow)
        self.assertIn("github.event.sender.login == 'coderabbitai[bot]'", workflow)
        self.assertIn("github.event.sender.type == 'Bot'", workflow)
        self.assertIn("github.event.context == 'CodeRabbit'", workflow)
        self.assertIn("github.event.state == 'success'", workflow)
        self.assertIn("github.event.sha", workflow)
        self.assertIn("reviewThreads(first:100,after:$endCursor)", workflow)
        self.assertIn("gh api graphql --paginate --slurp", workflow)
        self.assertIn("all(.[]?.data.repository.pullRequest.reviewThreads.nodes[]?; .isResolved == true)", workflow)
        self.assertIn(".[-1].data.repository.pullRequest.reviewThreads.pageInfo.hasNextPage == false", workflow)
        self.assertIn("startsWith(github.event.workflow_run.head_branch, 'xsec-marketplace/')", workflow)
        self.assertIn("startsWith(github.event.pull_request.head.ref, 'xsec-marketplace/')", workflow)
        self.assertIn("checks: read", workflow)
        self.assertIn("source-freshness-gate", workflow)
        self.assertIn('.name == "source-freshness-gate"', workflow)
        self.assertIn("needs.select-exact-generated-pr.result == 'success'", workflow)
        self.assertIn("outputs.eligible == 'true'", workflow)
        self.assertIn("always() && needs.select-exact-generated-pr.result == 'success'", workflow)
        self.assertIn("fromJSON(needs.select-exact-generated-pr.outputs.coderabbit_status_verified)", workflow)
        self.assertIn("expected at most one open exact-head generated PR", workflow)
        self.assertIn('($branch == "" or .head.ref == $branch)', workflow)
        self.assertIn("workflow_call:", finalizer)
        self.assertIn("coderabbit_status_verified:", finalizer)
        self.assertIn("requires a completed CodeRabbit review", finalizer)
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
