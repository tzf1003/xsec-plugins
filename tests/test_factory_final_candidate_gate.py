from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ARM_WORKFLOW = ROOT / ".github" / "workflows" / "arm-generated-marketplace-final-merge.yml"
FINAL_WORKFLOW = ROOT / ".github" / "workflows" / "final-merge-generated-marketplace-pr.yml"


class FactoryFinalCandidateGateWorkflowTests(unittest.TestCase):
    def test_retained_sidecar_refresh_is_a_pending_factory_candidate(self) -> None:
        workflow = ARM_WORKFLOW.read_text(encoding="utf-8")
        # Both the event branch and every same-repository Factory PR with a
        # shared head SHA must identify the generated repair, even if that
        # Factory PR was closed without merging. The commit-association API
        # omits such closed PRs before default-branch inclusion, so this must
        # use the complete main-targeting PR inventory. Otherwise an ordinary
        # same-SHA PR could overwrite its required pending status with success.
        self.assertGreaterEqual(workflow.count("xsec-marketplace/refresh-retained-sidecar-"), 2)
        self.assertIn('pulls?state=all&base=main&per_page=100', workflow)
        self.assertIn('any(.[][]; .head.sha == $sha and .head.repo.full_name == $repo', workflow)
        self.assertNotIn('commits/${PR_HEAD_SHA}/pulls', workflow)
        self.assertIn("factory_generated=true", workflow)
        self.assertIn("state=pending", workflow)

    def test_final_gate_revalidates_narrow_adoption_and_sidecar_candidates(self) -> None:
        workflow = FINAL_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("xsec-marketplace/refresh-retained-sidecar-*", workflow)
        self.assertIn("--verify-first-party-adoption-candidate", workflow)
        self.assertIn("--verify-retained-sidecar-refresh-candidate", workflow)
        self.assertIn("--verify-retained-release-signature --retained-release-plugin-id", workflow)
        self.assertIn("exact PR head has no successful Factory source gate", workflow)
        self.assertIn("exact PR head has no completed Codex review", workflow)
        self.assertIn("unresolved Codex review thread", workflow)

    def test_final_gate_never_turns_the_arm_owned_candidate_status_green(self) -> None:
        workflow = FINAL_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("The arm workflow owns factory-final-merge-gate", workflow)
        self.assertNotIn("state=success -f context=factory-final-merge-gate", workflow)
        self.assertNotIn("statuses: write", workflow)
        self.assertNotIn("trap ", workflow)
        self.assertNotIn("XSEC_MARKETPLACE_PUBLISH_TOKEN", workflow)
        self.assertIn("XSEC_MARKETPLACE_FINALIZER_APP_ID", workflow)
        self.assertIn("XSEC_MARKETPLACE_FINALIZER_APP_PRIVATE_KEY", workflow)
        self.assertIn("permission-contents: write", workflow)
        # GitHub's merge endpoint needs Contents:write. Requesting a separate
        # Pull requests:write grant would widen the short-lived bypass token
        # without enabling its one exact-head merge call.
        self.assertNotIn("permission-pull-requests: write", workflow)
        self.assertIn("-f sha=\"$HEAD_SHA\"", workflow)

    def test_finalizer_token_follows_the_last_external_source_sha_check(self) -> None:
        workflow = FINAL_WORKFLOW.read_text(encoding="utf-8")
        merge_step = workflow.split(
            "- name: Merge the exact revalidated head with the isolated Finalizer App", 1
        )[1]
        source_check = "while IFS= read -r source; do"
        token_assignment = 'GH_TOKEN="${{ steps.finalizer.outputs.token }}" gh api --method PUT'

        # The short-lived bypass token must not exist in the source-read loop.
        # A source beta/main push while the token action runs is therefore
        # detected by this second proof, immediately before the only PUT that
        # receives the token.
        self.assertNotIn("GH_TOKEN: ${{ steps.finalizer.outputs.token }}", workflow)
        self.assertIn(source_check, merge_step)
        self.assertIn('factory-publication-sources.json', merge_step)
        self.assertIn(token_assignment, merge_step)
        self.assertIn(
            "advanced immediately before the Finalizer merge; it remains pending.",
            merge_step,
        )
        self.assertLess(merge_step.index(source_check), merge_step.index(token_assignment))
        self.assertNotIn("GH_TOKEN", merge_step[: merge_step.index(token_assignment)])
        self.assertEqual(merge_step.count("GH_TOKEN="), 1)
        self.assertEqual(merge_step.count("gh api"), 1)


if __name__ == "__main__":
    unittest.main()
