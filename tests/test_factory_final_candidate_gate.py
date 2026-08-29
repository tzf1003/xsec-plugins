from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ARM_WORKFLOW = ROOT / ".github" / "workflows" / "arm-generated-marketplace-final-merge.yml"
FINAL_WORKFLOW = ROOT / ".github" / "workflows" / "final-merge-generated-marketplace-pr.yml"


class FactoryFinalCandidateGateWorkflowTests(unittest.TestCase):
    def test_retained_sidecar_refresh_is_a_pending_factory_candidate(self) -> None:
        workflow = ARM_WORKFLOW.read_text(encoding="utf-8")
        # Both the event branch and every open PR associated with a shared
        # commit SHA must identify the generated repair. Otherwise an ordinary
        # same-SHA PR could overwrite its required pending status with success.
        self.assertGreaterEqual(workflow.count("xsec-marketplace/refresh-retained-sidecar-"), 2)
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


if __name__ == "__main__":
    unittest.main()
