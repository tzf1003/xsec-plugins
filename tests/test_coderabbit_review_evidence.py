"""Recorded CodeRabbit API-shape contracts for exact-head Factory review evidence."""

from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "coderabbit_review_evidence.json"
WORKFLOWS = (
    ROOT / ".github" / "workflows" / "auto-finalize-generated-marketplace-pr.yml",
    ROOT / ".github" / "workflows" / "final-merge-generated-marketplace-pr.yml",
    ROOT / ".github" / "workflows" / "finalize-selected-generated-marketplace-pr.yml",
    ROOT / ".github" / "workflows" / "rebuild-stale-marketplace-batch.yml",
)
EVIDENCE_FILTER = r'''
def exact_review:
  ($reviews | type == "array" and length > 0)
  and all($reviews[]?; .data.repository.pullRequest.headRefOid == $head and (.data.repository.pullRequest.reviews.nodes | type == "array"))
  and ($reviews[-1].data.repository.pullRequest.reviews.pageInfo.hasNextPage == false)
  and any($reviews[]?.data.repository.pullRequest.reviews.nodes[]?;
    .author.login == "coderabbitai"
    and .author.__typename == "Bot"
    and .commit.oid == $head
    and (.submittedAt | type == "string")
    and (.state == "COMMENTED" or .state == "APPROVED")
  );
def exact_zero_finding_summary:
  ($comments | type == "array" and length > 0)
  and all($comments[]?; type == "array")
  and any($comments[][]?;
    .user.login == "coderabbitai[bot]"
    and .user.type == "Bot"
    and (.body | type == "string")
    and ((try (.body | capture("(?s)<!-- recent_review_start -->\\s*(?<recent>.*?)\\s*<!-- recent_review_end -->").recent) catch "") as $recent
      | ($recent | contains("No actionable comments were generated in the recent review."))
      and ($recent | test("Reviewing files that changed from the base of the PR and between [a-f0-9]{40} and " + $head + "\\."))
    )
  );
($statuses | type == "array" and length > 0)
and all($statuses[]?; type == "array")
and (
  [$statuses[][]
    | select(
        .context == "CodeRabbit"
        and .creator.login == "coderabbitai[bot]"
        and .creator.type == "Bot"
        and (.created_at | type == "string")
        and (.description | type == "string")
      )
  ]
  | if length > 0 then (.[0].state == "success" and .[0].description == "Review completed") else false end
)
and (exact_review or exact_zero_finding_summary)
'''


class CodeRabbitReviewEvidenceTests(unittest.TestCase):
    def test_recorded_api_shapes_enforce_exact_head_evidence(self) -> None:
        cases = json.loads(FIXTURES.read_text(encoding="utf-8"))
        self.assertEqual(len(cases), 4)
        for case in cases:
            command = [
                "jq", "-ne", "--arg", "head", case["head"],
                "--argjson", "statuses", json.dumps(case["statuses"]),
                "--argjson", "reviews", json.dumps(case["reviews"]),
                "--argjson", "comments", json.dumps(case["comments"]),
                EVIDENCE_FILTER,
            ]
            result = subprocess.run(command, check=False, capture_output=True, text=True)
            with self.subTest(case=case["name"]):
                self.assertEqual(result.returncode == 0, case["expected"], result.stderr)

    def test_every_gate_uses_bounded_summary_and_trusted_status(self) -> None:
        for workflow_path in WORKFLOWS:
            workflow = workflow_path.read_text(encoding="utf-8")
            with self.subTest(workflow=workflow_path.name):
                self.assertIn('creator.login == "coderabbitai[bot]"', workflow)
                self.assertIn('creator.type == "Bot"', workflow)
                self.assertIn('<!-- recent_review_start -->', workflow)
                self.assertIn('<!-- recent_review_end -->', workflow)
                self.assertIn('capture("(?s)', workflow)
                self.assertIn('No actionable comments were generated in the recent review.', workflow)
                self.assertIn('between [a-f0-9]{40} and " + $head + "\\\\."', workflow)
                self.assertNotIn('.body | contains($head)', workflow)


if __name__ == "__main__":
    unittest.main()
