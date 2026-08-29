from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import factory_finalizer_ruleset_policy as policy  # noqa: E402


FINALIZER_APP_ID = 424242


def active_ruleset() -> dict[str, object]:
    result = policy.expected_ruleset(FINALIZER_APP_ID)
    result.update(
        {
            "id": 99,
            "source_type": "Repository",
            "source": "tzf1003/xsec-plugins",
            "node_id": "RRS_test",
        }
    )
    return result


class FactoryFinalizerRulesetPolicyTests(unittest.TestCase):
    def test_absent_managed_ruleset_creates_exact_payload_without_reading_unrelated_rulesets(self) -> None:
        unrelated = {
            "id": 4,
            "name": "ordinary-maintainers-policy",
            # This is intentionally not a complete Ruleset response. The
            # Factory policy must leave unrelated entries uninspected.
            "unexpected": {"anything": "allowed"},
        }
        plan = policy.management_plan([unrelated], FINALIZER_APP_ID)

        self.assertEqual(plan["action"], "create")
        self.assertIsNone(plan["ruleset_id"])
        self.assertEqual(plan["ruleset"], policy.expected_ruleset(FINALIZER_APP_ID))

    def test_expected_same_name_ruleset_updates_only_that_id(self) -> None:
        plan = policy.management_plan([{"id": 1, "name": "unrelated"}, active_ruleset()], FINALIZER_APP_ID)

        self.assertEqual(plan["action"], "update")
        self.assertEqual(plan["ruleset_id"], 99)
        self.assertEqual(plan["ruleset"], policy.expected_ruleset(FINALIZER_APP_ID))
        policy.verify_ruleset(active_ruleset(), FINALIZER_APP_ID)

    def test_duplicate_same_name_rulesets_fail_closed_and_summary_defers_full_validation(self) -> None:
        duplicate = active_ruleset()
        duplicate["id"] = 100
        with self.assertRaisesRegex(policy.FinalizerRulesetPolicyError, "more than one"):
            policy.management_plan([active_ruleset(), duplicate], FINALIZER_APP_ID)

        # GET /rulesets is intentionally a summary response.  It can identify
        # the one managed ID, while the protected workflow fetches that ID and
        # applies the full fail-closed verifier before an update.
        summary_plan = policy.management_plan(
            [{"id": 99, "name": policy.RULESET_NAME, "enforcement": "active"}], FINALIZER_APP_ID
        )
        self.assertEqual(summary_plan["action"], "update")
        self.assertEqual(summary_plan["ruleset_id"], 99)

        wrong_ref = copy.deepcopy(active_ruleset())
        wrong_ref["conditions"] = {"ref_name": {"include": ["refs/heads/beta"], "exclude": []}}
        with self.assertRaisesRegex(policy.FinalizerRulesetPolicyError, "refs/heads/main"):
            policy.verify_ruleset(wrong_ref, FINALIZER_APP_ID)

        unsafe_bypass = copy.deepcopy(active_ruleset())
        unsafe_bypass["bypass_actors"].append(
            {"actor_id": 1, "actor_type": "User", "bypass_mode": "always"}
        )
        with self.assertRaisesRegex(policy.FinalizerRulesetPolicyError, "exactly one PR-only"):
            policy.verify_ruleset(unsafe_bypass, FINALIZER_APP_ID)

    def test_wrong_status_source_non_strict_policy_or_finalizer_app_fails_closed(self) -> None:
        wrong_source = copy.deepcopy(active_ruleset())
        wrong_source["rules"][0]["parameters"]["required_status_checks"][0]["integration_id"] = 1
        with self.assertRaisesRegex(policy.FinalizerRulesetPolicyError, "strict final gate"):
            policy.verify_ruleset(wrong_source, FINALIZER_APP_ID)

        non_strict = copy.deepcopy(active_ruleset())
        non_strict["rules"][0]["parameters"]["strict_required_status_checks_policy"] = False
        with self.assertRaisesRegex(policy.FinalizerRulesetPolicyError, "strict final gate"):
            policy.verify_ruleset(non_strict, FINALIZER_APP_ID)

        wrong_app = copy.deepcopy(active_ruleset())
        wrong_app["bypass_actors"][0]["actor_id"] = 7
        with self.assertRaisesRegex(policy.FinalizerRulesetPolicyError, "configured GitHub App"):
            policy.verify_ruleset(wrong_app, FINALIZER_APP_ID)

    def test_app_id_requires_a_positive_decimal_integration_id(self) -> None:
        for invalid in (None, "", "0", "-1", "app-name", "１２", 0, False):
            with self.subTest(invalid=invalid):
                with self.assertRaises(policy.FinalizerRulesetPolicyError):
                    policy.expected_ruleset(invalid)


if __name__ == "__main__":
    unittest.main()
