from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import factory_main_protection_policy as policy  # noqa: E402


def current_protection() -> dict[str, object]:
    return {
        "required_status_checks": {
            "strict": True,
            "contexts": [
                "source-gate",
                "source-freshness-gate",
                "factory-final-merge-gate",
                "unrelated-build",
                "legacy-unpinned",
            ],
            "checks": [
                {"context": "source-gate", "app_id": 15368},
                {"context": "source-freshness-gate", "app_id": 15368},
                {"context": "factory-final-merge-gate", "app_id": 15368},
                {"context": "unrelated-build", "app_id": 42},
                {"context": "nullable-unpinned", "app_id": None},
            ],
        },
        "enforce_admins": {"enabled": False},
        "required_pull_request_reviews": None,
        "restrictions": {
            "users": [{"login": "release-admin"}],
            "teams": [{"slug": "release-team"}],
            "apps": [{"slug": "release-app"}],
            "url": "response-only",
        },
        "required_linear_history": {"enabled": True},
        "allow_force_pushes": {"enabled": False},
        "allow_deletions": {"enabled": False},
        "block_creations": {"enabled": False},
        "required_conversation_resolution": {"enabled": True},
        "lock_branch": {"enabled": False},
        "allow_fork_syncing": {"enabled": False},
    }


class FactoryMainProtectionPolicyTests(unittest.TestCase):
    def test_strengthening_moves_finalizer_gate_to_ruleset_and_preserves_unrelated_checks(self) -> None:
        current = current_protection()
        current["required_pull_request_reviews"] = {
            "dismiss_stale_reviews": True,
            "required_approving_review_count": 1,
        }
        desired = policy.desired_policy(current)

        self.assertTrue(desired["required_status_checks"]["strict"])
        self.assertTrue(desired["enforce_admins"])
        self.assertNotIn("contexts", desired["required_status_checks"])
        self.assertNotIn(
            {"context": "source-freshness-gate", "app_id": 15368},
            desired["required_status_checks"]["checks"],
        )
        self.assertNotIn(
            {"context": "factory-final-merge-gate", "app_id": 15368},
            desired["required_status_checks"]["checks"],
        )
        self.assertEqual(
            desired["required_status_checks"]["checks"],
            [
                {"context": "legacy-unpinned", "app_id": -1},
                {"context": "nullable-unpinned", "app_id": -1},
                {"context": "source-gate", "app_id": 15368},
                {"context": "unrelated-build", "app_id": 42},
            ],
        )
        self.assertIsNone(desired["required_pull_request_reviews"])
        self.assertFalse(desired["required_conversation_resolution"])
        self.assertEqual(desired["restrictions"], {"users": ["release-admin"], "teams": ["release-team"], "apps": ["release-app"]})
        self.assertTrue(desired["required_linear_history"])
        self.assertFalse(desired["allow_force_pushes"])
        self.assertFalse(desired["allow_deletions"])

    def test_verifier_rejects_missing_source_gate_finalizer_in_classic_admin_bypass_or_non_strict_checks(self) -> None:
        active = current_protection()
        active["enforce_admins"] = {"enabled": True}
        active["required_status_checks"] = {
            "strict": True,
            "checks": [
                {"context": "source-gate", "app_id": 15368},
            ],
        }
        active["required_pull_request_reviews"] = None
        active["required_conversation_resolution"] = {"enabled": False}
        policy.verify_policy(active)

        stale = current_protection()
        stale["enforce_admins"] = {"enabled": True}
        stale["required_status_checks"] = {
            "strict": True,
            "checks": [{"context": "source-gate", "app_id": 15368}],
        }
        stale["required_status_checks"]["checks"] = [{"context": "unrelated", "app_id": 15368}]
        with self.assertRaisesRegex(policy.ProtectionPolicyError, "source-gate"):
            policy.verify_policy(stale)

        non_strict = current_protection()
        non_strict["enforce_admins"] = {"enabled": True}
        non_strict["required_status_checks"] = {
            "strict": False,
            "checks": [
                {"context": "source-gate", "app_id": 15368},
            ],
        }
        with self.assertRaisesRegex(policy.ProtectionPolicyError, "strict"):
            policy.verify_policy(non_strict)

        admin_bypass = current_protection()
        admin_bypass["required_status_checks"] = {
            "strict": True,
            "checks": [
                {"context": "source-gate", "app_id": 15368},
            ],
        }
        with self.assertRaisesRegex(policy.ProtectionPolicyError, "administrators"):
            policy.verify_policy(admin_bypass)

        finalizer_still_classic = current_protection()
        finalizer_still_classic["enforce_admins"] = {"enabled": True}
        finalizer_still_classic["required_status_checks"] = {
            "strict": True,
            "checks": [
                {"context": "source-gate", "app_id": 15368},
                {"context": "factory-final-merge-gate", "app_id": 15368},
            ],
        }
        with self.assertRaisesRegex(policy.ProtectionPolicyError, "dedicated finalizer Ruleset"):
            policy.verify_policy(finalizer_still_classic)

        review_required = current_protection()
        review_required["enforce_admins"] = {"enabled": True}
        review_required["required_status_checks"] = {
            "strict": True,
            "checks": [{"context": "source-gate", "app_id": 15368}],
        }
        review_required["required_pull_request_reviews"] = {
            "required_approving_review_count": 1,
        }
        with self.assertRaisesRegex(policy.ProtectionPolicyError, "review requirements"):
            policy.verify_policy(review_required)

        conversation_required = current_protection()
        conversation_required["enforce_admins"] = {"enabled": True}
        conversation_required["required_status_checks"] = {
            "strict": True,
            "checks": [{"context": "source-gate", "app_id": 15368}],
        }
        with self.assertRaisesRegex(policy.ProtectionPolicyError, "conversation requirements"):
            policy.verify_policy(conversation_required)


if __name__ == "__main__":
    unittest.main()
