from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
LIFECYCLE = ROOT / "docs" / "plugin-development-release-lifecycle.md"
PUBLISH_WORKFLOW = ROOT / ".github" / "workflows" / "publish.yml"


class ReleaseLifecycleDocumentationTests(unittest.TestCase):
    def test_marketplace_readme_links_to_the_lifecycle_contract(self) -> None:
        self.assertIn(
            "docs/plugin-development-release-lifecycle.md",
            README.read_text(encoding="utf-8"),
        )

    def test_lifecycle_contract_keeps_local_and_cloud_identities_distinct(self) -> None:
        document = LIFECYCLE.read_text(encoding="utf-8")
        for required_rule in (
            "`dev_revision`",
            "`releaseId`",
            "一个 `plugin.json.version`（SemVer）只能对应一个不可变 release",
            "必须先提高 `plugin.json.version`",
            "上传到 Marketplace 或任何云端 preview",
            "规范 JSON 重新计算 `releaseId`",
        ):
            with self.subTest(required_rule=required_rule):
                self.assertIn(required_rule, document)

    def test_lifecycle_contract_explains_the_publication_queue(self) -> None:
        document = LIFECYCLE.read_text(encoding="utf-8")
        readme = README.read_text(encoding="utf-8")
        for required_rule in (
            "发布队列",
            "取得队列槽位后",
            "`source_sha`",
            "过期 release index",
        ):
            with self.subTest(required_rule=required_rule):
                self.assertIn(required_rule, document)
        self.assertIn("Publication queue and Agent evidence", readme)
        self.assertIn("event SHA", readme)

    def test_external_source_transport_boundary_is_documented(self) -> None:
        document = LIFECYCLE.read_text(encoding="utf-8")
        readme = README.read_text(encoding="utf-8")
        self.assertIn("Git transport", document)
        self.assertIn("verified ref", document)
        self.assertIn("https://github.com", readme)
        self.assertIn("insteadOf", readme)
        self.assertIn("local verified ref", readme)

    def test_disabled_external_history_requires_cryptographic_sidecar_verification(self) -> None:
        document = LIFECYCLE.read_text(encoding="utf-8")
        readme = README.read_text(encoding="utf-8")
        self.assertIn("pinned Vercel KMS issuer JWKS", readme)
        self.assertIn("cryptographically verifies", readme)
        self.assertIn("Ed25519", document)
        self.assertIn("密码学验证 sidecar", document)

    def test_published_external_registry_removal_is_blocked_against_the_trusted_baseline(self) -> None:
        document = LIFECYCLE.read_text(encoding="utf-8")
        readme = README.read_text(encoding="utf-8")
        self.assertIn("trusted pre-change\nFactory revision", readme)
        self.assertIn("同一 PR 同时删除 registry、快照和证据", document)
        self.assertIn("设为 `disabled`", document)

    def test_duplicate_beta_delivery_replays_only_the_current_waiting_smoke_status(self) -> None:
        workflow = PUBLISH_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("needs-smoke-redispatch", workflow)
        self.assertIn("smoke_redispatch=true", workflow)
        self.assertIn("marketplace_revision=$(git rev-parse HEAD)", workflow)
        self.assertIn("steps.publication-decision.outputs.smoke_redispatch == 'true'", workflow)


if __name__ == "__main__":
    unittest.main()
