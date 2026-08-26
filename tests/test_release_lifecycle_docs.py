from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
LIFECYCLE = ROOT / "docs" / "plugin-development-release-lifecycle.md"


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


if __name__ == "__main__":
    unittest.main()
