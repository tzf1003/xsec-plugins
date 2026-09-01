from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import maintain_marketplace_defaults as maintenance  # noqa: E402
import verify_merged_stable_promotion as verifier  # noqa: E402
from marketplace_contract import active_default_official_plugin_ids  # noqa: E402


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def registry_entry(plugin_id: str, status: str = "active") -> dict[str, object]:
    return {
        "pluginId": plugin_id,
        "trustTier": "first-party",
        "source": {
            "repository": f"tzf1003/{plugin_id}",
            "path": f"plugins/{plugin_id}",
            "refs": {"beta": "refs/heads/beta", "stable": "refs/heads/main"},
        },
        "policy": {"installation": "INSTALLED_BY_DEFAULT", "authentication": "ON_INSTALL"},
        "category": "Security",
        "status": status,
    }


def marketplace_entry(plugin_id: str) -> dict[str, object]:
    return {
        "name": plugin_id,
        "source": {"source": "local", "path": f"./.xsec-factory/snapshots/{plugin_id}"},
        "policy": {"installation": "INSTALLED_BY_DEFAULT", "authentication": "ON_INSTALL"},
        "category": "Security",
    }


class MarketplaceDefaultsMaintenanceTests(unittest.TestCase):
    def make_root(self, directory: str, *, status: str = "active", discovered: bool = True) -> Path:
        root = Path(directory)
        retained_id = "com.xsec.workspace.files"
        entries = [registry_entry(maintenance.PROJECT_WORKSPACE_PLUGIN_ID, status), registry_entry(retained_id)]
        plugins = [marketplace_entry(retained_id)]
        if discovered:
            plugins.insert(0, marketplace_entry(maintenance.PROJECT_WORKSPACE_PLUGIN_ID))
        write_json(root / maintenance.REGISTRY_PATH, {"schemaVersion": 2, "plugins": entries})
        write_json(root / maintenance.MARKETPLACE_PATH, {"name": "xsec-official", "plugins": plugins})
        return root

    def test_transition_withdraws_discovery_and_retains_registry_history(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-default-set-") as directory:
            root = self.make_root(directory)
            self.assertTrue(maintenance.apply_transition(root))
            marketplace = json.loads((root / maintenance.MARKETPLACE_PATH).read_text(encoding="utf-8"))
            registry = json.loads((root / maintenance.REGISTRY_PATH).read_text(encoding="utf-8"))
            self.assertEqual([item["name"] for item in marketplace["plugins"]], ["com.xsec.workspace.files"])
            self.assertEqual(registry["plugins"][0]["status"], "disabled")
            self.assertEqual(active_default_official_plugin_ids(root), ("com.xsec.workspace.files",))

    def test_completed_transition_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-default-set-noop-") as directory:
            root = self.make_root(directory, status="disabled", discovered=False)
            self.assertFalse(maintenance.apply_transition(root))

    def test_partial_transition_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-default-set-partial-") as directory:
            root = self.make_root(directory, status="disabled", discovered=True)
            with self.assertRaisesRegex(
                maintenance.MarketplaceDefaultsMaintenanceError,
                "not in one atomic state",
            ):
                maintenance.apply_transition(root)

    def test_finalizer_payload_check_accepts_only_the_reviewed_delta(self) -> None:
        project_id = maintenance.PROJECT_WORKSPACE_PLUGIN_ID
        retained_id = "com.xsec.workspace.files"
        before_registry = {"schemaVersion": 2, "plugins": [registry_entry(project_id), registry_entry(retained_id)]}
        after_registry = json.loads(json.dumps(before_registry))
        after_registry["plugins"][0]["status"] = "disabled"
        before_marketplace = {"name": "xsec-official", "plugins": [marketplace_entry(project_id), marketplace_entry(retained_id)]}
        after_marketplace = {"name": "xsec-official", "plugins": [marketplace_entry(retained_id)]}
        verifier.verify_default_set_payloads(
            before_registry=before_registry,
            after_registry=after_registry,
            before_marketplace=before_marketplace,
            after_marketplace=after_marketplace,
        )
        after_marketplace["name"] = "changed"
        with self.assertRaisesRegex(verifier.PromotionVerificationError, "only remove project workspace"):
            verifier.verify_default_set_payloads(
                before_registry=before_registry,
                after_registry=after_registry,
                before_marketplace=before_marketplace,
                after_marketplace=after_marketplace,
            )

    def test_protected_workflows_route_the_transition_through_kms_and_finalizer(self) -> None:
        publish = (ROOT / ".github/workflows/publish.yml").read_text(encoding="utf-8")
        arm = (ROOT / ".github/workflows/arm-generated-marketplace-final-merge.yml").read_text(encoding="utf-8")
        finalizer = (ROOT / ".github/workflows/final-merge-generated-marketplace-pr.yml").read_text(encoding="utf-8")
        auto_finalizer = (ROOT / ".github/workflows/auto-finalize-generated-marketplace-pr.yml").read_text(encoding="utf-8")
        self.assertIn("push:\n    branches: [main]", publish)
        self.assertIn("align_desktop_defaults", publish)
        self.assertIn("maintenance=align_desktop_defaults", publish)
        self.assertIn("python scripts/maintain_marketplace_defaults.py --root .", publish)
        self.assertIn("xsec-marketplace/default-set-", arm)
        self.assertIn("xsec-marketplace/default-set-", finalizer)
        self.assertIn("xsec-marketplace/default-set-*", auto_finalizer)
        self.assertIn("--verify-default-set-transition-candidate", finalizer)


if __name__ == "__main__":
    unittest.main()
