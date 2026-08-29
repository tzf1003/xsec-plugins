from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import build_market  # noqa: E402
import verify_merged_stable_promotion as verifier  # noqa: E402


PLUGIN_ID = "com.example.plugin"


def git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(["git", *arguments], cwd=str(root), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    return completed.stdout.decode("utf-8").strip()


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def release(version: str, digest_seed: str) -> dict[str, object]:
    artifact = {"os": "any", "arch": "any", "url": f"artifacts/{version}.xsec-plugin", "sha256": hashlib.sha256(digest_seed.encode()).hexdigest()}
    engines = {"xsec": ">=1", "pluginApi": "^1"}
    return {"releaseId": build_market.release_id(version, engines, [artifact]), "version": version, "engines": engines, "artifacts": [artifact]}


class MergedMarketplacePublicationTests(unittest.TestCase):
    def make_repository(
        self, root: Path, *, registered: bool = False, with_release_history: bool = True
    ) -> tuple[str, dict[str, object], dict[str, object]]:
        stable = release("1.0.0", "stable")
        beta = release("1.1.0", "beta")
        if with_release_history:
            self.write_release(root, [stable], beta=stable["releaseId"], stable=stable["releaseId"])
        paths = [".agents/plugins/marketplace.json", ".agents/plugins/marketplace.json.sig.jws.json"]
        if with_release_history:
            paths.append(f"plugins/{PLUGIN_ID}/.xsec-market/releases.json.sig.jws.json")
        for path in paths:
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("{}\n", encoding="utf-8")
        if registered:
            write_json(
                root / ".xsec-factory/official-registry.json",
                {
                    "schemaVersion": 2,
                    "plugins": [
                        {
                            "pluginId": PLUGIN_ID,
                            "trustTier": "external",
                            "source": {
                                "repository": "example/plugin",
                                "path": f"plugins/{PLUGIN_ID}",
                                "refs": {"beta": "refs/heads/beta", "stable": "refs/heads/main"},
                            },
                            "policy": {"installation": "AVAILABLE", "authentication": "ON_INSTALL"},
                            "category": "Security",
                            "status": "active",
                        }
                    ],
                },
            )
            write_json(root / f".xsec-factory/official-publications/{PLUGIN_ID}.json", {"schemaVersion": 1, "pluginId": PLUGIN_ID, "events": []})
        git(root, "init", "--quiet", "--initial-branch=main")
        git(root, "config", "user.name", "Verifier Test")
        git(root, "config", "user.email", "verifier@example.invalid")
        git(root, "add", "--all")
        git(root, "commit", "--quiet", "-m", "base")
        return git(root, "rev-parse", "HEAD"), stable, beta

    def write_release(self, root: Path, records: list[dict[str, object]], *, beta: str, stable: str | None) -> None:
        write_json(
            root / f"plugins/{PLUGIN_ID}/.xsec-market/releases.json",
            {
                "schemaVersion": 2,
                "pluginId": PLUGIN_ID,
                "releases": records,
                "channels": {"beta": {"releaseId": beta}, "stable": None if stable is None else {"releaseId": stable}},
            },
        )

    def commit(self, root: Path, message: str) -> str:
        git(root, "add", "--all")
        git(root, "commit", "--quiet", "-m", message)
        return git(root, "rev-parse", "HEAD")

    def test_classifies_beta_without_relying_on_the_merge_subject(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-merged-beta-") as directory:
            root = Path(directory)
            before, stable, beta = self.make_repository(root)
            self.write_release(root, [stable, beta], beta=beta["releaseId"], stable=stable["releaseId"])
            (root / ".agents/plugins/marketplace.json.sig.jws.json").write_text("signed beta index\n", encoding="utf-8")
            (root / f"plugins/{PLUGIN_ID}/.xsec-market/releases.json.sig.jws.json").write_text("signed beta release\n", encoding="utf-8")
            (root / f"plugins/{PLUGIN_ID}/frontend.js").write_text("export {}\n", encoding="utf-8")
            after = self.commit(root, "Merge pull request #123 from arbitrary-title")

            result = verifier.classify_merged_change(root, before, after)

            self.assertEqual(result["kind"], "beta")
            self.assertEqual(result["promotions"], [{"plugin_id": PLUGIN_ID, "release_id": beta["releaseId"]}])

    def test_classifies_first_beta_when_the_baseline_has_no_release_index(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-merged-first-beta-") as directory:
            root = Path(directory)
            before, _, beta = self.make_repository(root, registered=True, with_release_history=False)
            self.write_release(root, [beta], beta=beta["releaseId"], stable=None)
            (root / ".agents/plugins/marketplace.json").write_text("new beta index\n", encoding="utf-8")
            (root / ".agents/plugins/marketplace.json.sig.jws.json").write_text("signed beta index\n", encoding="utf-8")
            (root / f"plugins/{PLUGIN_ID}/.xsec-market/releases.json.sig.jws.json").write_text("signed beta release\n", encoding="utf-8")
            (root / f"plugins/{PLUGIN_ID}/frontend.js").write_text("export {}\n", encoding="utf-8")
            event = {
                "channel": "beta",
                "releaseId": beta["releaseId"],
                "source": {"repository": "example/plugin", "path": f"plugins/{PLUGIN_ID}", "ref": "refs/heads/beta", "sha": "a" * 40},
                "artifact": {"sha256": beta["artifacts"][0]["sha256"], "url": beta["artifacts"][0]["url"]},
                "publisher": "factory",
            }
            write_json(root / f".xsec-factory/official-publications/{PLUGIN_ID}.json", {"schemaVersion": 1, "pluginId": PLUGIN_ID, "events": [event]})
            proof = root / f".xsec-factory/official-publication-proofs/{PLUGIN_ID}.json"
            proof.parent.mkdir(parents=True, exist_ok=True)
            proof.write_text("signed evidence\n", encoding="utf-8")
            after = self.commit(root, "first generated beta")

            result = verifier.classify_merged_change(root, before, after)

            self.assertEqual(result["kind"], "beta")
            self.assertEqual(
                result["promotions"],
                [
                    {
                        "plugin_id": PLUGIN_ID,
                        "release_id": beta["releaseId"],
                        "source": {"repository": "example/plugin", "ref": "refs/heads/beta", "sha": "a" * 40},
                    }
                ],
            )

    def test_classifies_stable_pointer_without_rebuilding_release_history(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-merged-stable-") as directory:
            root = Path(directory)
            stable = release("1.0.0", "stable")
            beta = release("1.1.0", "beta")
            self.write_release(root, [stable, beta], beta=beta["releaseId"], stable=stable["releaseId"])
            for path in (".agents/plugins/marketplace.json.sig.jws.json", f"plugins/{PLUGIN_ID}/.xsec-market/releases.json.sig.jws.json"):
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("{}\n", encoding="utf-8")
            git(root, "init", "--quiet", "--initial-branch=main")
            git(root, "config", "user.name", "Verifier Test")
            git(root, "config", "user.email", "verifier@example.invalid")
            before = self.commit(root, "base")
            self.write_release(root, [stable, beta], beta=beta["releaseId"], stable=beta["releaseId"])
            (root / ".agents/plugins/marketplace.json.sig.jws.json").write_text("signed stable index\n", encoding="utf-8")
            (root / f"plugins/{PLUGIN_ID}/.xsec-market/releases.json.sig.jws.json").write_text("signed stable release\n", encoding="utf-8")
            after = self.commit(root, "a reviewer chose any merge subject")

            result = verifier.classify_merged_change(root, before, after)

            self.assertEqual(result["kind"], "stable")
            self.assertEqual(result["promotions"], [{"plugin_id": PLUGIN_ID, "release_id": beta["releaseId"]}])

    def test_registered_source_binding_must_be_an_event_appended_by_this_pr(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-merged-source-") as directory:
            root = Path(directory)
            before, stable, beta = self.make_repository(root, registered=True)
            self.write_release(root, [stable, beta], beta=beta["releaseId"], stable=stable["releaseId"])
            (root / ".agents/plugins/marketplace.json.sig.jws.json").write_text("signed beta index\n", encoding="utf-8")
            (root / f"plugins/{PLUGIN_ID}/.xsec-market/releases.json.sig.jws.json").write_text("signed beta release\n", encoding="utf-8")
            (root / f"plugins/{PLUGIN_ID}/frontend.js").write_text("export {}\n", encoding="utf-8")
            event = {
                "channel": "beta",
                "releaseId": beta["releaseId"],
                "source": {"repository": "example/plugin", "path": f"plugins/{PLUGIN_ID}", "ref": "refs/heads/beta", "sha": "a" * 40},
                "artifact": {"sha256": beta["artifacts"][0]["sha256"], "url": beta["artifacts"][0]["url"]},
                "publisher": "factory",
            }
            write_json(root / f".xsec-factory/official-publications/{PLUGIN_ID}.json", {"schemaVersion": 1, "pluginId": PLUGIN_ID, "events": [event]})
            (root / f".xsec-factory/official-publication-proofs/{PLUGIN_ID}.json").parent.mkdir(parents=True, exist_ok=True)
            (root / f".xsec-factory/official-publication-proofs/{PLUGIN_ID}.json").write_text("signed evidence\n", encoding="utf-8")
            after = self.commit(root, "generated beta")

            result = verifier.classify_merged_change(root, before, after)

            self.assertEqual(result["promotions"][0]["source"], {"repository": "example/plugin", "ref": "refs/heads/beta", "sha": "a" * 40})

    def test_rejects_release_delta_with_an_unrelated_workflow_edit(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-merged-unsafe-") as directory:
            root = Path(directory)
            before, stable, beta = self.make_repository(root)
            self.write_release(root, [stable, beta], beta=beta["releaseId"], stable=stable["releaseId"])
            (root / ".agents/plugins/marketplace.json.sig.jws.json").write_text("signed beta index\n", encoding="utf-8")
            (root / f"plugins/{PLUGIN_ID}/.xsec-market/releases.json.sig.jws.json").write_text("signed beta release\n", encoding="utf-8")
            target = root / ".github/workflows/unsafe.yml"
            target.parent.mkdir(parents=True)
            target.write_text("name: unsafe\n", encoding="utf-8")
            after = self.commit(root, "generated beta plus unwanted workflow")

            with self.assertRaisesRegex(verifier.PromotionVerificationError, "unauthorized path"):
                verifier.classify_merged_change(root, before, after)

    def test_allows_only_the_fixed_factory_proof_directories_for_promoted_plugins(self) -> None:
        verifier.allowed_paths(
            "beta",
            [
                f".xsec-factory/official-publication-proofs/{PLUGIN_ID}.json",
                f".xsec-factory/official-adoptions/{PLUGIN_ID}.json",
                f".xsec-factory/official-adoption-proofs/{PLUGIN_ID}.json",
            ],
            {PLUGIN_ID},
        )
        with self.assertRaisesRegex(verifier.PromotionVerificationError, "unauthorized path"):
            verifier.allowed_paths(
                "beta",
                [f".xsec-factory/official-publications/{PLUGIN_ID}.json.sig.jws.json"],
                {PLUGIN_ID},
            )

    def test_classifies_signed_stable_completion_without_a_pointer_move_as_maintenance(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-merged-completion-") as directory:
            root = Path(directory)
            before, _, _ = self.make_repository(root)
            (root / ".agents/plugins/marketplace.json.sig.jws.json").write_text("refreshed index\n", encoding="utf-8")
            write_json(root / f".xsec-factory/official-publications/{PLUGIN_ID}.json", {"schemaVersion": 1, "pluginId": PLUGIN_ID, "events": []})
            (root / f".xsec-factory/official-publication-proofs/{PLUGIN_ID}.json").parent.mkdir(parents=True, exist_ok=True)
            (root / f".xsec-factory/official-publication-proofs/{PLUGIN_ID}.json").write_text("refreshed evidence\n", encoding="utf-8")
            write_json(root / f".xsec-factory/official-status/{PLUGIN_ID}.json", {"schemaVersion": 1})
            after = self.commit(root, "ordinary reviewer merge subject")

            self.assertEqual(verifier.classify_merged_change(root, before, after), {"kind": "maintenance"})

    def test_registered_no_pointer_stable_completion_carries_the_current_main_source(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-merged-registered-completion-") as directory:
            root = Path(directory)
            _, stable, beta = self.make_repository(root, registered=True)
            self.write_release(root, [stable, beta], beta=beta["releaseId"], stable=beta["releaseId"])
            before = self.commit(root, "stable already selects the reviewed beta")
            event = {
                "channel": "stable",
                "releaseId": beta["releaseId"],
                "source": {"repository": "example/plugin", "path": f"plugins/{PLUGIN_ID}", "ref": "refs/heads/main", "sha": "b" * 40},
                "artifact": {"sha256": beta["artifacts"][0]["sha256"], "url": beta["artifacts"][0]["url"]},
                "publisher": "factory",
            }
            (root / ".agents/plugins/marketplace.json.sig.jws.json").write_text("refreshed index\n", encoding="utf-8")
            (root / f"plugins/{PLUGIN_ID}/.xsec-market/releases.json.sig.jws.json").write_text("refreshed release\n", encoding="utf-8")
            write_json(root / f".xsec-factory/official-publications/{PLUGIN_ID}.json", {"schemaVersion": 1, "pluginId": PLUGIN_ID, "events": [event]})
            (root / f".xsec-factory/official-publication-proofs/{PLUGIN_ID}.json").parent.mkdir(parents=True, exist_ok=True)
            (root / f".xsec-factory/official-publication-proofs/{PLUGIN_ID}.json").write_text("refreshed evidence\n", encoding="utf-8")
            write_json(root / f".xsec-factory/official-status/{PLUGIN_ID}.json", {"schemaVersion": 1, "state": "promoting_stable"})
            after = self.commit(root, "ordinary reviewer merge subject")

            self.assertEqual(
                verifier.classify_merged_change(root, before, after),
                {
                    "kind": "stable-maintenance",
                    "promotions": [
                        {
                            "plugin_id": PLUGIN_ID,
                            "release_id": beta["releaseId"],
                            "source": {"repository": "example/plugin", "ref": "refs/heads/main", "sha": "b" * 40},
                        }
                    ],
                },
            )

    def test_first_party_adoption_candidate_allows_only_its_registry_activation_and_fixed_proofs(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-first-party-adoption-candidate-") as directory:
            root = Path(directory)
            registry = {
                "schemaVersion": 2,
                "plugins": [
                    {"pluginId": PLUGIN_ID, "status": "pending-adoption", "source": {"repository": "example/plugin"}},
                    {"pluginId": "com.example.unchanged", "status": "active"},
                ],
            }
            write_json(root / ".xsec-factory/official-registry.json", registry)
            git(root, "init", "--quiet", "--initial-branch=main")
            git(root, "config", "user.name", "Verifier Test")
            git(root, "config", "user.email", "verifier@example.invalid")
            before = self.commit(root, "pending first-party registration")
            registry["plugins"][0]["status"] = "active"
            write_json(root / ".xsec-factory/official-registry.json", registry)
            write_json(root / f".xsec-factory/official-adoptions/{PLUGIN_ID}.json", {"pluginId": PLUGIN_ID})
            write_json(root / f".xsec-factory/official-adoption-proofs/{PLUGIN_ID}.json", {"pluginId": PLUGIN_ID})
            after = self.commit(root, "activate one first-party registration")

            self.assertEqual(
                verifier.verify_first_party_adoption_candidate(root, before, after),
                {
                    "kind": "adoption",
                    "plugin_id": PLUGIN_ID,
                    "adoption_path": f".xsec-factory/official-adoptions/{PLUGIN_ID}.json",
                },
            )

    def test_first_party_adoption_candidate_rejects_an_unrelated_change(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-first-party-adoption-extra-") as directory:
            root = Path(directory)
            registry = {"schemaVersion": 2, "plugins": [{"pluginId": PLUGIN_ID, "status": "pending-adoption"}]}
            write_json(root / ".xsec-factory/official-registry.json", registry)
            git(root, "init", "--quiet", "--initial-branch=main")
            git(root, "config", "user.name", "Verifier Test")
            git(root, "config", "user.email", "verifier@example.invalid")
            before = self.commit(root, "pending first-party registration")
            registry["plugins"][0]["status"] = "active"
            write_json(root / ".xsec-factory/official-registry.json", registry)
            write_json(root / f".xsec-factory/official-adoptions/{PLUGIN_ID}.json", {"pluginId": PLUGIN_ID})
            write_json(root / f".xsec-factory/official-adoption-proofs/{PLUGIN_ID}.json", {"pluginId": PLUGIN_ID})
            (root / ".github/workflows/unrelated.yml").parent.mkdir(parents=True)
            (root / ".github/workflows/unrelated.yml").write_text("name: unrelated\n", encoding="utf-8")
            after = self.commit(root, "unsafe first-party activation")

            with self.assertRaisesRegex(verifier.PromotionVerificationError, "unauthorized path set"):
                verifier.verify_first_party_adoption_candidate(root, before, after)

    def test_retained_sidecar_refresh_candidate_allows_one_retained_sidecar_only(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-retained-sidecar-candidate-") as directory:
            root = Path(directory)
            before, _, _ = self.make_repository(root)
            sidecar = root / f"plugins/{PLUGIN_ID}/.xsec-market/releases.json.sig.jws.json"
            sidecar.write_text("refreshed retained release signature\n", encoding="utf-8")
            after = self.commit(root, "refresh one retained sidecar")

            self.assertEqual(
                verifier.verify_retained_sidecar_refresh_candidate(root, before, after),
                {
                    "kind": "retained-sidecar-refresh",
                    "plugin_id": PLUGIN_ID,
                    "sidecar_path": f"plugins/{PLUGIN_ID}/.xsec-market/releases.json.sig.jws.json",
                },
            )

    def test_retained_sidecar_refresh_candidate_rejects_an_unrelated_change(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-retained-sidecar-extra-") as directory:
            root = Path(directory)
            before, _, _ = self.make_repository(root)
            sidecar = root / f"plugins/{PLUGIN_ID}/.xsec-market/releases.json.sig.jws.json"
            sidecar.write_text("refreshed retained release signature\n", encoding="utf-8")
            (root / ".github/workflows/unrelated.yml").parent.mkdir(parents=True)
            (root / ".github/workflows/unrelated.yml").write_text("name: unrelated\n", encoding="utf-8")
            after = self.commit(root, "unsafe sidecar refresh")

            with self.assertRaisesRegex(verifier.PromotionVerificationError, "exactly one releases.json KMS sidecar"):
                verifier.verify_retained_sidecar_refresh_candidate(root, before, after)


if __name__ == "__main__":
    unittest.main()
