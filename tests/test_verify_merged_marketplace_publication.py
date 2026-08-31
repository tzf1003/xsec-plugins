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
SNAPSHOT_ROOT = build_market.SNAPSHOT_ROOT_RELATIVE_PATH.as_posix()


def snapshot_path(plugin_id: str) -> str:
    return f"{SNAPSHOT_ROOT}/{plugin_id}"


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
            paths.append(f"{snapshot_path(PLUGIN_ID)}/.xsec-market/releases.json.sig.jws.json")
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
            root / snapshot_path(PLUGIN_ID) / ".xsec-market/releases.json",
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

    def write_inflight_beta_status(
        self,
        root: Path,
        beta: dict[str, object],
        *,
        beta_sha: str = "a" * 40,
        main_gate_sha: str = "b" * 40,
        state: str = "waiting_for_smoke",
        stable_release_id: str | None = None,
    ) -> None:
        write_json(
            root / f".xsec-factory/official-status/{PLUGIN_ID}.json",
            {
                "schemaVersion": 1,
                "pluginId": PLUGIN_ID,
                "trustTier": "external",
                "source": {
                    "repository": "example/plugin",
                    "path": f"plugins/{PLUGIN_ID}",
                    "refs": {"beta": "refs/heads/beta", "stable": "refs/heads/main"},
                    "betaSha": beta_sha,
                    "stableSha": None,
                    "mainGateSha": main_gate_sha,
                },
                "release": {"betaReleaseId": beta["releaseId"], "stableReleaseId": stable_release_id},
                "publication": {
                    "state": state,
                    "deliveryId": "test-delivery",
                    "factoryRunUrl": None,
                    "smokeRunUrl": None,
                    "marketplaceRevision": None,
                },
            },
        )
        status_proof = root / f".xsec-factory/official-status-proofs/{PLUGIN_ID}.json"
        status_proof.parent.mkdir(parents=True, exist_ok=True)
        status_proof.write_text(f"status signature for {main_gate_sha}\n", encoding="utf-8")

    def test_classifies_beta_without_relying_on_the_merge_subject(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-merged-beta-") as directory:
            root = Path(directory)
            before, stable, beta = self.make_repository(root)
            self.write_release(root, [stable, beta], beta=beta["releaseId"], stable=stable["releaseId"])
            (root / ".agents/plugins/marketplace.json.sig.jws.json").write_text("signed beta index\n", encoding="utf-8")
            (root / snapshot_path(PLUGIN_ID) / ".xsec-market/releases.json.sig.jws.json").write_text("signed beta release\n", encoding="utf-8")
            (root / snapshot_path(PLUGIN_ID) / "frontend.js").write_text("export {}\n", encoding="utf-8")
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
            (root / snapshot_path(PLUGIN_ID) / ".xsec-market/releases.json.sig.jws.json").write_text("signed beta release\n", encoding="utf-8")
            (root / snapshot_path(PLUGIN_ID) / "frontend.js").write_text("export {}\n", encoding="utf-8")
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
            self.write_inflight_beta_status(root, beta)
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
                        "main_source": {"repository": "example/plugin", "ref": "refs/heads/main", "sha": "b" * 40},
                    }
                ],
            )

    def test_classifies_stable_pointer_without_rebuilding_release_history(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-merged-stable-") as directory:
            root = Path(directory)
            stable = release("1.0.0", "stable")
            beta = release("1.1.0", "beta")
            self.write_release(root, [stable, beta], beta=beta["releaseId"], stable=stable["releaseId"])
            for path in (".agents/plugins/marketplace.json.sig.jws.json", f"{snapshot_path(PLUGIN_ID)}/.xsec-market/releases.json.sig.jws.json"):
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("{}\n", encoding="utf-8")
            git(root, "init", "--quiet", "--initial-branch=main")
            git(root, "config", "user.name", "Verifier Test")
            git(root, "config", "user.email", "verifier@example.invalid")
            before = self.commit(root, "base")
            self.write_release(root, [stable, beta], beta=beta["releaseId"], stable=beta["releaseId"])
            (root / ".agents/plugins/marketplace.json.sig.jws.json").write_text("signed stable index\n", encoding="utf-8")
            (root / snapshot_path(PLUGIN_ID) / ".xsec-market/releases.json.sig.jws.json").write_text("signed stable release\n", encoding="utf-8")
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
            (root / snapshot_path(PLUGIN_ID) / ".xsec-market/releases.json.sig.jws.json").write_text("signed beta release\n", encoding="utf-8")
            (root / snapshot_path(PLUGIN_ID) / "frontend.js").write_text("export {}\n", encoding="utf-8")
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
            self.write_inflight_beta_status(root, beta)
            after = self.commit(root, "generated beta")

            result = verifier.classify_merged_change(root, before, after)

            self.assertEqual(result["promotions"][0]["source"], {"repository": "example/plugin", "ref": "refs/heads/beta", "sha": "a" * 40})
            self.assertEqual(result["promotions"][0]["main_source"], {"repository": "example/plugin", "ref": "refs/heads/main", "sha": "b" * 40})

    def test_classifies_source_only_registered_beta_without_rewriting_its_release(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-merged-source-only-beta-") as directory:
            root = Path(directory)
            _, stable, beta = self.make_repository(root, registered=True)
            self.write_release(root, [stable, beta], beta=beta["releaseId"], stable=stable["releaseId"])
            write_json(root / ".agents/plugins/marketplace.json", {"plugins": [{"source": {"path": f"./{snapshot_path(PLUGIN_ID)}"}}]})
            (root / ".agents/plugins/marketplace.json.sig.jws.json").write_text("baseline index signature\n", encoding="utf-8")
            (root / snapshot_path(PLUGIN_ID) / ".xsec-market/releases.json.sig.jws.json").write_text(
                "baseline release signature\n", encoding="utf-8"
            )
            before = self.commit(root, "adopted beta release")

            source_sha = "c" * 40
            event = {
                "channel": "beta",
                "releaseId": beta["releaseId"],
                "source": {
                    "repository": "example/plugin",
                    "path": f"plugins/{PLUGIN_ID}",
                    "ref": "refs/heads/beta",
                    "sha": source_sha,
                },
                "artifact": {"sha256": beta["artifacts"][0]["sha256"], "url": beta["artifacts"][0]["url"]},
                "publisher": "factory",
            }
            write_json(root / f".xsec-factory/official-publications/{PLUGIN_ID}.json", {"schemaVersion": 1, "pluginId": PLUGIN_ID, "events": [event]})
            proof = root / f".xsec-factory/official-publication-proofs/{PLUGIN_ID}.json"
            proof.parent.mkdir(parents=True, exist_ok=True)
            proof.write_text("source-only beta provenance signature\n", encoding="utf-8")
            self.write_inflight_beta_status(root, beta, beta_sha=source_sha, main_gate_sha="d" * 40)
            (root / ".agents/plugins/marketplace.json.sig.jws.json").write_text("refreshed index signature\n", encoding="utf-8")
            (root / snapshot_path(PLUGIN_ID) / ".xsec-market/releases.json.sig.jws.json").write_text(
                "refreshed release signature\n", encoding="utf-8"
            )
            after = self.commit(root, "source-only beta cycle")

            expected = {
                "kind": "beta",
                "promotions": [
                    {
                        "plugin_id": PLUGIN_ID,
                        "release_id": beta["releaseId"],
                        "source": {"repository": "example/plugin", "ref": "refs/heads/beta", "sha": source_sha},
                        "main_source": {"repository": "example/plugin", "ref": "refs/heads/main", "sha": "d" * 40},
                    }
                ],
            }
            self.assertEqual(verifier.classify_merged_change(root, before, after), expected)

            (root / f".xsec-factory/official-status-proofs/{PLUGIN_ID}.json").unlink()
            unsigned_after = self.commit(root, "pending source-only beta status")
            with self.assertRaisesRegex(verifier.PromotionVerificationError, "status sidecars"):
                verifier.classify_merged_change(root, before, unsigned_after)
            self.assertEqual(
                verifier.classify_merged_change(
                    root,
                    before,
                    unsigned_after,
                    allow_unsigned_official_status_plugin_id=PLUGIN_ID,
                ),
                expected,
            )

    def test_classifies_no_pointer_registered_beta_when_main_newly_rebuilds_it(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-merged-beta-smoke-ready-") as directory:
            root = Path(directory)
            _, stable, beta = self.make_repository(root, registered=True)
            self.write_release(root, [stable, beta], beta=beta["releaseId"], stable=stable["releaseId"])
            write_json(root / ".agents/plugins/marketplace.json", {"plugins": [{"source": {"path": f"./{snapshot_path(PLUGIN_ID)}"}}]})
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
            proof.write_text("baseline evidence signature\n", encoding="utf-8")
            self.write_inflight_beta_status(
                root, beta, main_gate_sha="c" * 40, state="waiting_for_beta", stable_release_id=stable["releaseId"]
            )
            # A publication-side KMS renewal may refresh another active
            # status proof in the same generated candidate. That proof has no
            # authority to rewrite its status document, but must not strand a
            # legitimate main-gate recheck either.
            other_status = root / ".xsec-factory/official-status/com.example.other.json"
            write_json(other_status, {"schemaVersion": 1, "pluginId": "com.example.other"})
            other_proof = root / ".xsec-factory/official-status-proofs/com.example.other.json"
            other_proof.parent.mkdir(parents=True, exist_ok=True)
            other_proof.write_text("baseline other status signature\n", encoding="utf-8")
            before = self.commit(root, "beta awaits a reproducible main")
            (root / ".agents/plugins/marketplace.json.sig.jws.json").write_text("refreshed index signature\n", encoding="utf-8")
            (root / snapshot_path(PLUGIN_ID) / ".xsec-market/releases.json.sig.jws.json").write_text("refreshed release signature\n", encoding="utf-8")
            proof.write_text("refreshed evidence signature\n", encoding="utf-8")
            self.write_inflight_beta_status(
                root, beta, main_gate_sha="d" * 40, state="waiting_for_smoke", stable_release_id=stable["releaseId"]
            )
            other_proof.write_text("refreshed other status signature\n", encoding="utf-8")
            after = self.commit(root, "main now reproduces existing beta")

            self.assertEqual(
                verifier.classify_merged_change(root, before, after),
                {
                    "kind": "beta-smoke-ready",
                    "promotions": [
                        {
                            "plugin_id": PLUGIN_ID,
                            "release_id": beta["releaseId"],
                            "source": {"repository": "example/plugin", "ref": "refs/heads/beta", "sha": "a" * 40},
                            "main_source": {"repository": "example/plugin", "ref": "refs/heads/main", "sha": "d" * 40},
                        }
                    ],
                },
            )

    def test_classifies_no_pointer_beta_main_gate_rebinds_and_downgrades(self) -> None:
        # A later main event may leave an existing Beta reproducible, leave it
        # non-reproducible, or change either result.  Each outcome must retain
        # the identical immutable Beta tuple while binding a new main head.
        cases = (
            ("waiting_for_beta", "waiting_for_beta"),
            ("waiting_for_smoke", "waiting_for_smoke"),
            ("waiting_for_smoke", "waiting_for_beta"),
        )
        for before_state, after_state in cases:
            with self.subTest(before_state=before_state, after_state=after_state), tempfile.TemporaryDirectory(
                prefix="xsec-merged-beta-smoke-recheck-"
            ) as directory:
                root = Path(directory)
                _, stable, beta = self.make_repository(root, registered=True)
                self.write_release(root, [stable, beta], beta=beta["releaseId"], stable=stable["releaseId"])
                write_json(root / ".agents/plugins/marketplace.json", {"plugins": [{"source": {"path": f"./{snapshot_path(PLUGIN_ID)}"}}]})
                event = {
                    "channel": "beta",
                    "releaseId": beta["releaseId"],
                    "source": {
                        "repository": "example/plugin",
                        "path": f"plugins/{PLUGIN_ID}",
                        "ref": "refs/heads/beta",
                        "sha": "a" * 40,
                    },
                    "artifact": {"sha256": beta["artifacts"][0]["sha256"], "url": beta["artifacts"][0]["url"]},
                    "publisher": "factory",
                }
                write_json(root / f".xsec-factory/official-publications/{PLUGIN_ID}.json", {"schemaVersion": 1, "pluginId": PLUGIN_ID, "events": [event]})
                proof = root / f".xsec-factory/official-publication-proofs/{PLUGIN_ID}.json"
                proof.parent.mkdir(parents=True, exist_ok=True)
                proof.write_text("baseline evidence signature\n", encoding="utf-8")
                self.write_inflight_beta_status(
                    root, beta, main_gate_sha="c" * 40, state=before_state, stable_release_id=stable["releaseId"]
                )
                before = self.commit(root, "previous registered main gate")
                (root / ".agents/plugins/marketplace.json.sig.jws.json").write_text("refreshed index signature\n", encoding="utf-8")
                (root / snapshot_path(PLUGIN_ID) / ".xsec-market/releases.json.sig.jws.json").write_text(
                    "refreshed release signature\n", encoding="utf-8"
                )
                proof.write_text("refreshed evidence signature\n", encoding="utf-8")
                self.write_inflight_beta_status(
                    root, beta, main_gate_sha="d" * 40, state=after_state, stable_release_id=stable["releaseId"]
                )
                after = self.commit(root, "registered main was rechecked")

                self.assertEqual(
                    verifier.classify_merged_change(root, before, after),
                    {
                        "kind": "beta-smoke-ready",
                        "promotions": [
                            {
                                "plugin_id": PLUGIN_ID,
                                "release_id": beta["releaseId"],
                                "source": {"repository": "example/plugin", "ref": "refs/heads/beta", "sha": "a" * 40},
                                "main_source": {"repository": "example/plugin", "ref": "refs/heads/main", "sha": "d" * 40},
                            }
                        ],
                    },
                )

    def test_rejects_no_pointer_beta_smoke_transition_without_a_status_proof_refresh(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-merged-beta-smoke-unsigned-status-") as directory:
            root = Path(directory)
            _, stable, beta = self.make_repository(root, registered=True)
            self.write_release(root, [stable, beta], beta=beta["releaseId"], stable=stable["releaseId"])
            write_json(root / ".agents/plugins/marketplace.json", {"plugins": [{"source": {"path": f"./{snapshot_path(PLUGIN_ID)}"}}]})
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
            proof.write_text("baseline evidence signature\n", encoding="utf-8")
            self.write_inflight_beta_status(root, beta, main_gate_sha="c" * 40, state="waiting_for_beta", stable_release_id=stable["releaseId"])
            before = self.commit(root, "beta awaits a reproducible main")
            (root / ".agents/plugins/marketplace.json.sig.jws.json").write_text("refreshed index signature\n", encoding="utf-8")
            (root / snapshot_path(PLUGIN_ID) / ".xsec-market/releases.json.sig.jws.json").write_text("refreshed release signature\n", encoding="utf-8")
            proof.write_text("refreshed evidence signature\n", encoding="utf-8")
            self.write_inflight_beta_status(root, beta, main_gate_sha="d" * 40, state="waiting_for_smoke", stable_release_id=stable["releaseId"])
            (root / f".xsec-factory/official-status-proofs/{PLUGIN_ID}.json").unlink()
            after = self.commit(root, "unsigned waiting for smoke status")

            with self.assertRaisesRegex(verifier.PromotionVerificationError, "status KMS proof"):
                verifier.classify_merged_change(root, before, after)

    def test_rejects_no_pointer_beta_smoke_transition_with_legacy_marketplace_source_path(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-merged-beta-smoke-legacy-path-") as directory:
            root = Path(directory)
            _, stable, beta = self.make_repository(root, registered=True)
            self.write_release(root, [stable, beta], beta=beta["releaseId"], stable=stable["releaseId"])
            # The Factory Registry uses this value, but Marketplace's public
            # schema deliberately requires the explicit repository-relative
            # form below.  Do not allow a second spelling through this gate.
            write_json(root / ".agents/plugins/marketplace.json", {"plugins": [{"source": {"path": f"plugins/{PLUGIN_ID}"}}]})
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
            proof.write_text("baseline evidence signature\n", encoding="utf-8")
            self.write_inflight_beta_status(
                root, beta, main_gate_sha="c" * 40, state="waiting_for_beta", stable_release_id=stable["releaseId"]
            )
            before = self.commit(root, "beta awaits a reproducible main")
            (root / ".agents/plugins/marketplace.json.sig.jws.json").write_text("refreshed index signature\n", encoding="utf-8")
            (root / snapshot_path(PLUGIN_ID) / ".xsec-market/releases.json.sig.jws.json").write_text(
                "refreshed release signature\n", encoding="utf-8"
            )
            proof.write_text("refreshed evidence signature\n", encoding="utf-8")
            self.write_inflight_beta_status(
                root, beta, main_gate_sha="d" * 40, state="waiting_for_smoke", stable_release_id=stable["releaseId"]
            )
            after = self.commit(root, "unsafe legacy Marketplace source path")

            with self.assertRaisesRegex(verifier.PromotionVerificationError, "Marketplace source path is not canonical"):
                verifier.classify_merged_change(root, before, after)

    def test_rejects_no_pointer_beta_smoke_transition_that_refreshes_an_inactive_release_sidecar(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-merged-beta-smoke-ready-unsafe-") as directory:
            root = Path(directory)
            _, stable, beta = self.make_repository(root, registered=True)
            self.write_release(root, [stable, beta], beta=beta["releaseId"], stable=stable["releaseId"])
            write_json(root / ".agents/plugins/marketplace.json", {"plugins": [{"source": {"path": f"./{snapshot_path(PLUGIN_ID)}"}}]})
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
            proof.write_text("baseline evidence signature\n", encoding="utf-8")
            self.write_inflight_beta_status(
                root, beta, main_gate_sha="c" * 40, state="waiting_for_beta", stable_release_id=stable["releaseId"]
            )
            before = self.commit(root, "beta awaits a reproducible main")
            (root / ".agents/plugins/marketplace.json.sig.jws.json").write_text("refreshed index signature\n", encoding="utf-8")
            (root / snapshot_path(PLUGIN_ID) / ".xsec-market/releases.json.sig.jws.json").write_text("refreshed release signature\n", encoding="utf-8")
            proof.write_text("refreshed evidence signature\n", encoding="utf-8")
            self.write_inflight_beta_status(
                root, beta, main_gate_sha="d" * 40, state="waiting_for_smoke", stable_release_id=stable["releaseId"]
            )
            unrelated = root / ".xsec-factory/snapshots/com.example.disabled/.xsec-market/releases.json.sig.jws.json"
            unrelated.parent.mkdir(parents=True, exist_ok=True)
            unrelated.write_text("unrelated retained release signature\n", encoding="utf-8")
            after = self.commit(root, "unsafe inactive release sidecar beside beta smoke")

            with self.assertRaisesRegex(verifier.PromotionVerificationError, "no-pointer Factory change is not a safe"):
                verifier.classify_merged_change(root, before, after)

    def test_rejects_release_delta_with_an_unrelated_workflow_edit(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-merged-unsafe-") as directory:
            root = Path(directory)
            before, stable, beta = self.make_repository(root)
            self.write_release(root, [stable, beta], beta=beta["releaseId"], stable=stable["releaseId"])
            (root / ".agents/plugins/marketplace.json.sig.jws.json").write_text("signed beta index\n", encoding="utf-8")
            (root / snapshot_path(PLUGIN_ID) / ".xsec-market/releases.json.sig.jws.json").write_text("signed beta release\n", encoding="utf-8")
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
            (root / snapshot_path(PLUGIN_ID) / ".xsec-market/releases.json.sig.jws.json").write_text("refreshed release\n", encoding="utf-8")
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

    def test_first_party_adoption_staging_candidate_adds_only_the_unsigned_adoption_document(self) -> None:
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
            write_json(root / f".xsec-factory/official-adoptions/{PLUGIN_ID}.json", {"pluginId": PLUGIN_ID})
            after = self.commit(root, "stage one first-party adoption assertion")

            self.assertEqual(
                verifier.verify_first_party_adoption_candidate(root, before, after),
                {
                    "kind": "adoption-stage",
                    "plugin_id": PLUGIN_ID,
                    "adoption_path": f".xsec-factory/official-adoptions/{PLUGIN_ID}.json",
                },
            )

    def test_first_party_adoption_activation_candidate_adds_only_its_sidecar_and_activates_registry_entry(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-first-party-adoption-activation-") as directory:
            root = Path(directory)
            registry = {
                "schemaVersion": 2,
                "plugins": [
                    {"pluginId": PLUGIN_ID, "status": "pending-adoption", "source": {"repository": "example/plugin"}},
                    {"pluginId": "com.example.unchanged", "status": "active"},
                ],
            }
            write_json(root / ".xsec-factory/official-registry.json", registry)
            write_json(root / f".xsec-factory/official-adoptions/{PLUGIN_ID}.json", {"pluginId": PLUGIN_ID})
            git(root, "init", "--quiet", "--initial-branch=main")
            git(root, "config", "user.name", "Verifier Test")
            git(root, "config", "user.email", "verifier@example.invalid")
            before = self.commit(root, "staged first-party adoption assertion")
            registry["plugins"][0]["status"] = "active"
            write_json(root / ".xsec-factory/official-registry.json", registry)
            write_json(root / f".xsec-factory/official-adoption-proofs/{PLUGIN_ID}.json", {"pluginId": PLUGIN_ID})
            after = self.commit(root, "activate one first-party registration")

            self.assertEqual(
                verifier.verify_first_party_adoption_candidate(root, before, after),
                {
                    "kind": "adoption-activation",
                    "plugin_id": PLUGIN_ID,
                    "adoption_path": f".xsec-factory/official-adoptions/{PLUGIN_ID}.json",
                },
            )

    def test_first_party_adoption_staging_candidate_rejects_an_unrelated_change(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-first-party-adoption-extra-") as directory:
            root = Path(directory)
            registry = {"schemaVersion": 2, "plugins": [{"pluginId": PLUGIN_ID, "status": "pending-adoption"}]}
            write_json(root / ".xsec-factory/official-registry.json", registry)
            git(root, "init", "--quiet", "--initial-branch=main")
            git(root, "config", "user.name", "Verifier Test")
            git(root, "config", "user.email", "verifier@example.invalid")
            before = self.commit(root, "pending first-party registration")
            write_json(root / f".xsec-factory/official-adoptions/{PLUGIN_ID}.json", {"pluginId": PLUGIN_ID})
            (root / ".github/workflows/unrelated.yml").parent.mkdir(parents=True)
            (root / ".github/workflows/unrelated.yml").write_text("name: unrelated\n", encoding="utf-8")
            after = self.commit(root, "unsafe first-party adoption staging")

            with self.assertRaisesRegex(verifier.PromotionVerificationError, "unauthorized path set"):
                verifier.verify_first_party_adoption_candidate(root, before, after)

    def test_retained_sidecar_refresh_candidate_allows_one_retained_sidecar_only(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-retained-sidecar-candidate-") as directory:
            root = Path(directory)
            before, _, _ = self.make_repository(root)
            sidecar = root / snapshot_path(PLUGIN_ID) / ".xsec-market/releases.json.sig.jws.json"
            sidecar.write_text("refreshed retained release signature\n", encoding="utf-8")
            after = self.commit(root, "refresh one retained sidecar")

            self.assertEqual(
                verifier.verify_retained_sidecar_refresh_candidate(root, before, after),
                {
                    "kind": "retained-sidecar-refresh",
                    "plugin_id": PLUGIN_ID,
                    "sidecar_path": f"{snapshot_path(PLUGIN_ID)}/.xsec-market/releases.json.sig.jws.json",
                },
            )

    def test_retained_sidecar_refresh_candidate_rejects_an_unrelated_change(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-retained-sidecar-extra-") as directory:
            root = Path(directory)
            before, _, _ = self.make_repository(root)
            sidecar = root / snapshot_path(PLUGIN_ID) / ".xsec-market/releases.json.sig.jws.json"
            sidecar.write_text("refreshed retained release signature\n", encoding="utf-8")
            (root / ".github/workflows/unrelated.yml").parent.mkdir(parents=True)
            (root / ".github/workflows/unrelated.yml").write_text("name: unrelated\n", encoding="utf-8")
            after = self.commit(root, "unsafe sidecar refresh")

            with self.assertRaisesRegex(verifier.PromotionVerificationError, "exactly one releases.json KMS sidecar"):
                verifier.verify_retained_sidecar_refresh_candidate(root, before, after)


if __name__ == "__main__":
    unittest.main()
