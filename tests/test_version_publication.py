from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import build_market
import verify_merged_stable_promotion as verifier

PLUGIN_ID = "io.example.files"
SNAPSHOT = f".xsec-factory/snapshots/{PLUGIN_ID}"
EVIDENCE = f".xsec-factory/official-publications/{PLUGIN_ID}.json"
STATUS = f".xsec-factory/official-status/{PLUGIN_ID}.json"


def git(root: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=root, check=True, capture_output=True, text=True).stdout.strip()


def write(root: Path, path: str, value: object) -> None:
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(value) + "\n")


def commit(root: Path) -> str:
    git(root, "add", ".")
    git(root, "commit", "-qm", "publication boundary")
    return git(root, "rev-parse", "HEAD")


class VersionPublicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="xsec-version-gate-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        git(self.root, "init", "-q", "--initial-branch=main")
        git(self.root, "config", "user.name", "Publication Test")
        git(self.root, "config", "user.email", "test@example.invalid")
        self.source = {"repository": "example/files", "path": ".", "refs": {"beta": "refs/heads/beta", "stable": "refs/heads/main"}}
        entry = {"pluginId": PLUGIN_ID, "trustTier": "external", "source": self.source,
                 "status": "active", "policy": {"installation": "AVAILABLE", "authentication": "ON_INSTALL"}, "category": "Security"}
        write(self.root, verifier.REGISTRY_PATH, {"schemaVersion": 2, "plugins": [entry]})
        write(self.root, verifier.MARKETPLACE_INDEX, {"plugins": []})
        self.before = commit(self.root)

    def publish(self, version: str = "1.0.0") -> dict[str, object]:
        release_path = f"{SNAPSHOT}/.xsec-market/releases.json"
        previous = json.loads((self.root / release_path).read_text()) if (self.root / release_path).exists() else {"releases": []}
        artifact = {"os": "any", "arch": "any", "url": f"artifacts/{version}.xsec-plugin", "sha256": hashlib.sha256(version.encode()).hexdigest()}
        engines = {"xsec": ">=0.1.0", "pluginApi": "^1.4.0"}
        record = {"version": version, "engines": engines, "artifacts": [artifact], "releaseId": build_market.release_id(version, engines, [artifact])}
        write(self.root, release_path, {"schemaVersion": 2, "pluginId": PLUGIN_ID,
              "releases": [*previous["releases"], record], "channels": {"beta": {"releaseId": record["releaseId"]}, "stable": None}})
        write(self.root, verifier.MARKETPLACE_INDEX, {"plugins": [{"name": PLUGIN_ID, "source": {"path": f"./{SNAPSHOT}"}}]})
        events = json.loads((self.root / EVIDENCE).read_text())["events"] if (self.root / EVIDENCE).exists() else []
        events.append({"channel": "beta", "releaseId": record["releaseId"], "source": {
            "repository": self.source["repository"], "path": ".", "ref": "refs/heads/beta", "sha": self.before}, "artifact": artifact, "publisher": "factory"})
        write(self.root, EVIDENCE, {"schemaVersion": 1, "pluginId": PLUGIN_ID, "events": events})
        write(self.root, STATUS, {"schemaVersion": 1, "pluginId": PLUGIN_ID, "trustTier": "external",
            "source": {**self.source, "betaSha": self.before, "mainGateSha": self.before, "stableSha": None},
            "release": {"betaReleaseId": record["releaseId"], "stableReleaseId": None},
            "publication": {"state": "waiting_for_smoke", "smokeRunUrl": None, "marketplaceRevision": None}})
        return record

    def classify(self) -> dict[str, object]:
        return verifier.classify_merged_change(self.root, self.before, commit(self.root))

    def test_registered_version_binds_both_source_refs(self) -> None:
        record = self.publish()
        result = self.classify()
        self.assertEqual(result["kind"], "version")
        self.assertEqual(result["promotions"][0]["release_id"], record["releaseId"])
        self.assertEqual(result["promotions"][0]["main_source"]["sha"], self.before)

    def test_source_repository_mismatch_is_rejected(self) -> None:
        self.publish()
        evidence = json.loads((self.root / EVIDENCE).read_text())
        evidence["events"][0]["source"]["repository"] = "example/other"
        write(self.root, EVIDENCE, evidence)
        with self.assertRaisesRegex(ValueError, "exact beta source event"):
            self.classify()

    def test_unrelated_mutation_is_rejected(self) -> None:
        self.publish()
        write(self.root, "scripts/unrelated.json", {})
        with self.assertRaisesRegex(ValueError, "unauthorized path"):
            self.classify()

    def test_immutable_history_rewrite_is_rejected(self) -> None:
        self.publish()
        self.before = commit(self.root)
        self.publish("1.1.0")
        path = f"{SNAPSHOT}/.xsec-market/releases.json"
        document = json.loads((self.root / path).read_text())
        document["releases"][0]["artifacts"][0]["url"] = "artifacts/replaced.xsec-plugin"
        write(self.root, path, document)
        with self.assertRaisesRegex(ValueError, "rewrote immutable release history"):
            self.classify()

    def test_duplicate_semver_is_rejected(self) -> None:
        self.publish()
        self.before = commit(self.root)
        self.publish()
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.classify()
