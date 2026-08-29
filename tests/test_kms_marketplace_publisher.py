from __future__ import annotations

import base64
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import build_market  # noqa: E402
import kms_marketplace_publisher as publisher  # noqa: E402


REVISION = "a" * 40
TEST_KMS_KID = "historical-test-key"
TEST_KMS_PUBLIC_KEY_X = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
TEST_KMS_PRIVATE_KEY_D = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
TEST_KMS_JWKS = json.dumps(
    {
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": TEST_KMS_PUBLIC_KEY_X,
                "kid": TEST_KMS_KID,
                "alg": "EdDSA",
                "use": "sig",
            }
        ]
    },
    separators=(",", ":"),
).encode("utf-8")

# RFC 8032's first Ed25519 test key, used only to produce deterministic test
# signatures. Production verification deliberately has no private-key input.
NODE_ED25519_SIGN_PROGRAM = f"""
import {{ createPrivateKey, sign }} from "node:crypto";
import {{ readFileSync }} from "node:fs";

const key = createPrivateKey({{
  key: {{
    kty: "OKP",
    crv: "Ed25519",
    x: "{TEST_KMS_PUBLIC_KEY_X}",
    d: "{TEST_KMS_PRIVATE_KEY_D}",
  }},
  format: "jwk",
}});
const signingInput = Buffer.from(readFileSync(0, "utf8"), "base64");
process.stdout.write(sign(null, signingInput, key).toString("base64url"));
"""


def base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def sign_test_ed25519(signing_input: bytes) -> bytes:
    """Sign one JWS input with the public RFC 8032 test fixture key."""

    node = shutil.which("node")
    if node is None:
        raise AssertionError("Node.js is required by the KMS sidecar verifier tests")
    completed = subprocess.run(
        [node, "--input-type=module", "--eval", NODE_ED25519_SIGN_PROGRAM],
        input=base64.b64encode(signing_input),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    return base64.urlsafe_b64decode(completed.stdout + b"=" * (-len(completed.stdout) % 4))


class KmsMarketplacePublisherTests(unittest.TestCase):
    def make_marketplace(self, root: Path) -> list[publisher.MarketplaceDocument]:
        index = {
            "plugins": [
                {"name": "com.example.beta", "source": {"path": "./plugins/com.example.beta"}},
                {"name": "com.example.alpha", "source": {"path": "./plugins/com.example.alpha"}},
            ]
        }
        index_path = root / ".agents" / "plugins" / "marketplace.json"
        index_path.parent.mkdir(parents=True)
        index_path.write_bytes(json.dumps(index, separators=(",", ":")).encode("utf-8"))
        for plugin_id in ("com.example.alpha", "com.example.beta"):
            release = root / "plugins" / plugin_id / ".xsec-market" / "releases.json"
            release.parent.mkdir(parents=True)
            release.write_bytes(f'{{"pluginId":"{plugin_id}"}}'.encode("utf-8"))
        return publisher.marketplace_documents(root)

    def broker_response(
        self,
        document: publisher.MarketplaceDocument,
        *,
        issuer_id: str = publisher.OFFICIAL_MARKETPLACE_KMS_ISSUER_ID,
        issuer_url: str = publisher.OFFICIAL_MARKETPLACE_KMS_ISSUER_URL,
        source_revision: str = REVISION,
        issued_at: int | None = None,
    ) -> bytes:
        envelope = {
            "schema_version": 1,
            "purpose": document.purpose,
            "subject": document.subject,
            "content_sha256": hashlib.sha256(document.path.read_bytes()).hexdigest(),
            "source_revision": source_revision,
            "issued_at": int(time.time()) if issued_at is None else issued_at,
        }
        envelope_bytes = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
        protected = base64url(json.dumps({
            "alg": "EdDSA",
            "kid": "test-key",
            "iss": publisher.OFFICIAL_MARKETPLACE_KMS_ISSUER_URL,
        }, separators=(",", ":")).encode("utf-8"))
        return json.dumps(
            {
                "ok": True,
                "data": {
                    "signed_document": {
                        "schema_version": 1,
                        "issuer_id": issuer_id,
                        "issuer_url": issuer_url,
                        "envelope_b64": base64url(envelope_bytes),
                        "jws": {"protected": protected, "payload": base64url(envelope_bytes), "signature": base64url(b"s" * 64)},
                    }
                },
            },
            separators=(",", ":"),
        ).encode("utf-8")

    def signed_historical_sidecar(
        self,
        document: publisher.MarketplaceDocument,
        *,
        detached: bool = False,
    ) -> bytes:
        """Build a real, historical KMS sidecar without a network request."""

        envelope = {
            "schema_version": 1,
            "purpose": document.purpose,
            "subject": document.subject,
            "content_sha256": hashlib.sha256(document.path.read_bytes()).hexdigest(),
            "source_revision": REVISION,
            "issued_at": 1_700_000_000,
        }
        envelope_bytes = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
        header: dict[str, object] = {
            "alg": "EdDSA",
            "kid": TEST_KMS_KID,
            "iss": publisher.OFFICIAL_MARKETPLACE_KMS_ISSUER_URL,
        }
        if detached:
            header.update({"b64": False, "crit": ["b64"]})
        protected = base64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        payload = "" if detached else base64url(envelope_bytes)
        signing_payload = envelope_bytes if detached else payload.encode("ascii")
        signature = sign_test_ed25519(protected.encode("ascii") + b"." + signing_payload)
        return json.dumps(
            {
                "schema_version": 1,
                "envelope_b64": base64url(envelope_bytes),
                "jws": {
                    "protected": protected,
                    "payload": payload,
                    "signature": base64url(signature),
                },
            },
            separators=(",", ":"),
        ).encode("utf-8")

    def test_retained_historical_sidecar_requires_a_valid_issuer_signature(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-kms-history-") as directory:
            document = self.make_marketplace(Path(directory))[0]
            sidecar = self.signed_historical_sidecar(document)
            self.assertEqual(
                publisher.verify_historical_sidecar_signature(
                    sidecar,
                    document,
                    now=1_700_000_001,
                    jwks_bytes=TEST_KMS_JWKS,
                ),
                REVISION,
            )

            forged = json.loads(sidecar)
            forged["jws"]["signature"] = base64url(b"f" * 64)
            with self.assertRaisesRegex(
                publisher.MarketplaceKmsPublisherError,
                "signature verification failed",
            ):
                publisher.verify_historical_sidecar_signature(
                    json.dumps(forged, separators=(",", ":")).encode("utf-8"),
                    document,
                    now=1_700_000_001,
                    jwks_bytes=TEST_KMS_JWKS,
                )

    def test_retained_historical_sidecar_verifies_detached_rfc_7797_jws(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-kms-history-") as directory:
            document = self.make_marketplace(Path(directory))[0]
            self.assertEqual(
                publisher.verify_historical_sidecar_signature(
                    self.signed_historical_sidecar(document, detached=True),
                    document,
                    now=1_700_000_001,
                    jwks_bytes=TEST_KMS_JWKS,
                ),
                REVISION,
            )

    def test_pinned_issuer_jwks_rejects_unknown_duplicate_and_malformed_keys(self) -> None:
        self.assertEqual(
            publisher.pinned_issuer_ed25519_key(TEST_KMS_JWKS, TEST_KMS_KID),
            TEST_KMS_PUBLIC_KEY_X,
        )
        with self.assertRaisesRegex(publisher.MarketplaceKmsPublisherError, "not published"):
            publisher.pinned_issuer_ed25519_key(TEST_KMS_JWKS, "unknown-key")

        duplicate = json.loads(TEST_KMS_JWKS)
        duplicate["keys"].append(dict(duplicate["keys"][0]))
        with self.assertRaisesRegex(publisher.MarketplaceKmsPublisherError, "duplicate key id"):
            publisher.pinned_issuer_ed25519_key(
                json.dumps(duplicate, separators=(",", ":")).encode("utf-8"),
                TEST_KMS_KID,
            )

        malformed = json.loads(TEST_KMS_JWKS)
        malformed["keys"][0]["x"] = base64url(b"x" * 31)
        with self.assertRaisesRegex(publisher.MarketplaceKmsPublisherError, "32-byte Ed25519 key"):
            publisher.pinned_issuer_ed25519_key(
                json.dumps(malformed, separators=(",", ":")).encode("utf-8"),
                TEST_KMS_KID,
            )

    def test_publisher_writes_only_desktop_sidecar_schema_for_every_document(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-kms-marketplace-") as directory:
            root = Path(directory)
            documents = self.make_marketplace(root)
            requested: list[tuple[str, str]] = []

            def sign(document: publisher.MarketplaceDocument) -> bytes:
                requested.append((document.purpose, document.subject))
                return self.broker_response(document)

            written = publisher.publish_sidecars(root, REVISION, sign)
            self.assertEqual(len(written), 3)
            self.assertEqual(
                requested,
                [
                    ("xsec.plugin-marketplace.index", ".agents/plugins/marketplace.json"),
                    ("xsec.plugin-marketplace.release", "plugins/com.example.alpha/.xsec-market/releases.json"),
                    ("xsec.plugin-marketplace.release", "plugins/com.example.beta/.xsec-market/releases.json"),
                ],
            )
            for sidecar_path in written:
                sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
                self.assertEqual(set(sidecar), {"schema_version", "envelope_b64", "jws"})
                self.assertNotIn("issuer_id", sidecar)
                self.assertNotIn("issuer_url", sidecar)
            self.assertEqual(publisher.validate_published_sidecars(root, REVISION), written)

    def test_retained_release_refresh_signs_only_the_selected_current_release_document(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-kms-retained-release-refresh-") as directory:
            root = Path(directory)
            documents = self.make_marketplace(root)
            selected = publisher.retained_release_document(root, "com.example.beta")
            self.assertEqual(
                selected.subject,
                "plugins/com.example.beta/.xsec-market/releases.json",
            )
            self.assertEqual(selected.purpose, "xsec.plugin-marketplace.release")

            requested: list[str] = []

            def sign(document: publisher.MarketplaceDocument) -> bytes:
                requested.append(document.subject)
                return self.broker_response(document)

            written = publisher.publish_documents([selected], REVISION, sign)
            self.assertEqual(requested, [selected.subject])
            self.assertEqual(written, [publisher.sidecar_path_for(selected)])
            self.assertEqual(publisher.validate_documents([selected], REVISION), written)
            self.assertFalse(publisher.sidecar_path_for(documents[0]).exists())
            alpha = publisher.retained_release_document(root, "com.example.alpha")
            self.assertFalse(publisher.sidecar_path_for(alpha).exists())

    def test_retained_release_refresh_rejects_non_marketplace_or_unsafe_plugin_ids(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-kms-retained-release-refresh-") as directory:
            root = Path(directory)
            self.make_marketplace(root)
            for plugin_id, expected in (
                ("com.example.missing", "current Marketplace release document"),
                ("../com.example.alpha", "plugin ID is unsafe"),
                ("con", "plugin ID is unsafe"),
            ):
                with self.subTest(plugin_id=plugin_id):
                    with self.assertRaisesRegex(publisher.MarketplaceKmsPublisherError, expected):
                        publisher.retained_release_document(root, plugin_id)

    def test_cli_can_cryptographically_verify_one_retained_release_sidecar_without_oidc(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-kms-retained-release-verify-") as directory:
            root = Path(directory)
            self.make_marketplace(root)
            document = publisher.retained_release_document(root, "com.example.beta")
            publisher.sidecar_path_for(document).write_bytes(self.signed_historical_sidecar(document))
            with patch.object(publisher, "download_pinned_issuer_jwks", return_value=TEST_KMS_JWKS), patch.object(
                sys,
                "argv",
                [
                    "kms_marketplace_publisher.py",
                    "--root",
                    str(root),
                    "--retained-release-plugin-id",
                    "com.example.beta",
                    "--verify-retained-release-signature",
                ],
            ):
                self.assertIsNone(publisher.main())

    def test_cli_authenticates_every_active_sidecar_and_requires_one_source_revision(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-kms-active-release-verify-") as directory:
            root = Path(directory)
            documents = self.make_marketplace(root)
            for document in documents:
                publisher.sidecar_path_for(document).write_bytes(self.signed_historical_sidecar(document))
            with patch.object(publisher, "download_pinned_issuer_jwks", return_value=TEST_KMS_JWKS), patch.object(
                sys,
                "argv",
                ["kms_marketplace_publisher.py", "--root", str(root), "--verify-active-marketplace-signatures"],
            ), patch("sys.stdout", new_callable=StringIO) as output:
                self.assertIsNone(publisher.main())
            self.assertEqual(json.loads(output.getvalue()), {"documents": len(documents), "source_revision": REVISION})

    def test_publisher_signs_external_factory_provenance_in_a_separate_fixed_proof_path(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-kms-factory-provenance-") as directory:
            root = Path(directory)
            self.make_marketplace(root)
            evidence = root / ".xsec-factory" / "official-publications" / "com.example.alpha.json"
            evidence.parent.mkdir(parents=True)
            evidence.write_bytes(b'{"schemaVersion":1,"pluginId":"com.example.alpha","events":[]}\n')

            documents = publisher.marketplace_documents(root)
            provenance = next(
                document for document in documents
                if document.purpose == publisher.OFFICIAL_PUBLICATION_PROVENANCE_PURPOSE
            )
            self.assertEqual(
                provenance.subject,
                ".xsec-factory/official-publications/com.example.alpha.json",
            )
            self.assertEqual(
                publisher.sidecar_path_for(provenance),
                root / ".xsec-factory" / "official-publication-proofs" / "com.example.alpha.json",
            )

            written = publisher.publish_sidecars(root, REVISION, self.broker_response)
            self.assertIn(publisher.sidecar_path_for(provenance), written)
            self.assertEqual(publisher.validate_published_sidecars(root, REVISION), written)

    def test_publisher_signs_first_party_adoption_in_its_own_fixed_proof_path(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-kms-first-party-adoption-") as directory:
            root = Path(directory)
            self.make_marketplace(root)
            adoption = root / ".xsec-factory" / "official-adoptions" / "com.xsec.workspace.sub-agent.json"
            adoption.parent.mkdir(parents=True)
            adoption.write_bytes(b'{"schemaVersion":1,"pluginId":"com.xsec.workspace.sub-agent"}\n')

            documents = publisher.marketplace_documents(root)
            provenance = next(
                document for document in documents
                if document.purpose == publisher.OFFICIAL_ADOPTION_PROVENANCE_PURPOSE
            )
            self.assertEqual(provenance.subject, ".xsec-factory/official-adoptions/com.xsec.workspace.sub-agent.json")
            self.assertEqual(
                publisher.sidecar_path_for(provenance),
                root / ".xsec-factory" / "official-adoption-proofs" / "com.xsec.workspace.sub-agent.json",
            )

            written = publisher.publish_sidecars(root, REVISION, self.broker_response)
            self.assertIn(publisher.sidecar_path_for(provenance), written)
            self.assertEqual(publisher.validate_published_sidecars(root, REVISION), written)

    def test_publisher_signs_factory_status_in_its_own_fixed_proof_path(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-kms-factory-status-") as directory:
            root = Path(directory)
            self.make_marketplace(root)
            status = root / ".xsec-factory" / "official-status" / "com.example.alpha.json"
            status.parent.mkdir(parents=True)
            status.write_bytes(b'{"schemaVersion":1,"pluginId":"com.example.alpha"}\n')

            documents = publisher.marketplace_documents(root)
            status_document = next(
                document for document in documents if document.purpose == publisher.OFFICIAL_STATUS_PURPOSE
            )
            self.assertEqual(status_document.subject, ".xsec-factory/official-status/com.example.alpha.json")
            self.assertEqual(
                publisher.sidecar_path_for(status_document),
                root / ".xsec-factory" / "official-status-proofs" / "com.example.alpha.json",
            )

            written = publisher.publish_sidecars(root, REVISION, self.broker_response)
            self.assertIn(publisher.sidecar_path_for(status_document), written)
            self.assertEqual(publisher.validate_published_sidecars(root, REVISION), written)

    def test_factory_status_proof_without_its_status_document_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-kms-orphan-status-proof-") as directory:
            root = Path(directory)
            self.make_marketplace(root)
            proof = root / ".xsec-factory" / "official-status-proofs" / "com.example.alpha.json"
            proof.parent.mkdir(parents=True)
            proof.write_text("orphan\n", encoding="utf-8")

            with self.assertRaisesRegex(publisher.MarketplaceKmsPublisherError, "status proof directory"):
                publisher.marketplace_documents(root)

    def test_official_factory_provenance_rejects_windows_device_plugin_ids(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-kms-factory-provenance-id-") as directory:
            root = Path(directory)
            for plugin_id in ("con", "nul", "lpt1", "com1.foo"):
                with self.subTest(plugin_id=plugin_id):
                    with self.assertRaisesRegex(publisher.MarketplaceKmsPublisherError, "plugin ID is unsafe"):
                        publisher.official_publication_provenance_document(root, plugin_id)

    def test_unexpected_broker_issuer_prevents_every_sidecar_write(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-kms-marketplace-") as directory:
            root = Path(directory)
            documents = self.make_marketplace(root)

            def sign(document: publisher.MarketplaceDocument) -> bytes:
                if document.subject.endswith("com.example.beta/.xsec-market/releases.json"):
                    return self.broker_response(document, issuer_id="00000000-0000-0000-0000-000000000000")
                return self.broker_response(document)

            with self.assertRaisesRegex(publisher.MarketplaceKmsPublisherError, "unexpected marketplace issuer"):
                publisher.publish_sidecars(root, REVISION, sign)
            self.assertFalse(any(root.rglob("*.sig.jws.json")))
            self.assertEqual(len(documents), 3)

    def test_broker_response_must_bind_the_workflow_sha_and_exact_document(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-kms-marketplace-") as directory:
            document = self.make_marketplace(Path(directory))[0]
            response = self.broker_response(document, source_revision="b" * 40)
            with self.assertRaisesRegex(publisher.MarketplaceKmsPublisherError, "source revision"):
                publisher.sidecar_from_broker_response(response, document, REVISION)

    def test_current_main_revision_overrides_stale_event_sha(self) -> None:
        current_main = "b" * 40
        environment = {
            "GITHUB_SHA": REVISION,
            publisher.CURRENT_SOURCE_REVISION_ENV: current_main,
        }
        self.assertEqual(publisher.source_revision_from_environment(environment), current_main)
        self.assertEqual(publisher.source_revision_from_environment({"GITHUB_SHA": REVISION}), REVISION)
        for invalid in ("", "B" * 40, "a" * 39):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(publisher.MarketplaceKmsPublisherError, publisher.CURRENT_SOURCE_REVISION_ENV):
                    publisher.source_revision_from_environment({"GITHUB_SHA": REVISION, publisher.CURRENT_SOURCE_REVISION_ENV: invalid})

    def test_unknown_protected_header_parameters_are_safely_identifiable(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-kms-marketplace-") as directory:
            document = self.make_marketplace(Path(directory))[0]
            response = json.loads(self.broker_response(document))
            header = {"alg": "EdDSA", "kid": "test-key", "b64": False, "crit": ["b64"], "untrusted\nname": True}
            response["data"]["signed_document"]["jws"]["protected"] = base64url(
                json.dumps(header, separators=(",", ":")).encode("utf-8")
            )
            with self.assertRaisesRegex(
                publisher.MarketplaceKmsPublisherError,
                r'unsupported parameters: "untrusted\\nname"',
            ):
                publisher.sidecar_from_broker_response(
                    json.dumps(response, separators=(",", ":")).encode("utf-8"),
                    document,
                    REVISION,
                )

    def test_kms_protected_issuer_must_match_the_pinned_marketplace_issuer(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-kms-marketplace-") as directory:
            document = self.make_marketplace(Path(directory))[0]
            response = json.loads(self.broker_response(document))
            header = {
                "alg": "EdDSA",
                "kid": "test-key",
                "b64": False,
                "crit": ["b64"],
                "iss": "https://kms.vercel.com/not-the-pinned-issuer",
            }
            response["data"]["signed_document"]["jws"]["protected"] = base64url(
                json.dumps(header, separators=(",", ":")).encode("utf-8")
            )
            with self.assertRaisesRegex(
                publisher.MarketplaceKmsPublisherError,
                "protected header issuer does not match the pinned marketplace issuer",
            ):
                publisher.sidecar_from_broker_response(
                    json.dumps(response, separators=(",", ":")).encode("utf-8"),
                    document,
                    REVISION,
                )

    def test_explicit_null_kms_protected_issuer_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-kms-marketplace-") as directory:
            document = self.make_marketplace(Path(directory))[0]
            response = json.loads(self.broker_response(document))
            header = {
                "alg": "EdDSA",
                "kid": "test-key",
                "b64": False,
                "crit": ["b64"],
                "iss": None,
            }
            response["data"]["signed_document"]["jws"]["protected"] = base64url(
                json.dumps(header, separators=(",", ":")).encode("utf-8")
            )
            with self.assertRaisesRegex(
                publisher.MarketplaceKmsPublisherError,
                "protected header issuer does not match the pinned marketplace issuer",
            ):
                publisher.sidecar_from_broker_response(
                    json.dumps(response, separators=(",", ":")).encode("utf-8"),
                    document,
                    REVISION,
                )

    def test_detached_rfc_7797_kms_sidecar_remains_compatible(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-kms-marketplace-") as directory:
            document = self.make_marketplace(Path(directory))[0]
            response = json.loads(self.broker_response(document))
            header = {
                "alg": "EdDSA",
                "kid": "test-key",
                "b64": False,
                "crit": ["b64"],
                "iss": publisher.OFFICIAL_MARKETPLACE_KMS_ISSUER_URL,
            }
            jws = response["data"]["signed_document"]["jws"]
            jws["protected"] = base64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
            jws["payload"] = ""
            publisher.sidecar_from_broker_response(
                json.dumps(response, separators=(",", ":")).encode("utf-8"),
                document,
                REVISION,
            )

    def test_explicit_null_kms_payload_encoding_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-kms-marketplace-") as directory:
            document = self.make_marketplace(Path(directory))[0]
            response = json.loads(self.broker_response(document))
            header = {
                "alg": "EdDSA",
                "kid": "test-key",
                "b64": None,
                "iss": publisher.OFFICIAL_MARKETPLACE_KMS_ISSUER_URL,
            }
            response["data"]["signed_document"]["jws"]["protected"] = base64url(
                json.dumps(header, separators=(",", ":")).encode("utf-8")
            )
            with self.assertRaisesRegex(
                publisher.MarketplaceKmsPublisherError,
                "payload encoding must be standard base64url or RFC 7797 detached",
            ):
                publisher.sidecar_from_broker_response(
                    json.dumps(response, separators=(",", ":")).encode("utf-8"),
                    document,
                    REVISION,
                )

    def test_cloud_request_uses_fixed_broker_and_canonical_standard_base64(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-kms-marketplace-") as directory:
            document = self.make_marketplace(Path(directory))[0]
            with patch.object(publisher, "request_json", return_value=b'{"ok":true,"data":{}}') as request_json:
                publisher.request_cloud_signature(document, "oidc-token", REVISION)
            request = request_json.call_args.args[0]
            self.assertEqual(request.full_url, publisher.PRODUCTION_BROKER_URL)
            self.assertEqual(request.get_header("Authorization"), "Bearer oidc-token")
            payload = json.loads(request.data.decode("utf-8"))
            self.assertEqual(payload["purpose"], document.purpose)
            self.assertEqual(payload["subject"], document.subject)
            self.assertEqual(payload["source_revision"], REVISION)
            self.assertEqual(base64.b64decode(payload["content_b64"], validate=True), document.path.read_bytes())
            self.assertEqual(base64.b64encode(document.path.read_bytes()).decode("ascii"), payload["content_b64"])

    def test_oidc_request_binds_the_fixed_broker_audience(self) -> None:
        environment = {
            "ACTIONS_ID_TOKEN_REQUEST_URL": "https://pipelines.actions.githubusercontent.com/request?job=123",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "runner-token",
        }
        with patch.object(publisher, "request_json", return_value=b'{"value":"broker-oidc"}') as request_json:
            self.assertEqual(publisher.github_oidc_token(environment), "broker-oidc")
        request = request_json.call_args.args[0]
        self.assertIn(f"audience={publisher.BROKER_AUDIENCE}", request.full_url)
        self.assertEqual(request.get_header("Authorization"), "Bearer runner-token")

    def test_oidc_request_rejects_a_non_github_actions_url_before_sending_runner_token(self) -> None:
        environment = {
            "ACTIONS_ID_TOKEN_REQUEST_URL": "https://actions.githubusercontent.com.attacker.invalid/request?job=123",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "runner-token",
        }
        with patch.object(publisher, "request_json") as request_json:
            with self.assertRaisesRegex(publisher.MarketplaceKmsPublisherError, "GitHub Actions HTTPS endpoint"):
                publisher.github_oidc_token(environment)
        request_json.assert_not_called()

    def test_raw_official_signing_key_path_is_removed_and_clean_deletes_only_stale_sidecars(self) -> None:
        for path in (
            SCRIPTS / "build_market.py",
            SCRIPTS / "validate_market.py",
            ROOT / ".github" / "workflows" / "publish.yml",
            ROOT / "README.md",
        ):
            self.assertNotIn("XSEC_MARKETPLACE_SIGNING_KEY_B64", path.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory(prefix="xsec-kms-clean-") as directory:
            root = Path(directory)
            marketplace = root / ".agents" / "plugins" / "marketplace.json"
            release = root / "plugins" / "com.example" / ".xsec-market" / "releases.json"
            marketplace.parent.mkdir(parents=True)
            release.parent.mkdir(parents=True)
            marketplace.write_text(
                json.dumps({"plugins": [{"source": {"path": "./plugins/com.example"}}]}),
                encoding="utf-8",
            )
            release.write_text("{}", encoding="utf-8")
            for document in (marketplace, release):
                document.with_name(document.name + ".sig").write_text("legacy", encoding="utf-8")
                document.with_name(document.name + ".sig.jws.json").write_text("stale", encoding="utf-8")
            build_market.clean_generated_output(root)
            for suffix in (".sig", ".sig.jws.json"):
                self.assertFalse(marketplace.with_name(marketplace.name + suffix).exists())
                self.assertFalse(release.with_name(release.name + suffix).exists())
            self.assertTrue(release.exists())

    def test_publish_workflow_requires_protected_main_oidc_and_desktop_smoke_dispatch(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")
        validation_workflow = (ROOT / ".github" / "workflows" / "validate.yml").read_text(encoding="utf-8")
        dispatcher = (ROOT / ".github" / "workflows" / "dispatch-reviewed-marketplace-smoke.yml").read_text(encoding="utf-8")
        merge_guard = (ROOT / ".github" / "workflows" / "verify-generated-marketplace-publication.yml").read_text(encoding="utf-8")
        self.assertIn("actions: write", workflow)
        self.assertIn("id-token: write", workflow)
        self.assertIn("pull-requests: write", workflow)
        self.assertIn("actions/setup-node@v4", workflow)
        self.assertIn('node-version: "24"', workflow)
        self.assertIn("actions/setup-node@v4", validation_workflow)
        self.assertIn('node-version: "24"', validation_workflow)
        self.assertIn("fetch-depth: 0", validation_workflow)
        self.assertIn("Materialize trusted pre-change Factory baseline", validation_workflow)
        self.assertIn("PULL_REQUEST_BASE_SHA", validation_workflow)
        self.assertIn("PUSH_BEFORE_SHA", validation_workflow)
        self.assertIn("git worktree add --detach", validation_workflow)
        self.assertIn("--baseline-root", validation_workflow)
        self.assertIn("environment: production", workflow)
        self.assertIn("github.ref_protected", workflow)
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("XSEC_MARKETPLACE_PUBLISH_TOKEN: ${{ secrets.XSEC_MARKETPLACE_PUBLISH_TOKEN }}", workflow)
        self.assertIn("actions/create-github-app-token@v2", workflow)
        self.assertIn("permission-contents: read", workflow)
        self.assertNotIn("GH_TOKEN: ${{ github.token }}", workflow)
        self.assertIn("token: ${{ secrets.XSEC_MARKETPLACE_PUBLISH_TOKEN }}", workflow)
        self.assertIn("ref: refs/heads/main", workflow)
        self.assertIn("Check out current protected main after acquiring the publication slot", workflow)
        self.assertIn("id: current-main", workflow)
        self.assertIn('source_revision="$(git rev-parse HEAD)"', workflow)
        self.assertIn('git rev-parse origin/main', workflow)
        self.assertNotIn("require_publish_token:", workflow)
        self.assertIn("needs: enforce-publish-ref", workflow)
        self.assertNotIn("needs.require_publish_token.result == 'success'", workflow)
        self.assertIn("classify-generated-main-change", workflow)
        self.assertIn("verify_merged_stable_promotion.py", workflow)
        self.assertIn("--verify-active-marketplace-signatures", workflow)
        self.assertIn("Refuse to sign while any generated Factory PR awaits review", workflow)
        self.assertIn("Skip a no-op Factory publication without KMS or dispatch", workflow)
        self.assertIn('sidecar_paths=()', workflow)
        self.assertIn("only_cleaned_sidecars=true", workflow)
        self.assertIn('git diff --name-status -- .agents/plugins plugins .xsec-factory', workflow)
        self.assertIn('[ "$change" = "D" ]', workflow)
        self.assertIn('git restore --source=HEAD --worktree -- "${sidecar_paths[@]}"', workflow)
        self.assertIn("only tracked *deletions* of the exact active", workflow)
        self.assertNotIn("github.event.head_commit.message", workflow)
        self.assertIn("python scripts/kms_marketplace_publisher.py --root .", workflow)
        self.assertIn("python scripts/kms_marketplace_publisher.py --root . --validate-only", workflow)
        self.assertNotIn("XSEC_MARKETPLACE_SIGNING_KEY_B64", workflow)
        # Keep the reviewed post-merge sender in lockstep with Desktop's repository_dispatch
        # receiver. Desktop accepts only the official source repository/ref,
        # then proves the protected source SHA is an ancestor of the generated
        # immutable marketplace commit before it constructs its own raw URL.
        self.assertIn('event_type:"xsec_official_marketplace_published"', dispatcher)
        self.assertIn("source_repository:$source_repository", dispatcher)
        self.assertIn("source_ref:$source_ref", dispatcher)
        self.assertIn("source_sha:$source_sha", dispatcher)
        self.assertIn("marketplace_revision:$marketplace_revision", dispatcher)
        self.assertIn("channel:$channel", dispatcher)
        self.assertIn('--arg source_repository "$GITHUB_REPOSITORY"', dispatcher)
        self.assertIn('--arg source_ref "refs/heads/main"', dispatcher)
        self.assertIn('XSEC_MARKETPLACE_SOURCE_REVISION: ${{ steps.current-main.outputs.source_revision }}', workflow)
        self.assertIn('--arg source_sha "$SOURCE_SHA"', dispatcher)
        self.assertIn("Require the merged generated PR, source gate, and completed Codex review", dispatcher)
        self.assertIn("unresolved Codex review threads", dispatcher)
        self.assertIn("Revalidate each registered source branch at the reviewed merge boundary", dispatcher)
        self.assertIn("merge_group:", merge_guard)
        self.assertIn("Reject a generated PR whose registered source branch advanced during review", merge_guard)
        self.assertNotIn('event_type:"xsec_marketplace_smoke"', workflow)
        self.assertNotIn("marketplace_public_key_b64", workflow)
        self.assertNotIn("expected_default_plugin_ids", workflow)
        self.assertIn("git add -A .agents/plugins plugins", workflow)
        self.assertIn('gh workflow run validate.yml --ref "$branch"', workflow)
        self.assertIn("--event workflow_dispatch", workflow)
        self.assertNotIn('"repos/${GITHUB_REPOSITORY}/pulls/${pull_number}/merge"', workflow)
        self.assertIn("review_body=\"@codex review\"$'\\n\\n'", workflow)
        self.assertIn('echo "pending_review=true"', workflow)
        self.assertIn("This workflow intentionally does not merge this PR", workflow)
        self.assertIn('pull_number="$(gh pr view "$pull_url" --json number --jq .number)"', workflow)
        # The protected workflow selects a title/prefix based on whether the
        # request is built-in or an approved external Factory publication.
        # Keep the legacy built-in values and ensure the dynamic values are
        # the ones handed to the generated PR and branch name.
        self.assertIn('echo "commit_title=chore: publish marketplace beta release"', workflow)
        self.assertIn('COMMIT_TITLE: ${{ steps.request.outputs.commit_title }}', workflow)
        self.assertIn('branch="xsec-marketplace/${BRANCH_PREFIX}-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"', workflow)
        self.assertIn("workflow_dispatch:", validation_workflow)

    def test_stable_promotion_workflow_only_moves_an_existing_pointer(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "promote-stable.yml").read_text(encoding="utf-8")
        publish_workflow = (ROOT / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("plugin_id:", workflow)
        self.assertIn("release_id:", workflow)
        self.assertNotIn("push:", workflow)
        self.assertIn("github.ref_protected", workflow)
        self.assertIn("environment: production", workflow)
        self.assertIn("python scripts/promote_release.py", workflow)
        self.assertNotIn("scripts/build_market.py", workflow)
        self.assertIn("chore: promote marketplace stable release", workflow)
        # Both workflows write the same signed index and generated PRs; do
        # not allow an otherwise valid promotion to race beta publication.
        self.assertIn("group: xsec-marketplace-publish-main", workflow)
        self.assertIn("ref: refs/heads/main", workflow)
        self.assertIn("Check out current protected main after acquiring the publication slot", workflow)
        self.assertIn("id: current-main", workflow)
        self.assertIn('source_revision="$(git rev-parse HEAD)"', workflow)
        self.assertIn('git rev-parse origin/main', workflow)
        self.assertIn('XSEC_MARKETPLACE_SOURCE_REVISION: ${{ steps.current-main.outputs.source_revision }}', workflow)
        self.assertNotIn('"repos/${GITHUB_REPOSITORY}/pulls/${pull_number}/merge"', workflow)
        self.assertIn("review_body=\"@codex review\"$'\\n\\n'", workflow)
        self.assertIn("This workflow intentionally does not merge this PR", workflow)
        self.assertIn("Refuse to sign while any generated Factory PR awaits review", workflow)
        self.assertNotIn("steps.publish.outputs.published == 'true'", workflow)
        self.assertIn("group: xsec-marketplace-publish-main", publish_workflow)
        self.assertIn("chore: publish marketplace beta release", publish_workflow)
        self.assertIn("chore: promote external marketplace stable release", publish_workflow)


if __name__ == "__main__":
    unittest.main()
