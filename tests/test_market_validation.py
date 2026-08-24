from __future__ import annotations

import base64
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from marketplace_contract import OFFICIAL_MARKETPLACE_PUBLIC_KEY_B64  # noqa: E402
from validate_market import (  # noqa: E402
    MarketplaceValidationError,
    validate_archive,
    validate_published,
    validate_signing_key,
    validate_source,
)


class MarketplaceValidationTests(unittest.TestCase):
    maxDiff = None

    def build_marketplace(self, destination: Path, *, signed: bool) -> tuple[dict[str, str], str | None]:
        environment = os.environ.copy()
        environment.pop("XSEC_MARKETPLACE_SIGNING_KEY_B64", None)
        command = [
            sys.executable,
            "scripts/build_market.py",
            "--clean",
            "--output-root",
            str(destination),
        ]
        if not signed:
            command.insert(2, "--allow-unsigned")
            subprocess.run(command, cwd=ROOT, env=environment, check=True, capture_output=True, text=True)
            return environment, None

        # Test-only deterministic seed. It never leaves this child process or
        # test output and is unrelated to the marketplace production secret.
        environment["XSEC_MARKETPLACE_SIGNING_KEY_B64"] = base64.b64encode(b"\x13" * 32).decode("ascii")
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        public_key = Ed25519PrivateKey.from_private_bytes(b"\x13" * 32).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        subprocess.run(command, cwd=ROOT, env=environment, check=True, capture_output=True, text=True)
        return environment, base64.b64encode(public_key).decode("ascii")

    def test_source_gate_accepts_disposable_unsigned_output(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-source-test-") as directory:
            output = Path(directory) / "marketplace"
            self.build_marketplace(output, signed=False)
            validate_source(ROOT, output)

    def test_published_gate_accepts_signed_artifacts_and_rejects_tampering(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-published-test-") as directory:
            output = Path(directory) / "marketplace"
            _, public_key = self.build_marketplace(output, signed=True)
            assert public_key is not None
            validate_published(output, public_key)

            artifact = next(output.glob("plugins/*/.xsec-market/artifacts/*.xsec-plugin"))
            with artifact.open("ab") as handle:
                handle.write(b"tampered")
            with self.assertRaisesRegex(MarketplaceValidationError, "SHA-256"):
                validate_published(output, public_key)

    def test_unsafe_zip_member_is_rejected_before_manifest_read(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-zip-test-") as directory:
            artifact = Path(directory) / "unsafe.xsec-plugin"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("../plugin.json", '{"name":"com.xsec.test","version":"1.0.0"}')
            with self.assertRaisesRegex(MarketplaceValidationError, "unsafe entry path"):
                validate_archive(artifact, "com.xsec.test", "1.0.0")

    def test_symbolic_link_zip_member_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-link-test-") as directory:
            artifact = Path(directory) / "link.xsec-plugin"
            link = zipfile.ZipInfo("plugin.json")
            link.external_attr = 0o120777 << 16
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr(link, "plugin.json")
            with self.assertRaisesRegex(MarketplaceValidationError, "symbolic link"):
                validate_archive(artifact, "com.xsec.test", "1.0.0")

    def test_signing_preflight_rejects_a_seed_for_another_public_key(self) -> None:
        previous = os.environ.get("XSEC_MARKETPLACE_SIGNING_KEY_B64")
        try:
            os.environ["XSEC_MARKETPLACE_SIGNING_KEY_B64"] = base64.b64encode(b"\x19" * 32).decode("ascii")
            with self.assertRaisesRegex(MarketplaceValidationError, "does not match"):
                validate_signing_key(OFFICIAL_MARKETPLACE_PUBLIC_KEY_B64)
        finally:
            if previous is None:
                os.environ.pop("XSEC_MARKETPLACE_SIGNING_KEY_B64", None)
            else:
                os.environ["XSEC_MARKETPLACE_SIGNING_KEY_B64"] = previous

    def test_signing_preflight_accepts_its_matching_public_key(self) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        seed = b"\x21" * 32
        public_key = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        previous = os.environ.get("XSEC_MARKETPLACE_SIGNING_KEY_B64")
        try:
            os.environ["XSEC_MARKETPLACE_SIGNING_KEY_B64"] = base64.b64encode(seed).decode("ascii")
            validate_signing_key(base64.b64encode(public_key).decode("ascii"))
        finally:
            if previous is None:
                os.environ.pop("XSEC_MARKETPLACE_SIGNING_KEY_B64", None)
            else:
                os.environ["XSEC_MARKETPLACE_SIGNING_KEY_B64"] = previous

    def test_manual_publish_is_rejected_outside_main_before_signing(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")
        self.assertIn("enforce-publish-ref:", workflow)
        self.assertIn('EVENT_NAME: ${{ github.event_name }}', workflow)
        self.assertIn('REF: ${{ github.ref }}', workflow)
        self.assertIn('[ "$EVENT_NAME" = "workflow_dispatch" ] && [ "$REF" != "refs/heads/main" ]', workflow)
        signing_job = workflow.split("  sign-and-publish:\n", 1)[1].split("    runs-on:", 1)[0]
        self.assertIn(
            "needs: enforce-publish-ref\n"
            "    if: ${{ needs.enforce-publish-ref.result == 'success' && github.ref == 'refs/heads/main' }}",
            signing_job,
        )


if __name__ == "__main__":
    unittest.main()
