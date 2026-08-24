from __future__ import annotations

import base64
from contextlib import nullcontext
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from marketplace_contract import OFFICIAL_MARKETPLACE_PUBLIC_KEY_B64  # noqa: E402
import build_market  # noqa: E402
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
        self.assertIn('REF_PROTECTED: ${{ github.ref_protected }}', workflow)
        self.assertIn('[ "$EVENT_NAME" = "workflow_dispatch" ] && [ "$REF" != "refs/heads/main" ]', workflow)
        self.assertIn('[ "$REF_PROTECTED" != "true" ]', workflow)
        signing_job = workflow.split("  sign-and-publish:\n", 1)[1].split("    runs-on:", 1)[0]
        self.assertIn(
            "needs: enforce-publish-ref\n"
            "    if: ${{ needs.enforce-publish-ref.result == 'success' && github.ref == 'refs/heads/main' && github.ref_protected }}",
            signing_job,
        )

    def test_disposable_build_rejects_nested_plugin_link_before_copytree(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-copy-link-") as directory:
            source_root = Path(directory) / "source"
            plugin_root = source_root / "plugins"
            plugin_dir = plugin_root / "com.xsec.test"
            nested_link = plugin_dir / "linked"
            outside = source_root / "outside"
            destination = Path(directory) / "destination"
            marketplace = source_root / ".agents" / "plugins" / "marketplace.json"
            plugin_dir.mkdir(parents=True)
            outside.mkdir()
            try:
                nested_link.symlink_to(outside, target_is_directory=True)
                link_check = nullcontext()
            except OSError:
                # Some Windows developer machines cannot create symlinks. The
                # CI test uses a real link; retain a local regression check of
                # the same detection branch when this capability is absent.
                nested_link.mkdir()
                link_check = patch.object(build_market, "is_link", side_effect=lambda path: path == nested_link)
            marketplace.parent.mkdir(parents=True)
            marketplace.write_text('{"plugins": []}\n', encoding="utf-8")

            with (
                patch.object(build_market, "PLUGIN_ROOT", plugin_root),
                patch.object(build_market, "MARKETPLACE", marketplace),
                patch.object(build_market.shutil, "copytree") as copytree,
                link_check,
            ):
                with self.assertRaisesRegex(ValueError, "plugin package must not contain symbolic links"):
                    build_market.copy_source_tree(destination)
                copytree.assert_not_called()

    def test_disposable_build_rejects_linked_plugin_root_before_traversal(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-root-link-") as directory:
            source_root = Path(directory) / "source"
            plugin_root = source_root / "plugins"
            destination = Path(directory) / "destination"
            plugin_root.mkdir(parents=True)

            with (
                patch.object(build_market, "PLUGIN_ROOT", plugin_root),
                patch.object(build_market, "is_link", side_effect=lambda path: path == plugin_root),
                patch.object(Path, "iterdir") as iterdir,
                patch.object(build_market.shutil, "copytree") as copytree,
            ):
                with self.assertRaisesRegex(ValueError, "plugin root must not be a symbolic link"):
                    build_market.copy_source_tree(destination)
                iterdir.assert_not_called()
                copytree.assert_not_called()


if __name__ == "__main__":
    unittest.main()
