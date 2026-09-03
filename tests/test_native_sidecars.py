from __future__ import annotations

import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_market  # noqa: E402
import native_sidecars  # noqa: E402
import validate_market  # noqa: E402


PLUGIN_ID = "com.xsec.attack-path"
PLUGIN_VERSION = "2.0.0"
SIDECAR_PATH = "bin/attack-path-mcp"
SOURCE_REVISION = "a" * 40
ASSET_PLUGIN_ID = "com.xsec.asset-discovery"
ASSET_SNAPSHOT = ROOT / ".xsec-factory" / "snapshots" / ASSET_PLUGIN_ID


def write_attack_path_source(root: Path, command: str = "./bin/attack-path-mcp") -> Path:
    source = root / "source"
    frontend = source / "com.xsec.desktop" / "frontend"
    skill = source / "skills" / "attack-path"
    frontend.mkdir(parents=True)
    skill.mkdir(parents=True)
    manifest = {
        "name": PLUGIN_ID,
        "version": PLUGIN_VERSION,
        "extensions": {
            "com.xsec.desktop": {
                "schemaVersion": 2,
                "engines": {"xsec": ">=0.1.0", "pluginApi": "^1.3.0"},
                "entrypoints": {"frontend": "com.xsec.desktop/frontend/index.js"},
            }
        },
    }
    mcp = {"mcpServers": {"attack-path": {
        "type": "stdio",
        "command": command,
        "cwd": "${PLUGIN_DATA}",
    }}}
    (source / "plugin.json").write_text(json.dumps(manifest), encoding="utf-8")
    (source / "mcp.json").write_text(json.dumps(mcp), encoding="utf-8")
    (frontend / "index.js").write_text("export {};\n", encoding="utf-8")
    (skill / "SKILL.md").write_text("# Attack path\n", encoding="utf-8")
    return source


def sidecar_inputs(root: Path) -> dict[tuple[str, str], Path]:
    inputs: dict[tuple[str, str], Path] = {}
    for target in native_sidecars.ATTACK_PATH_RECIPE.targets:
        binary = root / target.rust_target
        binary.write_bytes(f"sidecar for {target.rust_target}\n".encode("utf-8"))
        inputs[(PLUGIN_ID, target.rust_target)] = binary
    return inputs


class NativeSidecarFactoryTests(unittest.TestCase):
    def test_asset_discovery_binds_three_exact_server_modes_to_one_binary(self) -> None:
        recipe = native_sidecars.ASSET_DISCOVERY_RECIPE
        raw = (ASSET_SNAPSHOT / "mcp.json").read_bytes()
        native_sidecars.validate_mcp_declaration(recipe, raw, "asset mcp.json")
        broken = json.loads(raw)
        broken["mcpServers"]["asset-hunter"]["args"] = ["--provider", "fofa"]
        with self.assertRaisesRegex(ValueError, "invalid arguments for asset-hunter"):
            native_sidecars.validate_mcp_declaration(recipe, json.dumps(broken).encode(), "asset mcp.json")

        with tempfile.TemporaryDirectory(prefix="xsec-asset-sidecar-build-") as directory:
            root = Path(directory)
            inputs = {}
            for target in recipe.targets:
                binary = root / target.rust_target
                binary.write_bytes(target.rust_target.encode())
                inputs[(recipe.plugin_id, target.rust_target)] = binary
            output = root / "output" / ".xsec-factory" / "snapshots" / recipe.plugin_id
            build_market.build_plugin(
                ASSET_SNAPSHOT,
                output,
                native_sidecar_inputs=inputs,
                native_sidecar_source_revision=SOURCE_REVISION,
            )
            validate_market.validate_release(recipe.plugin_id, output)
            release = json.loads((output / ".xsec-market" / "releases.json").read_text(encoding="utf-8"))
            for artifact, target in zip(release["releases"][0]["artifacts"], recipe.targets, strict=True):
                with zipfile.ZipFile(output / ".xsec-market" / artifact["url"]) as archive:
                    entrypoint = native_sidecars.archive_path_for(recipe, target).as_posix()
                    self.assertEqual(archive.read(entrypoint), inputs[(recipe.plugin_id, target.rust_target)].read_bytes())
                    mcp = json.loads(archive.read("mcp.json"))
                    self.assertEqual(mcp["mcpServers"]["asset-normalize"]["command"], f"./{entrypoint}")

    def test_builds_and_validates_distinct_artifacts_for_each_supported_target(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-native-sidecar-build-") as directory:
            root = Path(directory)
            source = write_attack_path_source(root)
            output = root / "output" / ".xsec-factory" / "snapshots" / PLUGIN_ID
            inputs = sidecar_inputs(root)

            build_market.build_plugin(
                source,
                output,
                native_sidecar_inputs=inputs,
                native_sidecar_source_revision=SOURCE_REVISION,
            )

            release = json.loads((output / ".xsec-market" / "releases.json").read_text(encoding="utf-8"))
            artifacts = release["releases"][0]["artifacts"]
            expected = {(target.os_name, target.arch) for target in native_sidecars.ATTACK_PATH_RECIPE.targets}
            self.assertEqual({(artifact["os"], artifact["arch"]) for artifact in artifacts}, expected)
            self.assertNotIn(("any", "any"), {(artifact["os"], artifact["arch"]) for artifact in artifacts})
            provenance = release["releases"][0]["nativeSidecarProvenance"]
            self.assertEqual(provenance["source"]["repository"], "tzf1003/xSecDesktop")
            self.assertEqual(provenance["source"]["revision"], SOURCE_REVISION)
            validate_market.validate_release(PLUGIN_ID, output)

            release_path = output / ".xsec-market" / "releases.json"
            second = release["releases"][0]["artifacts"][1]
            with (output / ".xsec-market" / second["url"]).open("ab") as handle:
                handle.write(b"unexpected archive trailer")
            second["sha256"] = build_market.sha256(output / ".xsec-market" / second["url"])
            release["releases"][0]["releaseId"] = build_market.release_id(
                PLUGIN_VERSION,
                release["releases"][0]["engines"],
                release["releases"][0]["artifacts"],
                provenance,
            )
            release["channels"]["beta"] = {"releaseId": release["releases"][0]["releaseId"]}
            release_path.write_text(json.dumps(release), encoding="utf-8")
            validated = validate_market.validate_release(PLUGIN_ID, output)
            with self.assertRaisesRegex(validate_market.MarketplaceValidationError, "not deterministic"):
                validate_market.validate_native_artifact_reproducibility(
                    PLUGIN_ID,
                    source,
                    release["releases"][0]["artifacts"],
                    validated,
                )

            for artifact, target in zip(artifacts, native_sidecars.ATTACK_PATH_RECIPE.targets, strict=True):
                artifact_path = output / ".xsec-market" / artifact["url"]
                with zipfile.ZipFile(artifact_path) as archive:
                    entrypoint = native_sidecars.archive_path_for(native_sidecars.ATTACK_PATH_RECIPE, target).as_posix()
                    self.assertEqual(archive.read(entrypoint), inputs[(PLUGIN_ID, target.rust_target)].read_bytes())
                    mcp = json.loads(archive.read("mcp.json"))
                    self.assertEqual(mcp["mcpServers"]["attack-path"]["command"], f"./{entrypoint}")
            provenance["targets"][0]["sha256"] = "f" * 64
            release["releases"][0]["releaseId"] = build_market.release_id(
                PLUGIN_VERSION,
                release["releases"][0]["engines"],
                artifacts,
                provenance,
            )
            release["channels"]["beta"] = {"releaseId": release["releases"][0]["releaseId"]}
            (output / ".xsec-market" / "releases.json").write_text(json.dumps(release), encoding="utf-8")
            with self.assertRaisesRegex(validate_market.MarketplaceValidationError, "digest does not match provenance"):
                validate_market.validate_release(PLUGIN_ID, output)

    def test_build_rejects_a_missing_required_native_target(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-native-sidecar-missing-") as directory:
            root = Path(directory)
            source = write_attack_path_source(root)
            inputs = sidecar_inputs(root)
            missing_target = native_sidecars.ATTACK_PATH_RECIPE.targets[0]
            del inputs[(PLUGIN_ID, missing_target.rust_target)]

            with self.assertRaisesRegex(ValueError, "missing native sidecar input"):
                build_market.build_plugin(
                    source,
                    root / "output",
                    native_sidecar_inputs=inputs,
                    native_sidecar_source_revision=SOURCE_REVISION,
                )

    def test_build_rejects_a_source_sidecar_with_a_windows_extension(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-native-sidecar-source-binary-") as directory:
            root = Path(directory)
            source = write_attack_path_source(root)
            source_binary = source / "bin" / "attack-path-mcp.exe"
            source_binary.parent.mkdir()
            source_binary.write_bytes(b"untrusted source binary")

            with self.assertRaisesRegex(ValueError, "must be supplied by the Factory recipe"):
                build_market.build_plugin(
                    source,
                    root / "output",
                    native_sidecar_inputs=sidecar_inputs(root),
                    native_sidecar_source_revision=SOURCE_REVISION,
                )

    def test_release_rejects_platform_artifacts_without_provenance(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-native-sidecar-release-") as directory:
            root = Path(directory)
            source = write_attack_path_source(root)
            output = root / "output" / ".xsec-factory" / "snapshots" / PLUGIN_ID
            build_market.build_plugin(
                source,
                output,
                native_sidecar_inputs=sidecar_inputs(root),
                native_sidecar_source_revision=SOURCE_REVISION,
            )
            release_path = output / ".xsec-market" / "releases.json"
            release = json.loads(release_path.read_text(encoding="utf-8"))
            record = release["releases"][0]
            record.pop("nativeSidecarProvenance")
            record["releaseId"] = build_market.release_id(
                PLUGIN_VERSION,
                record["engines"],
                record["artifacts"],
            )
            release["channels"]["beta"] = {"releaseId": record["releaseId"]}
            release_path.write_text(json.dumps(release), encoding="utf-8")

            with self.assertRaisesRegex(validate_market.MarketplaceValidationError, "requires native sidecar provenance"):
                validate_market.validate_release(PLUGIN_ID, output)

    def test_build_rejects_missing_or_invalid_native_source_evidence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-native-sidecar-provenance-") as directory:
            root = Path(directory)
            source = write_attack_path_source(root)
            inputs = sidecar_inputs(root)

            with self.assertRaisesRegex(ValueError, "requires a protected source revision"):
                build_market.build_plugin(source, root / "missing", native_sidecar_inputs=inputs)
            with self.assertRaisesRegex(ValueError, "lowercase 40-character Git SHA"):
                build_market.build_plugin(
                    source,
                    root / "invalid",
                    native_sidecar_inputs=inputs,
                    native_sidecar_source_revision="invalid",
                )

    def test_validation_rejects_any_target_and_invalid_native_entrypoints(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-native-sidecar-invalid-") as directory:
            root = Path(directory)
            source = write_attack_path_source(root)
            artifact = root / "any-any.xsec-plugin"
            (source / SIDECAR_PATH).parent.mkdir()
            (source / SIDECAR_PATH).write_bytes(b"sidecar")
            build_market.write_zip(source, artifact)

            with self.assertRaisesRegex(validate_market.MarketplaceValidationError, "unsupported target any/any"):
                validate_market.validate_archive(artifact, PLUGIN_ID, PLUGIN_VERSION)

            with self.assertRaisesRegex(validate_market.MarketplaceValidationError, "attack-path-mcp.exe"):
                validate_market.validate_archive(
                    artifact,
                    PLUGIN_ID,
                    PLUGIN_VERSION,
                    os_name="windows",
                    arch="x86_64",
                )

            (source / SIDECAR_PATH).unlink()
            build_market.write_zip(source, artifact)
            with self.assertRaisesRegex(validate_market.MarketplaceValidationError, "missing bin/attack-path-mcp"):
                validate_market.validate_archive(artifact, PLUGIN_ID, PLUGIN_VERSION, os_name="macos", arch="aarch64")

            invalid = write_attack_path_source(root / "invalid", command="./bin/not-attack-path")
            (invalid / "bin").mkdir()
            (invalid / "bin" / "not-attack-path").write_bytes(b"sidecar")
            build_market.write_zip(invalid, artifact)
            with self.assertRaisesRegex(validate_market.MarketplaceValidationError, "must declare attack-path"):
                validate_market.validate_archive(artifact, PLUGIN_ID, PLUGIN_VERSION, os_name="macos", arch="aarch64")


if __name__ == "__main__":
    unittest.main()
