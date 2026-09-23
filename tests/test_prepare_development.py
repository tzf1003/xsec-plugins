from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import prepare_development as development
from native_sidecars import RECIPES, mcp_command_for, sha256_file


class DevelopmentPreparationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="xsec-development-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.factory = self.root / "factory"
        for plugin_id, recipe in RECIPES.items():
            source = self.factory / "plugins" / plugin_id
            source.mkdir(parents=True)
            manifest = {
                "name": plugin_id,
                "version": "3.0.0",
                "extensions": {"com.xsec.desktop": {
                    "schemaVersion": 2,
                    "permissions": {"mcp.servers.register": {}, "native.execute": {}},
                }},
            }
            servers = {}
            for server in recipe.servers:
                declaration = {
                    "type": "stdio",
                    "command": mcp_command_for(recipe),
                    "cwd": "${PLUGIN_DATA}",
                }
                if server.args:
                    declaration["args"] = list(server.args)
                if server.env:
                    declaration["env"] = dict(server.env)
                servers[server.server_id] = declaration
            (source / "plugin.json").write_text(json.dumps(manifest), encoding="utf-8")
            (source / "mcp.json").write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")
            subprocess.run(["git", "init", "--quiet", str(source)], check=True)

    def destination(self) -> Path:
        return next(iter(development.source_plan(self.factory).values()))

    def add_cargo_binary(self, root: Path, package: str) -> None:
        crate = root / package
        (crate / "src").mkdir(parents=True)
        (crate / "Cargo.toml").write_text(
            f'[package]\nname = "{package}"\nversion = "0.1.0"\nedition = "2021"\n',
            encoding="utf-8",
        )
        (crate / "src" / "main.rs").write_text("fn main() {}\n", encoding="utf-8")

    def test_native_sidecars_build_from_their_declared_source_repositories(self) -> None:
        desktop = self.root / "desktop"
        desktop.mkdir()
        (desktop / "Cargo.toml").write_text(
            '[workspace]\nmembers = ["xsec-attack-path-mcp", "xsec-asset-discovery-mcp"]\nresolver = "2"\n',
            encoding="utf-8",
        )
        for package in ("xsec-attack-path-mcp", "xsec-asset-discovery-mcp"):
            self.add_cargo_binary(desktop, package)
        subprocess.run(["cargo", "generate-lockfile"], cwd=desktop, check=True)

        terminal_source = self.factory / "plugins" / "com.xsec.system-terminal"
        (terminal_source / "Cargo.toml").write_text(
            '[workspace]\nmembers = ["system-terminal-mcp"]\nresolver = "2"\n',
            encoding="utf-8",
        )
        self.add_cargo_binary(terminal_source, "system-terminal-mcp")
        subprocess.run(["cargo", "generate-lockfile"], cwd=terminal_source, check=True)

        plan = development.source_plan(self.factory)
        host = development.desktop_host(desktop)
        binaries = development.build_sidecars(desktop, host, plan)

        self.assertEqual(set(binaries), set(RECIPES))
        self.assertTrue(all(path.is_file() and path.stat().st_size > 0 for path in binaries.values()))

    def test_real_source_contract_accepts_missing_generated_entrypoints(self) -> None:
        plan = development.source_plan(self.factory)
        self.assertEqual(set(plan), set(RECIPES))
        self.assertTrue(all(not path.exists() for path in plan.values()))

    def test_install_copies_executable_and_preserves_git_excludes(self) -> None:
        destination = self.destination()
        source = destination.parent.parent
        exclude = source / ".git" / "info" / "exclude"
        exclude.write_text("/developer-notes", encoding="utf-8")
        binary = Path("/bin/echo").resolve(strict=True)
        digest = development.install_binary(binary, destination)
        self.assertEqual(digest, sha256_file(binary))
        self.assertEqual(sha256_file(destination), digest)
        self.assertFalse(destination.is_symlink())
        self.assertTrue(os.access(destination, os.X_OK))
        self.assertIn("/developer-notes\n", exclude.read_text(encoding="utf-8"))
        ignored = development.run_output(["git", "check-ignore", str(destination)], source)
        self.assertEqual(Path(ignored), destination)
        development.install_binary(binary, destination)
        pattern = f"/{destination.relative_to(source).as_posix()}"
        self.assertEqual(exclude.read_text(encoding="utf-8").splitlines().count(pattern), 1)

    def test_symlink_directory_is_rejected_before_writing(self) -> None:
        destination = self.destination()
        external = self.root / "outside"
        external.mkdir()
        destination.parent.symlink_to(external, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "regular directory"):
            development.source_plan(self.factory)
        self.assertEqual(list(external.iterdir()), [])

    def test_symlink_binary_is_rejected_before_replacement(self) -> None:
        destination = self.destination()
        destination.parent.mkdir()
        binary = Path("/bin/echo").resolve(strict=True)
        destination.symlink_to(binary)
        before = sha256_file(binary)
        with self.assertRaises(ValueError):
            development.install_binary(binary, destination)
        self.assertTrue(destination.is_symlink())
        self.assertEqual(sha256_file(binary), before)

    def test_tracked_binary_is_not_overwritten(self) -> None:
        destination = self.destination()
        destination.parent.mkdir()
        shutil.copyfile(Path("/bin/echo").resolve(strict=True), destination)
        subprocess.run(["git", "add", str(destination)], cwd=destination.parent, check=True)
        with self.assertRaisesRegex(ValueError, "must not be tracked"):
            development.source_plan(self.factory)

    def test_unexpected_mcp_command_is_rejected(self) -> None:
        destination = self.destination()
        path = destination.parent.parent / "mcp.json"
        mcp = json.loads(path.read_text(encoding="utf-8"))
        next(iter(mcp["mcpServers"].values()))["command"] = "node"
        path.write_text(json.dumps(mcp), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "must declare"):
            development.source_plan(self.factory)
        self.assertFalse(destination.exists())

    def test_real_cargo_failure_preserves_existing_binaries(self) -> None:
        plan = development.source_plan(self.factory)
        for destination in plan.values():
            development.install_binary(Path("/bin/echo").resolve(strict=True), destination)
        before = {key: sha256_file(path) for key, path in plan.items()}
        desktop = self.root / "desktop"
        desktop.mkdir()
        (desktop / "Cargo.toml").write_text('[workspace]\nmembers = []\nresolver = "2"\n', encoding="utf-8")
        subprocess.run(["cargo", "generate-lockfile"], cwd=desktop, check=True)
        with self.assertRaises(subprocess.CalledProcessError):
            development.prepare(self.factory, desktop)
        self.assertEqual({key: sha256_file(path) for key, path in plan.items()}, before)


if __name__ == "__main__":
    unittest.main()
