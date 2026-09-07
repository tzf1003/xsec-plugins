#!/usr/bin/env python3
"""Build the official native MCP entrypoints for local Desktop development."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile

from native_sidecars import RECIPES, recipe_for_source, require_regular_input, sha256_file


FACTORY_ROOT = Path(__file__).resolve().parents[1]
EXECUTABLE_MODE = 0o755
SUPPORTED_HOST_SUFFIXES = ("-apple-darwin", "-unknown-linux-gnu")


def run_output(args: list[str], cwd: Path) -> str:
    return subprocess.run(args, cwd=cwd, check=True, text=True, stdout=subprocess.PIPE).stdout.strip()


def regular_directory(path: Path) -> Path:
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"expected a regular directory: {path}")
    return path.resolve(strict=True)


def source_plan(factory: Path) -> dict[str, Path]:
    """Validate every destination before compiling or changing any plugin."""
    plugins = regular_directory(factory / "plugins")
    destinations = {}
    for plugin_id, recipe in RECIPES.items():
        source = regular_directory(plugins / plugin_id)
        manifest = json.loads((source / "plugin.json").read_text(encoding="utf-8"))
        if manifest.get("name") != plugin_id or recipe_for_source(plugin_id, source) != recipe:
            raise ValueError(f"unexpected native source contract: {source}")
        git_root = run_output(["git", "rev-parse", "--show-toplevel"], source)
        if Path(git_root).resolve() != source:
            raise ValueError(f"plugin must be an independent Git project: {source}")
        destination = source / recipe.archive_path
        validate_destination(destination)
        if run_output(["git", "ls-files", "--", str(recipe.archive_path)], source):
            raise ValueError(f"development binary must not be tracked by Git: {destination}")
        destinations[plugin_id] = destination
    return destinations


def validate_destination(destination: Path) -> None:
    if os.path.lexists(destination.parent):
        regular_directory(destination.parent)
    if os.path.lexists(destination):
        require_regular_input(destination)


def desktop_host(desktop: Path) -> str:
    regular_directory(desktop)
    for name in ("Cargo.toml", "Cargo.lock"):
        require_regular_input(desktop / name)
    verbose = run_output(["rustc", "-vV"], desktop)
    hosts = [line.removeprefix("host: ") for line in verbose.splitlines() if line.startswith("host: ")]
    if len(hosts) != 1 or not hosts[0].endswith(SUPPORTED_HOST_SUFFIXES):
        raise ValueError("local development preparation requires a macOS or Linux Rust host")
    for recipe in RECIPES.values():
        if hosts[0] not in {target.rust_target for target in recipe.targets}:
            raise ValueError(f"unsupported native development target: {hosts[0]}")
    return hosts[0]


def build_sidecars(desktop: Path, host: str) -> dict[str, Path]:
    packages = {plugin_id: f"xsec-{recipe.archive_path.name}" for plugin_id, recipe in RECIPES.items()}
    command = ["cargo", "build", "--locked", "--target", host, "--message-format=json-render-diagnostics"]
    for package in packages.values():
        command.extend(["--package", package])
    with tempfile.TemporaryFile(mode="w+t", encoding="utf-8") as output:
        subprocess.run(command, cwd=desktop, check=True, stdout=output)
        output.seek(0)
        binaries = cargo_executables(output, set(packages.values()))
    if set(binaries) != set(packages.values()):
        raise ValueError("Cargo did not report every requested native executable")
    return {plugin_id: require_regular_input(binaries[package]) for plugin_id, package in packages.items()}


def cargo_executables(lines, packages: set[str]) -> dict[str, Path]:
    binaries = {}
    for line in lines:
        message = json.loads(line)
        if message.get("reason") != "compiler-artifact":
            continue
        target = message["target"]
        if target["name"] in packages and "bin" in target["kind"] and message.get("executable"):
            binaries[target["name"]] = Path(message["executable"])
    return binaries


def exclude_local_binary(destination: Path) -> None:
    source = destination.parent.parent
    relative = destination.relative_to(source).as_posix()
    raw = run_output(["git", "rev-parse", "--git-path", "info/exclude"], source)
    exclude = source / raw
    content = ""
    if os.path.lexists(exclude):
        if not stat.S_ISREG(exclude.lstat().st_mode):
            raise ValueError(f"Git exclude must be a regular file: {exclude}")
        content = exclude.read_text(encoding="utf-8")
    pattern = f"/{relative}"
    if pattern not in content.splitlines():
        exclude.parent.mkdir(parents=True, exist_ok=True)
        separator = "\n" if content and not content.endswith("\n") else ""
        with exclude.open("a", encoding="utf-8") as output:
            output.write(f"{separator}{pattern}\n")


def install_binary(binary: Path, destination: Path) -> str:
    """Replace one entrypoint atomically; never expose a partially copied file."""
    require_regular_input(binary)
    validate_destination(destination)
    exclude_local_binary(destination)
    destination.parent.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".xsec-native-", dir=destination.parent) as directory:
        staged = Path(directory) / destination.name
        shutil.copyfile(binary, staged)
        staged.chmod(EXECUTABLE_MODE)
        digest = sha256_file(staged)
        if digest != sha256_file(binary):
            raise ValueError(f"native binary changed during preparation: {binary}")
        validate_destination(destination)
        os.replace(staged, destination)
    if sha256_file(destination) != digest:
        raise ValueError(f"native binary changed after preparation: {destination}")
    return digest


def prepare(factory: Path, desktop: Path) -> None:
    destinations = source_plan(factory)
    host = desktop_host(desktop)
    print(f"Building native development entrypoints for {host}", flush=True)
    binaries = build_sidecars(desktop, host)
    if source_plan(factory) != destinations:
        raise ValueError("native source destinations changed during compilation")
    for plugin_id, destination in destinations.items():
        digest = install_binary(binaries[plugin_id], destination)
        print(f"Prepared {plugin_id}: {destination} sha256={digest}", flush=True)
    print("准备完成。请在开发工作台重新检查，再审核权限并接入。", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--desktop-source", type=Path, required=True, help="trusted local xSecDesktop Rust workspace")
    parser.add_argument("--factory-root", type=Path, default=FACTORY_ROOT)
    args = parser.parse_args()
    prepare(args.factory_root.absolute(), args.desktop_source.absolute())


if __name__ == "__main__":
    main()
