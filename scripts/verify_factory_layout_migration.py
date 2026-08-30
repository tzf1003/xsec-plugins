#!/usr/bin/env python3
"""Verify the one-time Factory layout migration before KMS re-signing."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path, PurePosixPath

from kms_marketplace_publisher import MarketplaceDocument, MarketplaceKmsPublisherError, download_pinned_issuer_jwks, verify_historical_sidecar_signature


MARKETPLACE_PATH = Path(".agents/plugins/marketplace.json")
LEGACY_PLUGIN_ROOT = Path("plugins")
SNAPSHOT_ROOT = Path(".xsec-factory/snapshots")
MIGRATION_MARKER = Path(".xsec-factory/layout-migration.json")
RELEASE_SIDECAR = Path(".xsec-market/releases.json.sig.jws.json")
MARKER = {"schemaVersion": 1, "layout": "git-subprojects-with-release-snapshots", "pendingKmsSidecars": True}
MIGRATION_SUPPORT_PATHS = frozenset((".agents/plugins/marketplace.json", ".agents/plugins/marketplace.json.sig.jws.json", ".gitmodules", ".xsec-factory/layout-migration.json"))
MIGRATION_SUPPORT_PLAN = Path(__file__).with_name("factory_layout_migration_plan.json")


class FactoryLayoutMigrationError(ValueError):
    """The candidate is not the narrow layout transition this check permits."""


def fail(message: str) -> None:
    raise FactoryLayoutMigrationError(message)


def require_directory(path: Path, label: str) -> Path:
    if path.is_symlink() or not path.is_dir():
        fail(f"{label}必须是常规目录")
    try:
        return path.resolve(strict=True)
    except OSError as error:
        raise FactoryLayoutMigrationError(f"无法读取{label}") from error


def read_json(path: Path, label: str) -> dict[str, object]:
    if path.is_symlink() or not path.is_file():
        fail(f"{label}不可用")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FactoryLayoutMigrationError(f"{label}不是有效 JSON") from error
    if not isinstance(value, dict):
        fail(f"{label}必须是 JSON 对象")
    return value


def plugin_ids(index: dict[str, object], root: PurePosixPath) -> tuple[str, ...]:
    entries = index.get("plugins")
    if not isinstance(entries, list) or not entries:
        fail("市场索引必须包含插件")
    ids: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict):
            fail("市场索引插件项无效")
        plugin_id = entry.get("name")
        source = entry.get("source")
        if not isinstance(plugin_id, str) or not isinstance(source, dict):
            fail("市场索引插件项缺少名称或来源")
        expected = f"./{(root / plugin_id).as_posix()}"
        if source.get("path") != expected:
            fail(f"市场索引插件 {plugin_id} 未使用预期路径")
        ids.append(plugin_id)
    if len(set(ids)) != len(ids):
        fail("市场索引包含重复插件")
    return tuple(ids)


def expected_snapshot_index(baseline: dict[str, object]) -> dict[str, object]:
    value = json.loads(json.dumps(baseline))
    entries = value.get("plugins")
    if not isinstance(entries, list):
        fail("基线市场索引缺少插件")
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
            fail("基线市场索引插件项无效")
        source = entry.get("source")
        if not isinstance(source, dict):
            fail("基线市场索引插件来源无效")
        source["path"] = f"./{(SNAPSHOT_ROOT / entry['name']).as_posix()}"
    return value


def regular_files(root: Path) -> dict[PurePosixPath, bytes]:
    if root.is_symlink() or not root.is_dir():
        fail(f"目录不可用：{root}")
    values: dict[PurePosixPath, bytes] = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            fail(f"目录不能包含符号链接：{path}")
        if path.is_file():
            values[PurePosixPath(path.relative_to(root).as_posix())] = path.read_bytes()
        elif not path.is_dir():
            fail(f"目录包含非常规条目：{path}")
    return values


def snapshot_files(root: Path, plugin_id: str) -> dict[PurePosixPath, bytes]:
    values = regular_files(root)
    values.pop(RELEASE_SIDECAR, None)
    return values


def require_missing(path: Path, label: str) -> None:
    if path.exists() or path.is_symlink():
        fail(f"{label}必须等待 KMS 重新签发")


def gitlines(root: Path, args: list[str]) -> list[str]:
    result = subprocess.run(
        ["git", *args], cwd=root, check=False, capture_output=True, text=True, encoding="utf-8"
    )
    if result.returncode != 0:
        fail("无法读取工厂 Git 元数据")
    return [line for line in result.stdout.splitlines() if line]


def gitlink_paths(root: Path) -> set[str]:
    paths: set[str] = set()
    for line in gitlines(root, ["ls-files", "--stage", "--", "plugins"]):
        try:
            header, path = line.split("\t", 1)
            mode, _object_id, stage = header.split(" ")
        except ValueError as error:
            raise FactoryLayoutMigrationError("工厂 Git 索引格式无效") from error
        if mode != "160000" or stage != "0" or not path.startswith("plugins/"):
            fail("工厂插件目录必须只包含 Git 子项目")
        paths.add(path)
    return paths


def submodule_settings(root: Path) -> dict[str, dict[str, str]]:
    values: dict[str, dict[str, str]] = {}
    for line in gitlines(root, ["config", "--file", ".gitmodules", "--get-regexp", r"^submodule\..+\.(path|url|branch)$"]):
        try:
            key, value = line.split(maxsplit=1)
            prefix, field = key.rsplit(".", 1)
            name = prefix.removeprefix("submodule.")
        except ValueError as error:
            raise FactoryLayoutMigrationError(".gitmodules 格式无效") from error
        values.setdefault(name, {})[field] = value
    return values


def registry_repositories(root: Path) -> dict[str, str]:
    registry = read_json(root / ".xsec-factory/official-registry.json", "工厂注册表")
    entries = registry.get("plugins")
    if not isinstance(entries, list):
        fail("工厂注册表缺少插件")
    repositories: dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            fail("工厂注册表插件项无效")
        plugin_id = entry.get("pluginId")
        source = entry.get("source")
        if not isinstance(plugin_id, str) or not isinstance(source, dict) or not isinstance(source.get("repository"), str):
            fail("工厂注册表插件来源无效")
        repositories[plugin_id] = source["repository"]
    return repositories


def verify_submodules(root: Path, ids: tuple[str, ...]) -> None:
    expected_paths = {f"plugins/{plugin_id}" for plugin_id in ids}
    if gitlink_paths(root) != expected_paths:
        fail("工厂 Git 子项目与市场插件不一致")
    repositories = registry_repositories(root)
    if set(repositories) != set(ids):
        fail("工厂注册表与市场插件不一致")
    settings = submodule_settings(root)
    for plugin_id in ids:
        path = f"plugins/{plugin_id}"
        item = settings.get(path)
        if item != {"path": path, "url": f"https://github.com/{repositories[plugin_id]}.git", "branch": "beta"}:
            fail(f"插件 {plugin_id} 的 Git 子项目来源无效")


def verify_factory_metadata(root: Path, baseline: Path) -> None:
    current = regular_files(root / ".xsec-factory")
    previous = regular_files(baseline / ".xsec-factory")
    current.pop(PurePosixPath("layout-migration.json"), None)
    current = {path: value for path, value in current.items() if not path.parts or path.parts[0] != "snapshots"}
    previous = {path: value for path, value in previous.items() if not path.parts or path.parts[0] != "snapshots"}
    if current != previous:
        fail("工厂注册、来源证明或状态记录不能随目录迁移改变")


def verify_predecessor_signatures(baseline: Path, ids: tuple[str, ...]) -> None:
    jwks = download_pinned_issuer_jwks()
    index = baseline / MARKETPLACE_PATH
    index_sidecar = index.with_name(f"{index.name}.sig.jws.json")
    verify_historical_sidecar_signature(
        index_sidecar.read_bytes(), MarketplaceDocument("xsec.plugin-marketplace.index", MARKETPLACE_PATH.as_posix(), index), jwks_bytes=jwks
    )
    for plugin_id in ids:
        release = baseline / LEGACY_PLUGIN_ROOT / plugin_id / ".xsec-market/releases.json"
        sidecar = release.with_name(f"{release.name}.sig.jws.json")
        subject = f"plugins/{plugin_id}/.xsec-market/releases.json"
        verify_historical_sidecar_signature(
            sidecar.read_bytes(), MarketplaceDocument("xsec.plugin-marketplace.release", subject, release), jwks_bytes=jwks
        )


def migration_support_hashes() -> dict[str, str]:
    plan = read_json(MIGRATION_SUPPORT_PLAN, "布局迁移计划")
    valid = all(
        isinstance(relative, str) and not relative.startswith("/") and ".." not in PurePosixPath(relative).parts
        and isinstance(digest, str) and len(digest) == 64 and all(char in "0123456789abcdef" for char in digest)
        for relative, digest in plan.items()
    )
    if not plan or not valid:
        fail("布局迁移计划无效")
    return {relative: digest for relative, digest in plan.items()}


def expected_transition_paths(root: Path, baseline: Path, ids: tuple[str, ...], support: dict[str, str]) -> set[str]:
    paths = set(MIGRATION_SUPPORT_PATHS) | set(support)
    for plugin_id in ids:
        legacy = LEGACY_PLUGIN_ROOT / plugin_id
        snapshot = SNAPSHOT_ROOT / plugin_id
        paths.add(legacy.as_posix())
        paths.update((legacy / path).as_posix() for path in regular_files(baseline / legacy))
        paths.update((snapshot / path).as_posix() for path in regular_files(root / snapshot))
    return paths


def verify_support_hashes(root: Path, support: dict[str, str]) -> None:
    for relative, digest in support.items():
        path = root / relative
        if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            fail(f"布局迁移支持文件哈希不匹配: {relative}")


def verify_transition_paths(root: Path, baseline: Path, ids: tuple[str, ...], before: str, after: str) -> None:
    support = migration_support_hashes()
    actual = set(gitlines(root, ["diff", "--name-only", "--no-renames", before, after]))
    expected = expected_transition_paths(root, baseline, ids, support)
    if actual != expected:
        unexpected = ", ".join(sorted(actual - expected)) or "<none>"
        missing = ", ".join(sorted(expected - actual)) or "<none>"
        fail(f"目录迁移变更路径不匹配: unexpected={unexpected}; missing={missing}")
    verify_support_hashes(root, support)


def verify(root: Path, baseline: Path, *, before: str | None = None, after: str | None = None) -> None:
    root = require_directory(root, "当前工厂目录")
    baseline = require_directory(baseline, "工厂基线目录")
    if (before is None) != (after is None):
        fail("目录迁移变更路径校验必须同时提供 before 和 after")
    if root == baseline:
        fail("工厂基线必须与当前目录不同")
    if read_json(root / MIGRATION_MARKER, "布局迁移标记") != MARKER:
        fail("布局迁移标记无效")
    if (baseline / MIGRATION_MARKER).exists() or (baseline / MIGRATION_MARKER).is_symlink():
        fail("布局迁移只能从未迁移的基线开始")
    current_index = read_json(root / MARKETPLACE_PATH, "当前市场索引")
    baseline_index = read_json(baseline / MARKETPLACE_PATH, "基线市场索引")
    ids = plugin_ids(current_index, PurePosixPath(*SNAPSHOT_ROOT.parts))
    if plugin_ids(baseline_index, PurePosixPath(*LEGACY_PLUGIN_ROOT.parts)) != ids:
        fail("市场插件集合不能随目录迁移改变")
    if current_index != expected_snapshot_index(baseline_index):
        fail("目录迁移只能重写市场索引中的快照路径")
    require_missing(root / MARKETPLACE_PATH.with_name("marketplace.json.sig.jws.json"), "市场索引签名")
    for plugin_id in ids:
        current = root / SNAPSHOT_ROOT / plugin_id
        previous = baseline / LEGACY_PLUGIN_ROOT / plugin_id
        if snapshot_files(current, plugin_id) != snapshot_files(previous, plugin_id):
            fail(f"插件 {plugin_id} 的发布快照不能随目录迁移改变")
        require_missing(current / RELEASE_SIDECAR, f"插件 {plugin_id} 的发布签名")
    verify_factory_metadata(root, baseline)
    verify_submodules(root, ids)
    verify_predecessor_signatures(baseline, ids)
    if before is not None and after is not None:
        verify_transition_paths(root, baseline, ids, before, after)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--baseline-root", type=Path, required=True)
    parser.add_argument("--before")
    parser.add_argument("--after")
    args = parser.parse_args()
    try:
        verify(args.root, args.baseline_root, before=args.before, after=args.after)
    except (FactoryLayoutMigrationError, MarketplaceKmsPublisherError) as error:
        raise SystemExit(f"工厂布局迁移校验失败: {error}") from error
    print("工厂布局迁移基线和历史签名校验通过")


if __name__ == "__main__":
    main()
