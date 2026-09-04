"""Static Factory recipes for official native MCP sidecars.

The Factory accepts pre-built binaries only through this module's small,
reviewed allowlist.  It never discovers or executes a command from a plugin
source tree.  A protected release runner is responsible for compiling the
listed Rust targets and passing their regular-file outputs explicitly.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tempfile
from typing import Iterator, Mapping, Sequence


MAX_SIDECAR_BYTES = 64 * 1024 * 1024
SOURCE_REVISION_PATTERN = re.compile(r"^[0-9a-f]{40}$")
NATIVE_SIDECAR_PERMISSIONS = frozenset({"mcp.servers.register", "native.execute"})
NATIVE_SIDECAR_TARGET_MATRIX_VERSION = 2
LEGACY_NATIVE_SIDECAR_RUST_TARGETS = frozenset({
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "x86_64-pc-windows-msvc",
})


@dataclass(frozen=True)
class NativeTarget:
    rust_target: str
    os_name: str
    arch: str


@dataclass(frozen=True)
class NativeStdioServer:
    server_id: str
    args: tuple[str, ...] = ()
    env: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class NativeSidecarRecipe:
    plugin_id: str
    skill_id: str
    source_repository: str
    archive_path: PurePosixPath
    servers: tuple[NativeStdioServer, ...]
    targets: tuple[NativeTarget, ...]


ATTACK_PATH_RECIPE = NativeSidecarRecipe(
    plugin_id="com.xsec.attack-path",
    skill_id="attack-path",
    source_repository="tzf1003/xSecDesktop",
    archive_path=PurePosixPath("bin/attack-path-mcp"),
    servers=(NativeStdioServer("attack-path"),),
    targets=(
        NativeTarget("aarch64-apple-darwin", "macos", "aarch64"),
        NativeTarget("x86_64-apple-darwin", "macos", "x86_64"),
        NativeTarget("x86_64-unknown-linux-gnu", "linux", "x86_64"),
        NativeTarget("x86_64-pc-windows-msvc", "windows", "x86_64"),
    ),
)

ASSET_DISCOVERY_RECIPE = NativeSidecarRecipe(
    plugin_id="com.xsec.asset-discovery",
    skill_id="asset-discovery",
    source_repository="tzf1003/xSecDesktop",
    archive_path=PurePosixPath("bin/asset-discovery-mcp"),
    servers=(
        NativeStdioServer("asset-normalize"),
        NativeStdioServer(
            "asset-hunter",
            args=("--provider", "hunter"),
            env=(("XSEC_ASSET_HUNTER_API_BASE_URL", "https://hunter.qianxin.com/openApi/search"),),
        ),
        NativeStdioServer(
            "asset-fofa",
            args=("--provider", "fofa"),
            env=(("XSEC_ASSET_FOFA_API_BASE_URL", "https://fofoapi.com"),),
        ),
    ),
    targets=(
        NativeTarget("aarch64-apple-darwin", "macos", "aarch64"),
        NativeTarget("x86_64-apple-darwin", "macos", "x86_64"),
        NativeTarget("x86_64-unknown-linux-gnu", "linux", "x86_64"),
        NativeTarget("x86_64-pc-windows-msvc", "windows", "x86_64"),
    ),
)

RECIPES = {
    ATTACK_PATH_RECIPE.plugin_id: ATTACK_PATH_RECIPE,
    ASSET_DISCOVERY_RECIPE.plugin_id: ASSET_DISCOVERY_RECIPE,
}


def archive_path_for(recipe: NativeSidecarRecipe, target: NativeTarget) -> PurePosixPath:
    """Return the executable pathname for one immutable platform artifact."""

    if target.os_name == "windows":
        return recipe.archive_path.with_suffix(".exe")
    return recipe.archive_path


def mcp_command_for(recipe: NativeSidecarRecipe, target: NativeTarget | None = None) -> str:
    """Return the artifact-local stdio command for source or one platform."""

    path = recipe.archive_path if target is None else archive_path_for(recipe, target)
    return f"./{path.as_posix()}"


def provenance_for_inputs(
    recipe: NativeSidecarRecipe,
    source_revision: str,
    inputs: Mapping[str, Path],
) -> dict[str, object]:
    """Return immutable source and binary evidence for one native release."""

    if not SOURCE_REVISION_PATTERN.fullmatch(source_revision):
        raise ValueError("native sidecar source revision must be a lowercase 40-character Git SHA")
    targets = []
    for target in recipe.targets:
        binary = inputs.get(target.rust_target)
        if binary is None:
            raise ValueError(f"missing native sidecar input: {recipe.plugin_id}@{target.rust_target}")
        targets.append({
            "rustTarget": target.rust_target,
            "os": target.os_name,
            "arch": target.arch,
            "sha256": sha256_file(binary),
        })
    return {
        "source": {
            "repository": recipe.source_repository,
            "revision": source_revision,
        },
        "targetMatrixVersion": NATIVE_SIDECAR_TARGET_MATRIX_VERSION,
        "targets": targets,
    }


def validate_provenance(recipe: NativeSidecarRecipe, value: object) -> dict[str, object]:
    """Validate signed release metadata before comparing packaged binaries."""

    if not isinstance(value, dict) or set(value) not in (
        {"source", "targets"},
        {"source", "targetMatrixVersion", "targets"},
    ):
        raise ValueError("native sidecar provenance has an unsupported schema")
    targets = value.get("targets")
    revision = provenance_source_revision(recipe, value.get("source"))
    target_matrix_version = value.get("targetMatrixVersion")
    expected_targets = targets_for_provenance_version(recipe, target_matrix_version)
    if not isinstance(targets, list) or len(targets) != len(expected_targets):
        raise ValueError("native sidecar provenance must declare every allowlisted target exactly once")
    actual: dict[str, dict[str, object]] = {}
    for target in targets:
        if not isinstance(target, dict) or set(target) != {"rustTarget", "os", "arch", "sha256"}:
            raise ValueError("native sidecar provenance target has an invalid schema")
        rust_target = target.get("rustTarget")
        digest = target.get("sha256")
        if not isinstance(rust_target, str) or rust_target in actual:
            raise ValueError("native sidecar provenance has duplicate or invalid Rust targets")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("native sidecar provenance target must have a lowercase SHA-256")
        actual[rust_target] = target
    normalized_targets = []
    for expected in expected_targets:
        target = actual.get(expected.rust_target)
        if target is None or target.get("os") != expected.os_name or target.get("arch") != expected.arch:
            raise ValueError(f"native sidecar provenance has invalid target {expected.rust_target}")
        normalized_targets.append({
            "rustTarget": expected.rust_target,
            "os": expected.os_name,
            "arch": expected.arch,
            "sha256": target["sha256"],
        })
    normalized = {
        "source": {"repository": recipe.source_repository, "revision": revision},
        "targets": normalized_targets,
    }
    if target_matrix_version is not None:
        normalized["targetMatrixVersion"] = target_matrix_version
    return normalized


def provenance_source_revision(recipe: NativeSidecarRecipe, source: object) -> str:
    """Validate the immutable source evidence and return its revision."""

    if not isinstance(source, dict) or set(source) != {"repository", "revision"}:
        raise ValueError("native sidecar provenance source must contain repository and revision")
    if source.get("repository") != recipe.source_repository:
        raise ValueError(f"native sidecar provenance source must be {recipe.source_repository}")
    revision = source.get("revision")
    if not isinstance(revision, str) or not SOURCE_REVISION_PATTERN.fullmatch(revision):
        raise ValueError("native sidecar provenance source revision must be a lowercase 40-character Git SHA")
    return revision


def targets_for_provenance_version(
    recipe: NativeSidecarRecipe,
    target_matrix_version: object,
) -> tuple[NativeTarget, ...]:
    """Return the exact target matrix selected by signed provenance."""

    if target_matrix_version is None:
        return tuple(
            target
            for target in recipe.targets
            if target.rust_target in LEGACY_NATIVE_SIDECAR_RUST_TARGETS
        )
    if target_matrix_version == NATIVE_SIDECAR_TARGET_MATRIX_VERSION:
        return recipe.targets
    raise ValueError("native sidecar provenance has an unsupported target matrix version")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_native_sidecar_inputs(values: Sequence[str]) -> dict[tuple[str, str], Path]:
    """Parse ``plugin-id@rust-target=path`` inputs without shell expansion."""

    parsed: dict[tuple[str, str], Path] = {}
    for value in values:
        key, separator, raw_path = value.partition("=")
        plugin_id, at, rust_target = key.partition("@")
        if not separator or not at or not plugin_id or not rust_target or not raw_path:
            raise ValueError("native sidecar input must use plugin-id@rust-target=path")
        identity = (plugin_id, rust_target)
        if identity in parsed:
            raise ValueError(f"duplicate native sidecar input for {plugin_id}@{rust_target}")
        recipe = RECIPES.get(plugin_id)
        if recipe is None:
            raise ValueError(f"native sidecar input is not allowlisted: {plugin_id}@{rust_target}")
        target_for(recipe, rust_target)
        parsed[identity] = Path(raw_path)
    return parsed


def recipe_for_source(plugin_id: str, source_dir: Path) -> NativeSidecarRecipe | None:
    """Return the recipe only for an explicit native Agent Plugin contract."""

    if not source_declares_native_sidecar_contract(source_dir, plugin_id):
        return None
    recipe = RECIPES.get(plugin_id)
    if recipe is None:
        raise ValueError(f"native MCP plugin is not on the Factory allowlist: {plugin_id}")
    mcp_path = source_dir / "mcp.json"
    if not os.path.lexists(mcp_path):
        raise ValueError(f"native MCP plugin must provide mcp.json: {plugin_id}")
    raw = read_regular_mcp(mcp_path, f"{plugin_id} mcp.json")
    validate_mcp_declaration(recipe, raw, f"{plugin_id} mcp.json")
    return recipe


def source_declares_native_sidecar_contract(source_dir: Path, plugin_id: str) -> bool:
    """Read the manifest marker that opts a source into Factory sidecars."""

    path = source_dir / "plugin.json"
    raw = read_regular_mcp(path, f"{plugin_id} plugin.json")
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{plugin_id} plugin.json is invalid JSON: {error}") from error
    return declares_native_sidecar_contract(manifest)


def declares_native_sidecar_contract(manifest: object) -> bool:
    """Require both the v2 host schema and its explicit native authorities."""

    if not isinstance(manifest, dict):
        return False
    extensions = manifest.get("extensions")
    desktop = extensions.get("com.xsec.desktop") if isinstance(extensions, dict) else None
    permissions = desktop.get("permissions") if isinstance(desktop, dict) else None
    return (
        isinstance(desktop, dict)
        and desktop.get("schemaVersion") == 2
        and isinstance(permissions, dict)
        and NATIVE_SIDECAR_PERMISSIONS.issubset(permissions)
    )


def read_regular_mcp(path: Path, label: str) -> bytes:
    """Read mcp.json only after refusing symlinks and non-file entries."""

    try:
        metadata = os.lstat(path)
    except OSError as error:
        raise ValueError(f"read {label}: {error}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"{label} must be a regular file")
    try:
        return path.read_bytes()
    except OSError as error:
        raise ValueError(f"read {label}: {error}") from error


def mcp_servers(raw: bytes, label: str) -> Mapping[str, object]:
    """Parse the portable MCP document before applying a native policy."""

    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} is invalid JSON: {error}") from error
    servers = value.get("mcpServers") if isinstance(value, dict) else None
    if not isinstance(servers, dict):
        raise ValueError(f"{label} must contain an mcpServers object")
    return servers


def declares_stdio_server(raw: bytes, label: str) -> bool:
    return any(isinstance(server, dict) and server.get("type") == "stdio" for server in mcp_servers(raw, label).values())


def validate_mcp_declaration(
    recipe: NativeSidecarRecipe,
    raw: bytes,
    label: str,
    target: NativeTarget | None = None,
) -> None:
    servers = mcp_servers(raw, label)
    expected_names = {server.server_id for server in recipe.servers}
    if set(servers.keys()) != expected_names:
        raise ValueError(f"{label} must declare only the allowlisted stdio servers")
    for server in servers.values():
        if not isinstance(server, dict) or server.get("type") != "stdio":
            raise ValueError(f"{label} must declare only the allowlisted stdio servers")
    command = mcp_command_for(recipe, target)
    for expected in recipe.servers:
        server = servers.get(expected.server_id)
        if not isinstance(server, dict) or server.get("command") != command:
            raise ValueError(f"{label} must declare {expected.server_id} at {command}")
        if server.get("args", []) != list(expected.args):
            raise ValueError(f"{label} has invalid arguments for {expected.server_id}")
        if server.get("cwd") != "${PLUGIN_DATA}":
            raise ValueError(f"{label} must run {expected.server_id} with cwd=${{PLUGIN_DATA}}")
        if server.get("env", {}) != dict(expected.env):
            raise ValueError(f"{label} has invalid environment for {expected.server_id}")


def require_inputs(recipe: NativeSidecarRecipe, inputs: Mapping[tuple[str, str], Path]) -> dict[str, Path]:
    expected = {(recipe.plugin_id, target.rust_target) for target in recipe.targets}
    supplied = {identity for identity in inputs if identity[0] == recipe.plugin_id}
    unknown = supplied - expected
    if unknown:
        plugin_id, target = sorted(unknown)[0]
        raise ValueError(f"native sidecar input is not allowlisted: {plugin_id}@{target}")
    missing = expected - supplied
    if missing:
        plugin_id, target = sorted(missing)[0]
        raise ValueError(f"missing native sidecar input: {plugin_id}@{target}")
    return {target: require_regular_input(inputs[(recipe.plugin_id, target)]) for _, target in expected}


def require_regular_input(path: Path) -> Path:
    try:
        metadata = os.lstat(path)
    except OSError as error:
        raise ValueError(f"read native sidecar input {path}: {error}") from error
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size == 0 or metadata.st_size > MAX_SIDECAR_BYTES:
        raise ValueError(f"native sidecar input must be a non-empty regular file within {MAX_SIDECAR_BYTES} bytes: {path}")
    return path.resolve(strict=True)


@contextmanager
def staged_plugin(
    source_dir: Path,
    files: Sequence[Path],
    recipe: NativeSidecarRecipe,
    target: NativeTarget,
    sidecar: Path,
) -> Iterator[Path]:
    """Copy verified source files and one allowlisted binary into a clean tree."""

    with tempfile.TemporaryDirectory(prefix="xsec-native-sidecar-") as directory:
        staging = Path(directory) / "plugin"
        copy_source_files(source_dir, staging, files, native_archive_paths(recipe))
        rewrite_mcp_command(staging, recipe, target)
        entrypoint = staging / archive_path_for(recipe, target)
        entrypoint.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(sidecar, entrypoint)
        entrypoint.chmod(0o755)
        yield staging


def native_archive_paths(recipe: NativeSidecarRecipe) -> set[PurePosixPath]:
    return {archive_path_for(recipe, target) for target in recipe.targets}


def copy_source_files(
    source_dir: Path,
    staging: Path,
    files: Sequence[Path],
    native_paths: set[PurePosixPath],
) -> None:
    for source in files:
        relative = source.relative_to(source_dir)
        if PurePosixPath(relative.as_posix()) in native_paths:
            raise ValueError(f"native sidecar must be supplied by the Factory recipe, not source: {relative}")
        destination = staging / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)


def rewrite_mcp_command(staging: Path, recipe: NativeSidecarRecipe, target: NativeTarget) -> None:
    """Use the executable filename expected by this platform artifact."""

    if archive_path_for(recipe, target) == recipe.archive_path:
        return
    path = staging / "mcp.json"
    try:
        document = json.loads(read_regular_mcp(path, f"staged {recipe.plugin_id} mcp.json"))
        servers = document["mcpServers"]
        for server in recipe.servers:
            servers[server.server_id]["command"] = mcp_command_for(recipe, target)
    except (KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot stage platform MCP declaration for {recipe.plugin_id}: {error}") from error
    path.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def target_for(recipe: NativeSidecarRecipe, rust_target: str) -> NativeTarget:
    for target in recipe.targets:
        if target.rust_target == rust_target:
            return target
    raise ValueError(f"native sidecar target is not allowlisted: {recipe.plugin_id}@{rust_target}")


def archive_member_is_regular_file(member: object) -> bool:
    is_directory = getattr(member, "is_dir", lambda: False)()
    mode = int(getattr(member, "external_attr", 0)) >> 16
    return not is_directory and stat.S_IFMT(mode) in {0, stat.S_IFREG}


def archive_member_is_executable(member: object) -> bool:
    return archive_member_is_regular_file(member) and bool((int(getattr(member, "external_attr", 0)) >> 16) & 0o111)


def validate_native_archive(
    plugin_id: str,
    archive_members: Mapping[str, object],
    mcp_bytes: bytes | None,
    os_name: str,
    arch: str,
) -> bool:
    """Validate a native artifact's platform and required portable entrypoint.

    ``archive_members`` is intentionally opaque to keep ZIP-library handling at
    the caller. The native entrypoint itself must still be a regular file.
    """

    if "mcp.json" not in archive_members:
        return False
    mcp_member = archive_members["mcp.json"]
    if not archive_member_is_regular_file(mcp_member):
        raise ValueError(f"native MCP artifact mcp.json must be a regular file: {plugin_id}")
    if mcp_bytes is None:
        raise ValueError(f"native MCP artifact cannot read mcp.json: {plugin_id}")
    if not declares_stdio_server(mcp_bytes, f"artifact {plugin_id} mcp.json"):
        raise ValueError(f"native MCP artifact must declare a stdio server: {plugin_id}")
    recipe = RECIPES.get(plugin_id)
    if recipe is None:
        raise ValueError(f"native MCP artifact is not on the Factory allowlist: {plugin_id}")
    target = next((item for item in recipe.targets if item.os_name == os_name and item.arch == arch), None)
    if target is None:
        raise ValueError(f"native MCP artifact has unsupported target {os_name}/{arch}: {plugin_id}")
    validate_mcp_declaration(recipe, mcp_bytes, f"artifact {plugin_id} mcp.json", target)
    entrypoint = archive_path_for(recipe, target).as_posix()
    member = archive_members.get(entrypoint)
    if member is None:
        raise ValueError(f"native MCP artifact is missing {entrypoint}: {plugin_id}")
    if not archive_member_is_regular_file(member):
        raise ValueError(f"native MCP artifact entrypoint must be a regular file: {plugin_id}")
    if not archive_member_is_executable(member):
        raise ValueError(f"native MCP artifact entrypoint must be executable: {plugin_id}")
    return True
