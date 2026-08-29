#!/usr/bin/env python3
"""Materialize a split first-party source repository from signed Factory artifacts.

This is a migration tool, not a publisher.  It deliberately starts from the
immutable Beta/Stable artifact selected by the retained Factory release index,
then creates two source branches whose tip trees contain no Marketplace
metadata, artifacts or signatures.  A bounded, filtered copy of the legacy
plugin history is retained below those tips for developer context.

The default command is a dry run: it creates the candidate repository only in
an automatically removed temporary directory and prints the two source commit
IDs plus the *pending* Registry v2 record.  ``--push`` is the sole remote-write
mode.  It accepts only the statically approved public GitHub target for the
selected plugin, requires both remote branches to be absent and never forces a
push.  The tool never reads, creates or prints credentials, tokens or KMS
material, and it never creates an adoption proof or activates a Registry row.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile

from build_market import RELEASE_ID_PATTERN, is_link, load_release_document
from external_source_factory import FIRST_PARTY_APPROVED_SOURCES
from kms_marketplace_publisher import MarketplaceDocument, MarketplaceKmsPublisherError, verify_historical_sidecar_signature
from validate_market import validate_archive, validate_zip_member


ROOT = Path(__file__).resolve().parents[1]
GIT_SHA_PATTERN = re.compile(r"^[a-f0-9]{40}$")
ARTIFACT_DIGEST_PATTERN = re.compile(r"^[a-f0-9]{64}$")
FORBIDDEN_SOURCE_SUFFIXES = (".xsec-plugin", ".sig.jws.json")
MIGRATION_AUTHOR_NAME = "XSEC Marketplace Migration"
MIGRATION_AUTHOR_EMAIL = "xsec-marketplace-migration@users.noreply.github.com"
TRUSTED_FACTORY_ORIGIN = "https://github.com/tzf1003/xsec-plugins.git"
TRANSPORT_ENVIRONMENT_KEYS = (
    "GIT_CONFIG",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_PARAMETERS",
    "GIT_SSL_NO_VERIFY",
    "GIT_HTTP_PROXY",
    "HTTP_PROXY",
    "http_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
    "GIT_ASKPASS",
    "SSH_ASKPASS",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_COMMON_DIR",
    "GIT_CEILING_DIRECTORIES",
    "GIT_DISCOVERY_ACROSS_FILESYSTEM",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_TEMPLATE_DIR",
)


def safe_openssh_command() -> str:
    """Return the only SSH transport command accepted for an approved target.

    ``GIT_SSH_COMMAND`` normally inherits ``~/.ssh/config``.  A ``Host
    github.com`` entry can then replace the hostname or add a ProxyCommand
    even when Git itself did not rewrite the URL.  The materializer only needs
    standard GitHub SSH transport, so use the null user configuration and
    command-line settings that lock down routing and host-key verification.
    The caller's SSH agent remains available for authentication; this tool
    never reads a key or token itself.
    """

    return " ".join(
        (
            "ssh",
            "-F",
            os.devnull,
            "-o",
            "Hostname=github.com",
            "-o",
            "User=git",
            "-o",
            "ProxyCommand=none",
            "-o",
            "ProxyJump=none",
            "-o",
            "CanonicalizeHostname=no",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "HostKeyAlias=github.com",
            "-o",
            "UserKnownHostsFile=~/.ssh/known_hosts",
            "-o",
            "GlobalKnownHostsFile=none",
            "-o",
            "UpdateHostKeys=no",
            "-o",
            "PermitLocalCommand=no",
        )
    )


class MaterializationError(ValueError):
    """The migration must stop before producing or pushing a source branch."""


def fail(message: str) -> None:
    raise MaterializationError(message)


def run_git(
    arguments: list[str],
    *,
    cwd: Path | None = None,
    input_bytes: bytes | None = None,
    environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    """Run Git without a shell and retain diagnostics for a fail-closed error."""

    command = ["git", *arguments]
    completed = subprocess.run(
        command,
        cwd=None if cwd is None else str(cwd),
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        check=False,
    )
    if completed.returncode:
        diagnostic = completed.stderr.decode("utf-8", errors="replace").strip()
        fail(f"Git command failed ({' '.join(arguments[:2])}): {diagnostic or 'unknown error'}")
    return completed


def git_stdout(
    arguments: list[str],
    *,
    cwd: Path,
    environment: dict[str, str] | None = None,
) -> str:
    return run_git(arguments, cwd=cwd, environment=environment).stdout.decode("utf-8", errors="strict").strip()


def trusted_history_environment() -> dict[str, str]:
    """Disable replacement objects for every read of Factory Git history.

    ``refs/replace/*`` is a local presentation layer: it can change the tree
    seen by ``fast-export`` without changing a branch's visible SHA.  The
    initial source migration binds public ancestry to the protected Factory
    history, so replacement refs are forbidden and Git's replacement feature
    stays disabled even if a process environment tries to re-enable it.
    """

    environment = os.environ.copy()
    environment.pop("GIT_REPLACE_REF_BASE", None)
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    return environment


def factory_git_stdout(factory_root: Path, arguments: list[str]) -> str:
    """Read the trusted Factory worktree with replacement objects disabled."""

    return git_stdout(arguments, cwd=factory_root, environment=trusted_history_environment())


def factory_git_blob(factory_root: Path, revision: str, path: PurePosixPath) -> bytes:
    """Read one exact, trusted Factory blob without checkout EOL conversion.

    Marketplace KMS envelopes bind document *bytes*.  On Windows, Git may
    materialize a text blob as CRLF in the worktree even though the signed
    protected-main blob is LF.  The first-party materializer has already
    pinned ``HEAD`` to the trusted remote main before it calls this helper, so
    authenticate the immutable Git object rather than a checkout presentation
    of that object.
    """

    if revision != "HEAD" or path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        fail("trusted Factory release document path is invalid")
    return run_git(
        ["cat-file", "blob", f"{revision}:{path.as_posix()}"],
        cwd=factory_root,
        environment=trusted_history_environment(),
    ).stdout


def sealed_transport_environment(
    *,
    protocols: tuple[str, ...],
    repository_discovery_ceiling: Path | None = None,
) -> dict[str, str]:
    """Return an environment that cannot inherit user transport rewrites.

    Remote Factory history and first-party source branches are security
    boundaries.  Do not allow the caller's environment, proxy selection or
    global/system Git configuration to reinterpret a literal approved URL.
    Repository-local configuration is deliberately excluded by using a fresh
    temporary directory for read-only remote lookups; the sole write path
    rejects its newly-created repository's URL rewrite rules separately.
    """

    environment = os.environ.copy()
    for key in TRANSPORT_ENVIRONMENT_KEYS:
        environment.pop(key, None)
    for key in tuple(environment):
        if key.startswith(("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")):
            environment.pop(key, None)
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ALLOW_PROTOCOL": ":".join(protocols),
        }
    )
    if repository_discovery_ceiling is not None:
        try:
            environment["GIT_CEILING_DIRECTORIES"] = str(repository_discovery_ceiling.resolve(strict=True))
        except OSError as error:
            raise MaterializationError("cannot isolate Git transport from repository discovery") from error
    if "ssh" in protocols:
        environment["GIT_SSH_COMMAND"] = safe_openssh_command()
        environment["GIT_SSH_VARIANT"] = "ssh"
    return environment


def sealed_transport_arguments(*, protocols: tuple[str, ...]) -> list[str]:
    """Return Git options paired with :func:`sealed_transport_environment`."""

    arguments = [
        "-c",
        "credential.helper=",
        "-c",
        "http.sslVerify=true",
        "-c",
        "http.followRedirects=false",
        "-c",
        "protocol.allow=never",
    ]
    for protocol in protocols:
        arguments.extend(["-c", f"protocol.{protocol}.allow=always"])
    return arguments


def candidate_environment(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Seal all Git configuration used while constructing a public source tree.

    The candidate starts life on the operator's machine.  Global/system
    configuration must not choose a template, hook path, replacement object,
    credential helper, or other process behavior while its commits are made.
    The candidate never needs a transport until the separately sealed push.
    """

    environment = sealed_transport_environment(protocols=())
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    environment.pop("GIT_REPLACE_REF_BASE", None)
    if extra is not None:
        environment.update(extra)
    return environment


def candidate_git_arguments(arguments: list[str]) -> list[str]:
    """Force every candidate-repository Git command to ignore all hooks."""

    return ["-c", f"core.hooksPath={os.devnull}", *arguments]


def candidate_run_git(
    arguments: list[str],
    *,
    cwd: Path,
    input_bytes: bytes | None = None,
    environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    return run_git(
        candidate_git_arguments(arguments),
        cwd=cwd,
        input_bytes=input_bytes,
        environment=candidate_environment(environment),
    )


def candidate_git_stdout(
    arguments: list[str],
    *,
    cwd: Path,
    environment: dict[str, str] | None = None,
) -> str:
    return candidate_run_git(arguments, cwd=cwd, environment=environment).stdout.decode("utf-8", errors="strict").strip()


def assert_no_local_url_rewrites(repository: Path) -> None:
    """Fail if the temporary source repository can rewrite a remote URL.

    Global and system files are sealed out for every remote operation.  A
    local ``url.*.insteadOf`` or ``pushInsteadOf`` entry would still take
    precedence for ``git push <literal-url>``, so inspect only the local file
    (without include processing) and reject it before the target preflight or
    write.  The repository is generated by this tool and normally has no such
    entries; an entry is always an integrity failure, never an operator hint.
    """

    completed = subprocess.run(
        ["git", "config", "--local", "--no-includes", "--null", "--list"],
        cwd=str(repository),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=sealed_transport_environment(protocols=("https", "ssh")),
        check=False,
    )
    if completed.returncode:
        diagnostic = completed.stderr.decode("utf-8", errors="replace").strip()
        fail(f"cannot inspect materialized source local Git config: {diagnostic or 'unknown error'}")
    for item in completed.stdout.split(b"\0"):
        if not item:
            continue
        key = item.split(b"\n", 1)[0].decode("ascii", errors="replace").lower()
        if key.startswith("url.") and key.endswith((".insteadof", ".pushinsteadof")):
            fail("materialized source repository must not contain Git URL rewrite configuration")


def trusted_factory_remote_main(factory_root: Path) -> str:
    """Resolve the public Factory ``main`` head without trusting local refs.

    A clean clone can retain an obsolete ``origin/main`` indefinitely. Source
    commits reconstructed from that stale immutable history would later look
    structurally valid to adoption, so query only the canonical HTTPS Factory
    remote before any artifact or history is read.  This is deliberately a
    no-write, no-prompt transport with global/system Git configuration ignored.
    """

    # Do not run from ``factory_root``: local ``url.*.insteadOf`` rules are
    # loaded after global/system config and could silently replace the literal
    # URL above.  A private, empty working directory prevents Git repository
    # discovery from loading any Factory-local config at all.
    with tempfile.TemporaryDirectory(prefix="xsec-factory-remote-check-") as directory:
        transport_root = Path(directory)
        output = run_git(
            [
                *sealed_transport_arguments(protocols=("https",)),
                "ls-remote",
                "--refs",
                TRUSTED_FACTORY_ORIGIN,
                "refs/heads/main",
            ],
            cwd=transport_root,
            environment=sealed_transport_environment(
                protocols=("https",),
                repository_discovery_ceiling=transport_root,
            ),
        ).stdout.decode("utf-8", errors="strict").splitlines()
    if len(output) != 1:
        fail("trusted Factory remote main revision is unavailable")
    fields = output[0].split("\t")
    if len(fields) != 2 or fields[1] != "refs/heads/main" or not GIT_SHA_PATTERN.fullmatch(fields[0]):
        fail("trusted Factory remote main revision is invalid")
    return fields[0]


def safe_plugin_id(value: str) -> str:
    if value not in FIRST_PARTY_APPROVED_SOURCES:
        fail("plugin ID is not one of the eleven approved first-party source mappings")
    return value


def require_exact_target(plugin_id: str, target: str) -> str:
    """Accept only canonical GitHub HTTPS/SSH spellings of the static mapping."""

    expected = FIRST_PARTY_APPROVED_SOURCES[plugin_id]
    allowed = {
        f"https://github.com/{expected}.git",
        f"https://github.com/{expected}",
        f"git@github.com:{expected}.git",
        f"git@github.com:{expected}",
        f"ssh://git@github.com/{expected}.git",
        f"ssh://git@github.com/{expected}",
    }
    if target not in allowed:
        fail("target must be the exact approved public GitHub repository for this first-party plugin")
    # Preserve the caller's exact approved transport spelling. This lets a
    # developer use an existing SSH agent without this tool discovering or
    # transforming credentials, while the static owner/repository comparison
    # still prevents a redirect to another target.
    return target


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while True:
                block = handle.read(1024 * 1024)
                if not block:
                    break
                digest.update(block)
    except OSError as error:
        fail(f"cannot read immutable release artifact: {error}")
    return digest.hexdigest()


def safe_artifact_path(release_path: Path, raw_url: object) -> Path:
    if not isinstance(raw_url, str) or not raw_url or "\\" in raw_url:
        fail("release artifact URL must be a relative portable path")
    path = PurePosixPath(raw_url)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} or ":" in part for part in path.parts):
        fail("release artifact URL escaped the retained release directory")
    candidate = release_path.parent.joinpath(*path.parts)
    try:
        resolved_parent = release_path.parent.resolve(strict=True)
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(resolved_parent)
    except (OSError, ValueError) as error:
        raise MaterializationError("release artifact URL escaped the retained release directory") from error
    if not resolved.is_file() or resolved.is_symlink():
        fail("release artifact must be a regular retained Factory file")
    return resolved


def selected_release_artifact(factory_root: Path, plugin_id: str, channel: str) -> tuple[dict[str, object], Path]:
    if channel not in {"beta", "stable"}:
        fail("release channel must be beta or stable")
    release_path = factory_root / "plugins" / plugin_id / ".xsec-market" / "releases.json"
    try:
        document = load_release_document(release_path, plugin_id)
    except (OSError, ValueError) as error:
        raise MaterializationError(f"retained release history is invalid for {plugin_id}: {error}") from error
    channels = document.get("channels")
    pointer = channels.get(channel) if isinstance(channels, dict) else None
    release_id = pointer.get("releaseId") if isinstance(pointer, dict) else None
    if not isinstance(release_id, str) or not RELEASE_ID_PATTERN.fullmatch(release_id):
        fail(f"retained {channel} pointer is unavailable")
    records = document.get("releases")
    if not isinstance(records, list):
        fail("retained release history has no records")
    record = next((item for item in records if isinstance(item, dict) and item.get("releaseId") == release_id), None)
    if record is None:
        fail(f"retained {channel} pointer does not name an immutable release record")
    artifacts = record.get("artifacts")
    if not isinstance(artifacts, list):
        fail("retained release record has invalid artifacts")
    portable = [
        artifact
        for artifact in artifacts
        if isinstance(artifact, dict) and artifact.get("os") == "any" and artifact.get("arch") == "any"
    ]
    if len(portable) != 1:
        fail("first-party source materialization requires exactly one any/any immutable artifact")
    artifact = portable[0]
    digest = artifact.get("sha256")
    if not isinstance(digest, str) or not ARTIFACT_DIGEST_PATTERN.fullmatch(digest):
        fail("retained release artifact SHA-256 is invalid")
    path = safe_artifact_path(release_path, artifact.get("url"))
    if sha256_file(path) != digest:
        fail("retained release artifact SHA-256 does not match its immutable release record")
    version = record.get("version")
    if not isinstance(version, str):
        fail("retained release record version is invalid")
    try:
        # Historical Stable packages are intentionally not held to a newly
        # introduced frontend rule, but all archive-safety and manifest checks
        # still run before extraction.
        validate_archive(path, plugin_id, version, require_current_official_frontend_contract=False)
    except ValueError as error:
        raise MaterializationError(f"retained {channel} artifact is not safely extractable: {error}") from error
    if sha256_file(path) != digest:
        fail("retained release artifact changed while it was being verified")
    return record, path


def verify_retained_release_signature(factory_root: Path, plugin_id: str) -> None:
    """Authenticate the exact release index before using any artifact it names."""

    release_path = factory_root / "plugins" / plugin_id / ".xsec-market" / "releases.json"
    sidecar = release_path.with_name("releases.json.sig.jws.json")
    if is_link(release_path) or is_link(sidecar) or not release_path.is_file() or not sidecar.is_file():
        fail("retained release history and its KMS sidecar must be regular files")
    subject = PurePosixPath("plugins") / plugin_id / ".xsec-market" / "releases.json"
    # Do not verify the potentially EOL-converted Windows worktree file. The
    # trusted Factory preflight pins HEAD to origin/main, and the signature is
    # over the Git blob that Desktop receives from the protected repository.
    signed_bytes = factory_git_blob(factory_root, "HEAD", subject)
    try:
        with tempfile.TemporaryDirectory(prefix="xsec-materializer-signed-release-") as directory:
            signed_document = Path(directory) / "releases.json"
            signed_document.write_bytes(signed_bytes)
            document = MarketplaceDocument(
                "xsec.plugin-marketplace.release",
                subject.as_posix(),
                signed_document,
            )
            verify_historical_sidecar_signature(sidecar.read_bytes(), document)
    except (OSError, MarketplaceKmsPublisherError) as error:
        raise MaterializationError("retained release KMS sidecar is invalid") from error


def source_member_is_forbidden(path: PurePosixPath) -> bool:
    return ".xsec-market" in path.parts or path.name.endswith(FORBIDDEN_SOURCE_SUFFIXES)


def extract_verified_artifact(artifact: Path, plugin_id: str, version: str, destination: Path) -> None:
    """Extract regular members only after ZIP target/path safety validation."""

    if destination.exists() or destination.is_symlink():
        fail("artifact extraction destination must be a new regular directory")
    destination.mkdir(parents=True)
    try:
        destination_root = destination.resolve(strict=True)
        with zipfile.ZipFile(artifact) as archive:
            entries: dict[str, str] = {}
            for info in archive.infolist():
                validate_zip_member(info.filename, info, entries)
                member = PurePosixPath(info.filename)
                if source_member_is_forbidden(member):
                    fail("immutable artifact unexpectedly contains Marketplace metadata, signature or artifact content")
                if info.is_dir():
                    output = destination.joinpath(*member.parts)
                    output.mkdir(parents=True, exist_ok=True)
                    continue
                mode = info.external_attr >> 16
                if stat.S_IFMT(mode) not in {0, stat.S_IFREG}:
                    fail("immutable artifact contains a non-regular source member")
                output = destination.joinpath(*member.parts)
                try:
                    output.resolve(strict=False).relative_to(destination_root)
                except ValueError as error:
                    raise MaterializationError("immutable artifact extraction escaped its plugin directory") from error
                output.parent.mkdir(parents=True, exist_ok=True)
                if output.exists() or output.is_symlink():
                    fail("immutable artifact contains colliding source members")
                with archive.open(info, "r") as source, output.open("xb") as target:
                    shutil.copyfileobj(source, target)
                if mode & stat.S_IXUSR:
                    output.chmod(output.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except (OSError, RuntimeError, zipfile.BadZipFile) as error:
        raise MaterializationError(f"cannot safely extract immutable release artifact: {error}") from error
    manifest = destination / "plugin.json"
    codex_manifest = destination / ".codex-plugin" / "plugin.json"
    try:
        plugin_manifest = json.loads(manifest.read_text(encoding="utf-8"))
        codex = json.loads(codex_manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MaterializationError(f"immutable artifact has no valid dual plugin manifest: {error}") from error
    if plugin_manifest.get("name") != plugin_id or plugin_manifest.get("version") != version:
        fail("immutable artifact plugin manifest does not match its selected release")
    if codex.get("name") != plugin_id or codex.get("version") != version:
        fail("immutable artifact Codex manifest does not match its selected release")


def read_category(factory_root: Path, plugin_id: str) -> str:
    marketplace_path = factory_root / ".agents" / "plugins" / "marketplace.json"
    try:
        marketplace = json.loads(marketplace_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MaterializationError(f"cannot read retained Marketplace category: {error}") from error
    entries = marketplace.get("plugins") if isinstance(marketplace, dict) else None
    if not isinstance(entries, list):
        fail("retained Marketplace entries are invalid")
    entry = next((item for item in entries if isinstance(item, dict) and item.get("name") == plugin_id), None)
    category = entry.get("category") if isinstance(entry, dict) else None
    if not isinstance(category, str) or not category or category != category.strip() or len(category) > 80:
        fail("retained Marketplace category is unavailable for the first-party plugin")
    return category


def pending_registry_entry(factory_root: Path, plugin_id: str) -> dict[str, object]:
    return {
        "pluginId": plugin_id,
        "trustTier": "first-party",
        "source": {
            "repository": FIRST_PARTY_APPROVED_SOURCES[plugin_id],
            "path": f"plugins/{plugin_id}",
            "refs": {"beta": "refs/heads/beta", "stable": "refs/heads/main"},
        },
        "policy": {"installation": "INSTALLED_BY_DEFAULT", "authentication": "ON_INSTALL"},
        "category": read_category(factory_root, plugin_id),
        "status": "pending-adoption",
    }


def require_factory_history(factory_root: Path) -> Path:
    root = factory_root.resolve(strict=True)
    if not (root / ".git").exists():
        fail("Factory root must be a Git worktree so filtered plugin history can be retained")
    top_level = factory_git_stdout(root, ["rev-parse", "--show-toplevel"])
    try:
        resolved_top_level = Path(top_level).resolve(strict=True)
    except OSError as error:
        raise MaterializationError("cannot resolve Factory Git worktree") from error
    if resolved_top_level != root:
        fail("Factory root must be the Git worktree top level")
    origin = factory_git_stdout(root, ["config", "--get", "remote.origin.url"])
    if origin != TRUSTED_FACTORY_ORIGIN:
        fail("Factory origin must be the canonical trusted xsec-plugins GitHub HTTPS remote")
    if factory_git_stdout(root, ["rev-parse", "--is-shallow-repository"]) != "false":
        fail("materialization requires complete non-shallow Factory history")
    replacement_refs = factory_git_stdout(root, ["for-each-ref", "--format=%(refname)", "refs/replace/"])
    if replacement_refs:
        fail("materialization rejects Factory Git replacement refs")
    main = factory_git_stdout(root, ["rev-parse", "--verify", "main^{commit}"])
    if not GIT_SHA_PATTERN.fullmatch(main):
        fail("Factory protected main revision is unavailable")
    origin_main = factory_git_stdout(root, ["rev-parse", "--verify", "refs/remotes/origin/main^{commit}"])
    if not GIT_SHA_PATTERN.fullmatch(origin_main):
        fail("trusted Factory origin/main revision is unavailable")
    remote_main = trusted_factory_remote_main(root)
    head = factory_git_stdout(root, ["rev-parse", "--verify", "HEAD^{commit}"])
    if head != main or head != origin_main or head != remote_main:
        fail("materialization requires a checkout at the current trusted Factory remote main commit")
    if run_git(
        ["status", "--porcelain", "--untracked-files=all"],
        cwd=root,
        environment=trusted_history_environment(),
    ).stdout.strip():
        fail("materialization requires a clean trusted Factory main checkout")
    return root


def filter_index_paths(plugin_id: str) -> int:
    """Internal ``git filter-branch`` index filter; never emits source files."""

    prefix = PurePosixPath("plugins") / plugin_id
    output = run_git(["ls-files", "-z"], cwd=Path.cwd()).stdout
    for raw_path in output.split(b"\0"):
        if not raw_path:
            continue
        try:
            value = raw_path.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise MaterializationError("legacy plugin history contains a non-UTF-8 path") from error
        path = PurePosixPath(value)
        try:
            path.relative_to(prefix)
        except ValueError:
            # fast-export is already path-scoped. Refuse rather than carrying
            # an unrelated Factory file into a source repository.
            fail("legacy history filter retained a path outside the selected plugin")
        if source_member_is_forbidden(path):
            run_git(["update-index", "--force-remove", "--", value], cwd=Path.cwd())
    return 0


def filter_legacy_history(factory_root: Path, plugin_id: str, repository: Path) -> str:
    """Import main's path-limited history and remove Factory-only files in every commit."""

    # Never inherit ``init.templateDir``.  A caller-controlled template can
    # carry post-checkout hooks which would run while the candidate branch is
    # assembled.  The private empty directory is explicit even though the
    # candidate environment also suppresses global/system configuration.
    try:
        with tempfile.TemporaryDirectory(prefix=".xsec-empty-git-template-", dir=str(repository.parent)) as template:
            candidate_run_git(
                ["init", "--quiet", "--initial-branch=main", f"--template={template}", str(repository)],
                cwd=factory_root,
            )
    except OSError as error:
        raise MaterializationError("cannot create a controlled empty Git template directory") from error
    # Persist the disabled hook path for the filter subprocesses as well as
    # forcing it on each top-level Candidate Git command below.
    candidate_run_git(["config", "--local", "core.hooksPath", os.devnull], cwd=repository)
    export = subprocess.Popen(
        [
            "git",
            "-C",
            str(factory_root),
            "--no-replace-objects",
            "fast-export",
            "--show-original-ids",
            "main",
            "--",
            f"plugins/{plugin_id}",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=trusted_history_environment(),
    )
    assert export.stdout is not None
    imported = subprocess.run(
        ["git", *candidate_git_arguments(["-C", str(repository), "fast-import", "--quiet"])],
        stdin=export.stdout,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=candidate_environment(),
        check=False,
    )
    export.stdout.close()
    if export.stderr is not None:
        export_stderr = export.stderr.read()
        export.stderr.close()
    else:
        export_stderr = b""
    export_status = export.wait()
    if export_status or imported.returncode:
        detail = (export_stderr + imported.stderr).decode("utf-8", errors="replace").strip()
        fail(f"cannot import filtered legacy plugin history: {detail or 'unknown error'}")
    if not candidate_git_stdout(["rev-parse", "--verify", "refs/heads/main^{commit}"], cwd=repository):
        fail("Factory main has no retained history for the selected plugin")
    # fast-import populates refs and the index but does not necessarily create
    # a matching working tree. filter-branch refuses even an index-only delta,
    # so explicitly establish a clean checkout before its per-commit filter.
    candidate_run_git(["checkout", "--quiet", "--force", "main"], cwd=repository)
    candidate_run_git(["reset", "--hard", "--quiet", "refs/heads/main"], cwd=repository)

    script = Path(__file__).resolve().as_posix()
    python = Path(sys.executable).resolve().as_posix()
    index_filter = " ".join(
        shlex.quote(value)
        for value in (python, script, "--filter-index", "--plugin-id", plugin_id)
    )
    environment = candidate_environment()
    environment["FILTER_BRANCH_SQUELCH_WARNING"] = "1"
    candidate_run_git(
        ["filter-branch", "--force", "--prune-empty", "--index-filter", index_filter, "--", "refs/heads/main"],
        cwd=repository,
        environment=environment,
    )
    original_refs = candidate_git_stdout(["for-each-ref", "--format=%(refname)", "refs/original/"], cwd=repository)
    for reference in (line for line in original_refs.splitlines() if line):
        candidate_run_git(["update-ref", "-d", reference], cwd=repository)
    candidate_run_git(["reflog", "expire", "--expire=now", "--all"], cwd=repository)
    candidate_run_git(["gc", "--prune=now"], cwd=repository)
    history = candidate_git_stdout(["rev-parse", "--verify", "refs/heads/main^{commit}"], cwd=repository)
    assert_no_factory_content(repository, "refs/heads/main")
    return history


def assert_no_factory_content(repository: Path, reference: str) -> None:
    paths = candidate_git_stdout(["ls-tree", "-r", "--name-only", reference], cwd=repository).splitlines()
    for value in paths:
        path = PurePosixPath(value)
        if source_member_is_forbidden(path):
            fail("materialized source history still contains Marketplace metadata, signature or artifact content")


def replace_plugin_tree(repository: Path, plugin_id: str, artifact: Path, record: dict[str, object]) -> None:
    version = record.get("version")
    if not isinstance(version, str):
        fail("selected release version is invalid")
    destination = repository / "plugins" / plugin_id
    try:
        destination.resolve(strict=False).relative_to(repository.resolve(strict=True))
    except (OSError, ValueError) as error:
        raise MaterializationError("materialized plugin destination escaped source repository") from error
    if destination.exists() or destination.is_symlink():
        if destination.is_symlink() or not destination.is_dir():
            fail("legacy source plugin path is unsafe")
        shutil.rmtree(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    extract_verified_artifact(artifact, plugin_id, version, destination)


def write_standard_layout(repository: Path, plugin_id: str) -> None:
    source_repository = FIRST_PARTY_APPROVED_SOURCES[plugin_id]
    readme = f"""# {plugin_id}\n\nThis is the public source repository for `{plugin_id}`. It was materialized from\nthe immutable signed XSEC Marketplace release during the first-party source\nmigration. Develop on `beta`; merge reviewed, tested changes to `main` for the\nStable source line.\n\nMarketplace artifacts, release indexes, signatures, and Factory adoption proof\nremain in [tzf1003/xsec-plugins](https://github.com/tzf1003/xsec-plugins).\nThis source repository never stores Factory credentials or KMS material.\n\nSource repository: <https://github.com/{source_repository}>\n"""
    workflow = f"""name: Plugin source validation\n\non:\n  push:\n    branches: [main, beta]\n  pull_request:\n    branches: [main, beta]\n\npermissions:\n  contents: read\n\njobs:\n  manifest:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - name: Require the dual plugin manifests\n        run: |\n          test -f plugins/{plugin_id}/plugin.json\n          test -f plugins/{plugin_id}/.codex-plugin/plugin.json\n"""
    (repository / "README.md").write_text(readme, encoding="utf-8", newline="\n")
    ci = repository / ".github" / "workflows" / "ci.yml"
    ci.parent.mkdir(parents=True, exist_ok=True)
    ci.write_text(workflow, encoding="utf-8", newline="\n")


def regular_file_hashes(root: Path) -> dict[str, str]:
    """Return a canonical tree for locally generated regular source files."""

    result: dict[str, str] = {}
    try:
        resolved_root = root.resolve(strict=True)
        for path in root.rglob("*"):
            if path.is_symlink():
                fail("materialized source tree must not contain symbolic links")
            if path.is_dir():
                continue
            if not path.is_file():
                fail("materialized source tree must contain only regular files")
            relative = path.resolve(strict=True).relative_to(resolved_root).as_posix()
            result[relative] = sha256_file(path)
    except (OSError, ValueError) as error:
        raise MaterializationError("cannot read expected materialized source tree") from error
    return result


def expected_materialized_file_hashes(plugin_id: str, artifact: Path, record: dict[str, object]) -> dict[str, str]:
    version = record.get("version")
    if not isinstance(version, str):
        fail("selected release version is invalid")
    with tempfile.TemporaryDirectory(prefix="xsec-materialized-tree-") as directory:
        root = Path(directory)
        extract_verified_artifact(artifact, plugin_id, version, root / "plugins" / plugin_id)
        write_standard_layout(root, plugin_id)
        return regular_file_hashes(root)


def assert_materialized_branch_tree(
    repository: Path,
    branch: str,
    plugin_id: str,
    artifact: Path,
    record: dict[str, object],
) -> None:
    """Require the final commit to equal the signed artifact plus standard layout.

    Disabled hooks are the primary protection, while this exact-tree comparison
    is the final defence before a candidate can be pushed.  It catches an
    unexpected template file, hook side effect, or any other local mutation
    that made it into the branch even if Git still reports a clean worktree.
    """

    expected = expected_materialized_file_hashes(plugin_id, artifact, record)
    tree = candidate_run_git(["ls-tree", "-r", "-z", "--full-tree", branch], cwd=repository).stdout
    actual: dict[str, str] = {}
    for entry in (item for item in tree.split(b"\0") if item):
        try:
            header, raw_path = entry.split(b"\t", 1)
            mode, object_type, object_id = header.split(b" ")
            path = raw_path.decode("utf-8", errors="strict")
            object_name = object_id.decode("ascii", errors="strict")
        except (UnicodeDecodeError, ValueError) as error:
            raise MaterializationError("materialized source branch has an invalid tree entry") from error
        if mode not in {b"100644", b"100755"} or object_type != b"blob" or not GIT_SHA_PATTERN.fullmatch(object_name):
            fail("materialized source branch must contain only regular source files")
        if path in actual:
            fail("materialized source branch contains duplicate file paths")
        actual[path] = hashlib.sha256(
            candidate_run_git(["cat-file", "blob", object_name], cwd=repository).stdout
        ).hexdigest()
    if actual != expected:
        fail("final materialized source branch does not exactly match the signed artifact and standard layout")


def deterministic_commit_environment(repository: Path, parent: str, offset: int) -> dict[str, str]:
    raw_timestamp = candidate_git_stdout(["show", "-s", "--format=%ct", parent], cwd=repository)
    try:
        timestamp = int(raw_timestamp) + offset
    except ValueError as error:
        raise MaterializationError("legacy history has an invalid commit timestamp") from error
    value = f"{timestamp} +0000"
    environment = candidate_environment()
    environment.update(
        {
            "GIT_AUTHOR_NAME": MIGRATION_AUTHOR_NAME,
            "GIT_AUTHOR_EMAIL": MIGRATION_AUTHOR_EMAIL,
            "GIT_COMMITTER_NAME": MIGRATION_AUTHOR_NAME,
            "GIT_COMMITTER_EMAIL": MIGRATION_AUTHOR_EMAIL,
            "GIT_AUTHOR_DATE": value,
            "GIT_COMMITTER_DATE": value,
        }
    )
    return environment


def commit_materialized_branch(
    repository: Path,
    branch: str,
    parent: str,
    plugin_id: str,
    channel: str,
    artifact: Path,
    record: dict[str, object],
    timestamp_offset: int,
) -> str:
    candidate_run_git(["checkout", "--quiet", "--force", "-B", branch, parent], cwd=repository)
    replace_plugin_tree(repository, plugin_id, artifact, record)
    write_standard_layout(repository, plugin_id)
    candidate_run_git(["add", "--all"], cwd=repository)
    version = record.get("version")
    release_id = record.get("releaseId")
    if not isinstance(version, str) or not isinstance(release_id, str):
        fail("selected immutable release identity is invalid")
    candidate_run_git(
        ["-c", "commit.gpgSign=false", "commit", "--no-verify", "--quiet", "-m", f"chore: materialize {channel} source {version} ({release_id})"],
        cwd=repository,
        environment=deterministic_commit_environment(repository, parent, timestamp_offset),
    )
    commit = candidate_git_stdout(["rev-parse", "HEAD"], cwd=repository)
    if not GIT_SHA_PATTERN.fullmatch(commit):
        fail("materialized source commit is invalid")
    assert_no_factory_content(repository, branch)
    assert_materialized_branch_tree(repository, branch, plugin_id, artifact, record)
    return commit


def materialize_repository(factory_root: Path, plugin_id: str, repository: Path) -> dict[str, object]:
    """Create a local candidate repository; callers decide whether to push it."""

    plugin_id = safe_plugin_id(plugin_id)
    factory_root = require_factory_history(factory_root)
    if repository.exists():
        fail("materialization repository path must not already exist")
    verify_retained_release_signature(factory_root, plugin_id)
    beta_record, beta_artifact = selected_release_artifact(factory_root, plugin_id, "beta")
    stable_record, stable_artifact = selected_release_artifact(factory_root, plugin_id, "stable")
    history = filter_legacy_history(factory_root, plugin_id, repository)
    stable_commit = commit_materialized_branch(
        repository,
        "main",
        history,
        plugin_id,
        "stable",
        stable_artifact,
        stable_record,
        1,
    )
    beta_commit = commit_materialized_branch(
        repository,
        "beta",
        history,
        plugin_id,
        "beta",
        beta_artifact,
        beta_record,
        2,
    )
    assert_no_factory_content(repository, "main")
    assert_no_factory_content(repository, "beta")
    return {
        "sourceCommits": {"beta": beta_commit, "stable": stable_commit},
        "pendingAdoptionRegistry": pending_registry_entry(factory_root, plugin_id),
    }


def push_candidate(repository: Path, plugin_id: str, target: str) -> None:
    canonical_target = require_exact_target(plugin_id, target)
    protocols = ("https",) if canonical_target.startswith("https://") else ("ssh",)
    environment = sealed_transport_environment(protocols=protocols)
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    environment.pop("GIT_REPLACE_REF_BASE", None)
    assert_no_local_url_rewrites(repository)
    try:
        hook_path = git_stdout(
            ["config", "--local", "--get", "core.hooksPath"],
            cwd=repository,
            environment=candidate_environment(),
        )
    except MaterializationError:
        hook_path = None
    if hook_path != os.devnull:
        fail("materialization candidate must retain its disabled local Git hook path before push")
    if candidate_git_stdout(["status", "--porcelain", "--untracked-files=all"], cwd=repository):
        fail("materialization candidate must be clean before its one-time push")
    assert_no_factory_content(repository, "refs/heads/main")
    assert_no_factory_content(repository, "refs/heads/beta")
    # Preflight away from the candidate repository so neither a local URL
    # alias nor a parent worktree config can reinterpret the approved literal.
    with tempfile.TemporaryDirectory(prefix="xsec-source-target-check-") as directory:
        transport_root = Path(directory)
        heads = run_git(
            [
                *sealed_transport_arguments(protocols=protocols),
                "ls-remote",
                "--heads",
                canonical_target,
                "refs/heads/main",
                "refs/heads/beta",
            ],
            cwd=transport_root,
            environment=sealed_transport_environment(
                protocols=protocols,
                repository_discovery_ceiling=transport_root,
            ),
        ).stdout
    if heads.strip():
        fail("target already has main or beta; materialization refuses to overwrite or force-push")
    run_git(
        [
            "-c",
            f"core.hooksPath={os.devnull}",
            *sealed_transport_arguments(protocols=protocols),
            "push",
            "--atomic",
            "--porcelain",
            "--no-verify",
            canonical_target,
            "refs/heads/main:refs/heads/main",
            "refs/heads/beta:refs/heads/beta",
        ],
        cwd=repository,
        environment=environment,
    )


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT, help="xsec-plugins Factory worktree root")
    parser.add_argument("--plugin-id", required=True, help="one of the eleven approved first-party plugin IDs")
    parser.add_argument("--target", help="exact approved GitHub source repository URL; required with --push")
    parser.add_argument("--push", action="store_true", help="push new main/beta branches after an exact-target preflight")
    parser.add_argument("--filter-index", action="store_true", help=argparse.SUPPRESS)
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    try:
        plugin_id = safe_plugin_id(args.plugin_id)
        if args.filter_index:
            return filter_index_paths(plugin_id)
        if args.push and args.target is None:
            fail("--push requires --target with the exact approved public GitHub repository URL")
        if args.target is not None:
            require_exact_target(plugin_id, args.target)
        with tempfile.TemporaryDirectory(prefix=f"xsec-first-party-source-{plugin_id}-") as directory:
            result = materialize_repository(args.root, plugin_id, Path(directory) / "repository")
            if args.push:
                assert args.target is not None
                push_candidate(Path(directory) / "repository", plugin_id, args.target)
        # Keep stdout machine-readable and deliberately narrow: callers can
        # submit only this pending Registry row to the protected Factory PR.
        sys.stdout.write(json.dumps(result, separators=(",", ":"), sort_keys=True) + "\n")
        return 0
    except MaterializationError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
