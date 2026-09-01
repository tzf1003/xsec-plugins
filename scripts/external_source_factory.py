#!/usr/bin/env python3
"""Bridge approved external plugin repositories into the official KMS market.

This script is deliberately used only by the protected ``publish.yml``
workflow.  It never obtains GitHub credentials, runs source build scripts, or
signs anything.  The workflow supplies an exact, already-checked-out commit;
this bridge snapshots that package below ``.xsec-factory/snapshots/<id>/`` so the existing
official builder, KMS publisher, release index, and Desktop marketplace reader
keep one compatible on-disk contract.

The snapshot is a published source/cache record, not the external repository's
development authority.  Its provenance is kept separately in
``.xsec-factory/official-publications/<id>.json``.
"""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tempfile

from build_market import (
    MARKETPLACE_RELATIVE_PATH,
    RELEASE_ID_PATTERN,
    ROOT,
    SNAPSHOT_ROOT_RELATIVE_PATH,
    WINDOWS_RESERVED_DEVICE_NAMES,
    is_link,
    iter_plugin_files,
    load_release_document,
    release_id,
    require_release_engines,
    sha256,
    stable_json,
    write_zip,
)
from kms_marketplace_publisher import (
    MarketplaceDocument,
    MarketplaceKmsPublisherError,
    OFFICIAL_ADOPTION_PROOFS_RELATIVE_PATH,
    OFFICIAL_PUBLICATION_PROOFS_RELATIVE_PATH,
    OFFICIAL_STATUS_PROOFS_RELATIVE_PATH,
    official_adoption_provenance_document,
    official_publication_provenance_document,
    sidecar_path_for,
    verify_historical_sidecar_signature,
)


REGISTRY_RELATIVE_PATH = Path(".xsec-factory") / "official-registry.json"
PUBLICATIONS_RELATIVE_PATH = Path(".xsec-factory") / "official-publications"
PUBLICATION_PROOFS_RELATIVE_PATH = OFFICIAL_PUBLICATION_PROOFS_RELATIVE_PATH
ADOPTIONS_RELATIVE_PATH = Path(".xsec-factory") / "official-adoptions"
ADOPTION_PROOFS_RELATIVE_PATH = OFFICIAL_ADOPTION_PROOFS_RELATIVE_PATH
STATUSES_RELATIVE_PATH = Path(".xsec-factory") / "official-status"
STATUS_PROOFS_RELATIVE_PATH = OFFICIAL_STATUS_PROOFS_RELATIVE_PATH
GIT_SHA_PATTERN = re.compile(r"^[a-f0-9]{40}$")
# Keep this in lockstep with Desktop's package/catalog validator: ASCII
# lowercase/digits, 64 bytes at most, no terminal separator or repeated
# dot/hyphen separator. Factory metadata must never publish an ID Desktop will
# later reject.
PLUGIN_ID_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?$")
REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,38}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$")
SEMVER_NUMERIC_IDENTIFIER = r"(?:0|[1-9][0-9]*)"
SEMVER_PRERELEASE_IDENTIFIER = r"(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
SEMVER_BUILD_IDENTIFIER = r"[0-9A-Za-z-]+"
SEMVER_PATTERN = re.compile(
    rf"^{SEMVER_NUMERIC_IDENTIFIER}\.{SEMVER_NUMERIC_IDENTIFIER}\.{SEMVER_NUMERIC_IDENTIFIER}"
    rf"(?:-{SEMVER_PRERELEASE_IDENTIFIER}(?:\.{SEMVER_PRERELEASE_IDENTIFIER})*)?"
    rf"(?:\+{SEMVER_BUILD_IDENTIFIER}(?:\.{SEMVER_BUILD_IDENTIFIER})*)?$"
)
SNAPSHOT_EXCLUDED_NAMES = frozenset({".git", ".xsec-market", "__pycache__", "node_modules"})
# These values mirror the Desktop host's compiled ownership boundary. A
# package imported from an approved external repository is still optional
# Factory content, even though it is delivered by the official marketplace;
# it must never be able to impersonate a built-in package or claim the host's
# reserved workspace/MCP contribution routes.
RESERVED_DESKTOP_PLUGIN_IDS = frozenset(
    {
        "com.xsec.workspace.approvals",
        "com.xsec.attack-path",
        "com.xsec.asset-discovery",
        "com.xsec.workspace.browser",
        "com.xsec.workspace.conversation-tree",
        "com.xsec.workspace.files",
        "com.xsec.workspace.project-outcomes",
        "com.xsec.project-workspace",
        "com.xsec.workspace.sub-agent",
        "com.xsec.system-terminal",
        "com.xsec.workspace.traffic",
        "com.xsec.desktop.shell-compat",
        "com.xsec.desktop.legacy-main-pages",
        "com.xsec.desktop.legacy-settings-pages",
    }
)
RESERVED_OFFICIAL_WORKSPACE_CONTRIBUTIONS = frozenset(
    {
        "approvals",
        "attack-path",
        "browser",
        "conversation-tree",
        "evidence-detail",
        "files",
        "finding-detail",
        "project-outcomes",
        "report-detail",
        "request-detail",
        "sub-agent",
        "subagent-detail",
        "system-terminal",
        "task-detail",
        "traffic",
        "traffic-replay",
    }
)
# External Factory packages inherit the official marketplace delivery trust but
# are not Desktop-owned code. Keep them out of *all* identifiers that the
# Desktop shell has already bound to built-in navigation, routes, pages or
# settings surfaces. This is intentionally a static mirror of the current
# Desktop-owned manifests plus its legacy shell contributions, rather than a
# set derived from the checked-out `plugins/` tree: an unreviewed registry or
# source change must not be able to shrink the ownership boundary first.
RESERVED_DESKTOP_ROUTE_AND_PAGE_SURFACES = frozenset(
    {
        # Current official plugin route/navigation/settings identities.
        "asset-discovery",
        "project.overview",
        "project.files",
        "project.assets",
        "project.batch",
        "project.passive-findings",
        "project.findings",
        "project.reports",
        "project-workspace",
        "project-overview",
        "project-files",
        "overview",
        "assets",
        "files",
        "batch",
        "runs",
        "passive-findings",
        "findings",
        "reports",
        "project/:projectId/overview",
        "project/:projectId/files",
        "project/:projectId/assets",
        "project/:projectId/batch",
        "project/:projectId/passive-findings",
        "project/:projectId/findings",
        "project/:projectId/reports",
        # Desktop's legacy main-page routes.
        "main.overview",
        "main.quick-start",
        "main.task-center",
        "main.projects",
        "main.plugins",
        "quick-start",
        "new-session",
        "task-center",
        "projects",
        "plugins",
        # Desktop's legacy and current built-in settings pages.
        "account",
        "cloud",
        "execution-history",
        "approval-history",
        "token-usage",
        "archived-sessions",
        "appearance",
        "settings-system",
        "settings-proxy",
        "settings-verification",
        "settings-prompts",
        "product-issues",
    }
)
RESERVED_DESKTOP_SURFACES = (
    RESERVED_OFFICIAL_WORKSPACE_CONTRIBUTIONS | RESERVED_DESKTOP_ROUTE_AND_PAGE_SURFACES
)
RESERVED_OFFICIAL_AGENT_TOOLS = frozenset(
    {
        "plugin.attack-path.tree_list",
        "plugin.attack-path.tree_node_create",
        "xsec_shared_finding_add",
        "xsec_shared_findings_list",
        "xsec_subagent_cancel",
        "xsec_subagent_complete",
        "xsec_subagent_dispatch",
        "xsec_subagent_heartbeat",
        "xsec_subagent_register_session",
        "xsec_subagent_status",
        "xsec_tree_list",
        "xsec_tree_node_create",
        "xsec_tree_node_get",
        "xsec_tree_node_update",
    }
)
RESERVED_HOST_CORE_AGENT_TOOLS = frozenset(
    {
        "xsec_task_profile",
        "xsec_workspace_reveal",
        "xsec_assignment_get",
        "xsec_browser_session_create",
        "xsec_browser_session_get",
        "xsec_browser_navigate",
        "xsec_browser_snapshot",
        "xsec_browser_screenshot",
        "xsec_browser_click",
        "xsec_browser_type",
        "xsec_browser_select",
        "xsec_browser_wait",
        "xsec_browser_session_close",
        "xsec_passive_findings_list",
        "xsec_passive_finding_get",
        "xsec_finding_upsert",
        "xsec_asset_import",
        "xsec_collection_finalize",
        "xsec_evidence_upload_begin",
        "xsec_evidence_upload_complete",
        "xsec_report_submit",
        "xsec_verification_profile",
        "xsec_email_messages_list",
        "xsec_sms_messages_list",
        "xsec_verification_code_wait",
        "xsec_cli_search",
        "xsec_cli_status",
        "xsec_cli_ensure",
        "xsec_cli_install_job",
        "xsec_cli_install_cancel",
        "xsec_project_outcomes_list",
        "xsec_project_outcomes_get",
        "xsec_page_group_create",
        "xsec_page_group_use",
    }
)
# OfficialMarketplace packages receive their declared capabilities without the
# confirmation path used for a normal third-party package. External Factory
# source approval is therefore intentionally *not* an automatic privilege
# escalation path. The small set below is enough for a browser-sandboxed,
# optional workspace integration; a capability outside it needs an explicit
# Desktop trust-model/API change rather than only a registry/source edit.
EXTERNAL_FACTORY_ALLOWED_CAPABILITIES = frozenset(
    {
        "workspace.project.read",
        "workspace.session.read",
        "workspace.tool.open",
        "pluginData.read",
        "pluginData.write",
        "network.request",
        "notifications.show",
        "secrets.own.read",
        "secrets.own.write",
        "agent.tools.register",
    }
)

# The only source identities allowed to retain the Desktop's built-in
# namespace and automatic-install capability after the split.  This is a
# static compiler-like allowlist: registry metadata cannot create a new
# privileged package simply by declaring ``trustTier: first-party``.
FIRST_PARTY_APPROVED_SOURCES = {
    "com.xsec.asset-discovery": "tzf1003/xsec-plugin-asset-discovery",
    "com.xsec.attack-path": "tzf1003/xsec-plugin-attack-path",
    "com.xsec.project-workspace": "tzf1003/xsec-plugin-project-workspace",
    "com.xsec.system-terminal": "tzf1003/xsec-plugin-system-terminal",
    "com.xsec.workspace.approvals": "tzf1003/xsec-plugin-approvals",
    "com.xsec.workspace.browser": "tzf1003/xsec-plugin-browser",
    "com.xsec.workspace.conversation-tree": "tzf1003/xsec-plugin-conversation-tree",
    "com.xsec.workspace.files": "tzf1003/xsec-plugin-files",
    "com.xsec.workspace.project-outcomes": "tzf1003/xsec-plugin-project-outcomes",
    "com.xsec.workspace.sub-agent": "tzf1003/xsec-plugin-sub-agent",
    "com.xsec.workspace.traffic": "tzf1003/xsec-plugin-traffic",
}
TRUST_TIERS = frozenset({"external", "first-party"})
PUBLICATION_STATES = frozenset(
    {"waiting_for_beta", "building_beta", "waiting_for_smoke", "promoting_stable", "published", "failed"}
)


class ExternalSourceFactoryError(ValueError):
    """The approved-source bridge must stop before marketplace signing."""


def fail(message: str) -> None:
    raise ExternalSourceFactoryError(message)


def require_write_path_below(root: Path, path: Path, label: str) -> None:
    """Keep generated metadata below the Factory root without link traversal."""

    if is_link(root) or not root.is_dir():
        fail(f"{label} root must be a regular directory")
    try:
        relative = path.relative_to(root)
        root_resolved = root.resolve(strict=True)
        path.resolve(strict=False).relative_to(root_resolved)
    except (OSError, ValueError) as error:
        raise ExternalSourceFactoryError(f"{label} must remain below the Factory root") from error
    current = root
    for part in relative.parts:
        current = current / part
        if is_link(current):
            fail(f"refusing to write {label} through symbolic link: {current}")


def stable_write(root: Path, path: Path, value: object, label: str) -> None:
    """Atomically replace generated metadata without following links."""

    require_write_path_below(root, path, label)
    path.parent.mkdir(parents=True, exist_ok=True)
    # A path component can only be replaced by a concurrent writer after the
    # first check. Re-check after mkdir before opening the temporary file.
    require_write_path_below(root, path, label)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(stable_json(value))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def require_object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    return value


def require_exact_keys(value: dict[str, object], keys: set[str], label: str) -> None:
    if set(value) != keys:
        fail(f"{label} has an unsupported schema")


def read_json(path: Path, label: str) -> dict[str, object]:
    if is_link(path):
        fail(f"{label} must not be a symbolic link")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{label} is not valid UTF-8 JSON: {error}")
    return require_object(value, label)


def require_text(value: object, label: str, *, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > maximum or "\x00" in value:
        fail(f"{label} must be a non-empty bounded string")
    return value


def safe_plugin_id(value: object, label: str = "plugin ID") -> str:
    if (
        not isinstance(value, str)
        or not PLUGIN_ID_PATTERN.fullmatch(value)
        or ".." in value
        or "--" in value
    ):
        fail(f"{label} must be a safe plugin identifier")
    # Publication evidence is persisted as `<plugin-id>.json`; reject the
    # Windows device aliases that would make that file ambiguous or
    # uncreatable on a supported Factory host.
    if value.split(".", 1)[0].casefold() in WINDOWS_RESERVED_DEVICE_NAMES:
        fail(f"{label} must not be a Windows reserved device name")
    return value


def safe_external_plugin_id(value: object, label: str = "plugin ID") -> str:
    identifier = safe_plugin_id(value, label)
    # Desktop developer mode treats this whole namespace as built-in/internal
    # development content. An external registry entry here would either be
    # hidden from the developer workflow or accidentally inherit an internal
    # trust boundary, so reserve the namespace rather than only today's list
    # of built-in IDs.
    if identifier == "com.xsec" or identifier.startswith("com.xsec."):
        fail(f"{label} is reserved for the Desktop namespace")
    if identifier in RESERVED_DESKTOP_PLUGIN_IDS:
        fail(f"{label} is reserved for a Desktop-owned package")
    return identifier


def safe_repository(value: object, label: str = "source.repository") -> str:
    if not isinstance(value, str) or not REPOSITORY_PATTERN.fullmatch(value):
        fail(f"{label} must be an owner/repository GitHub slug")
    owner, repository = value.split("/", 1)
    if (
        any(part.startswith(".") or part.endswith(".") or ".." in part for part in (owner, repository))
        or repository.casefold().endswith(".git")
    ):
        fail(f"{label} must be an owner/repository GitHub slug")
    return value


def safe_sha(value: object, label: str = "source SHA") -> str:
    if not isinstance(value, str) or not GIT_SHA_PATTERN.fullmatch(value):
        fail(f"{label} must be a lowercase 40-character Git commit SHA")
    return value


def safe_source_path(value: object, label: str = "source.path") -> PurePosixPath:
    if not isinstance(value, str) or not value or value != value.strip() or "\\" in value:
        fail(f"{label} must be a non-empty forward-slash checkout-relative path")
    if value == ".":
        return PurePosixPath(".")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} or ":" in part for part in path.parts):
        fail(f"{label} must remain below the checked-out repository")
    return path


def require_below(root: Path, candidate: Path, label: str, *, directory: bool = False) -> Path:
    if is_link(root):
        fail(f"{label} root must not be a symbolic link")
    try:
        root_resolved = root.resolve(strict=True)
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root_resolved)
    except (OSError, ValueError) as error:
        raise ExternalSourceFactoryError(f"{label} must remain below its root") from error
    if is_link(candidate):
        fail(f"{label} must not be a symbolic link")
    if directory:
        if not resolved.is_dir():
            fail(f"{label} must be a directory")
    elif not resolved.is_file():
        fail(f"{label} must be a regular file")
    return resolved


def resolve_source_directory(source_root: Path, source_path: PurePosixPath, label: str) -> Path:
    if is_link(source_root):
        fail(f"{label} checkout must not be a symbolic link")
    current = source_root
    if source_path != PurePosixPath("."):
        for part in source_path.parts:
            current = current / part
            if is_link(current):
                fail(f"{label} must not traverse symbolic links")
    return require_below(source_root, current, label, directory=True)


def require_link_free_tree(root: Path, label: str, *, excluded_names: frozenset[str] = frozenset()) -> None:
    """Reject links in a tree without traversing content the package excludes."""

    if is_link(root):
        fail(f"{label} must not be a symbolic link")
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        retained_directories: list[str] = []
        for name in directories:
            path = current_path / name
            if name in excluded_names:
                continue
            if is_link(path):
                fail(f"{label} must not contain symbolic links: {path.relative_to(root).as_posix()}")
            retained_directories.append(name)
        directories[:] = retained_directories
        for name in files:
            if name in excluded_names:
                continue
            path = current_path / name
            if is_link(path):
                fail(f"{label} must not contain symbolic links: {path.relative_to(root).as_posix()}")


@dataclass(frozen=True)
class Registration:
    plugin_id: str
    trust_tier: str
    repository: str
    source_path: PurePosixPath
    beta_ref: str
    stable_ref: str
    installation: str
    authentication: str
    category: str
    status: str

    def ref_for(self, channel: str) -> str:
        if channel == "beta":
            return self.beta_ref
        if channel == "stable":
            return self.stable_ref
        fail("publication channel must be beta or stable")


def parse_registration(value: object, index: int) -> Registration:
    label = f"official Factory registry plugin at index {index}"
    entry = require_object(value, label)
    require_exact_keys(entry, {"pluginId", "trustTier", "source", "policy", "category", "status"}, label)
    trust_tier = entry.get("trustTier")
    if trust_tier not in TRUST_TIERS:
        fail(f"{label}.trustTier must be external or first-party")
    raw_plugin_id = entry.get("pluginId")
    if trust_tier == "external":
        plugin_id = safe_external_plugin_id(raw_plugin_id, f"{label}.pluginId")
    else:
        plugin_id = safe_plugin_id(raw_plugin_id, f"{label}.pluginId")
        if plugin_id not in FIRST_PARTY_APPROVED_SOURCES:
            fail(f"{label}.pluginId is not an approved first-party plugin")
    source = require_object(entry.get("source"), f"{label}.source")
    require_exact_keys(source, {"repository", "path", "refs"}, f"{label}.source")
    repository = safe_repository(source.get("repository"), f"{label}.source.repository")
    source_path = safe_source_path(source.get("path"), f"{label}.source.path")
    refs = require_object(source.get("refs"), f"{label}.source.refs")
    require_exact_keys(refs, {"beta", "stable"}, f"{label}.source.refs")
    if refs.get("beta") != "refs/heads/beta" or refs.get("stable") != "refs/heads/main":
        fail(f"{label}.source.refs must map beta to refs/heads/beta and stable to refs/heads/main")
    policy = require_object(entry.get("policy"), f"{label}.policy")
    require_exact_keys(policy, {"installation", "authentication"}, f"{label}.policy")
    if trust_tier == "external":
        # The installed-by-default official set is compiled into Desktop. An
        # external registry edit must never silently extend that set.
        if policy.get("installation") != "AVAILABLE":
            fail(f"{label}.policy.installation must be AVAILABLE")
    else:
        expected_repository = FIRST_PARTY_APPROVED_SOURCES[plugin_id]
        if repository != expected_repository:
            fail(f"{label}.source.repository does not match the approved first-party source")
        if source_path != PurePosixPath("plugins") / plugin_id:
            fail(f"{label}.source.path must be plugins/{plugin_id} for a first-party plugin")
        if policy.get("installation") != "INSTALLED_BY_DEFAULT":
            fail(f"{label}.policy.installation must be INSTALLED_BY_DEFAULT")
    if policy.get("authentication") != "ON_INSTALL":
        fail(f"{label}.policy.authentication must be ON_INSTALL")
    category = require_text(entry.get("category"), f"{label}.category", maximum=80)
    status = entry.get("status")
    allowed_statuses = {"active", "disabled"}
    if trust_tier == "first-party":
        # A protected migration first registers a retained built-in snapshot
        # as pending, then the production adoption workflow creates and signs
        # its proof in the same generated activation PR.  External packages
        # never get this transitional trust state.
        allowed_statuses.add("pending-adoption")
    if status not in allowed_statuses:
        fail(f"{label}.status is invalid for its trust tier")
    return Registration(
        plugin_id=plugin_id,
        trust_tier=str(trust_tier),
        repository=repository,
        source_path=source_path,
        beta_ref="refs/heads/beta",
        stable_ref="refs/heads/main",
        installation=str(policy["installation"]),
        authentication=str(policy["authentication"]),
        category=category,
        status=status,
    )


def load_registry(root: Path, *, allow_legacy_v1: bool = False) -> tuple[Registration, ...]:
    """Load current Registry v2, optionally reading a trusted v1 baseline.

    The protected source gate compares a proposed v2 migration with the
    previous protected commit.  That parent legitimately has Registry v1,
    whose rows are exactly the old restrictive external shape.  Current
    Factory input must still be v2; this narrow compatibility path exists
    only for a separately materialized trusted baseline.
    """

    path = root / REGISTRY_RELATIVE_PATH
    if is_link(path.parent):
        fail("official external registry directory must not be a symbolic link")
    document = read_json(path, "official Factory registry")
    require_exact_keys(document, {"schemaVersion", "plugins"}, "official Factory registry")
    schema_version = document.get("schemaVersion")
    if schema_version not in {1, 2}:
        fail("official Factory registry schemaVersion must be 2")
    if schema_version == 1 and not allow_legacy_v1:
        fail("official Factory registry schemaVersion must be 2")
    raw_plugins = document.get("plugins")
    if not isinstance(raw_plugins, list):
        fail("official Factory registry plugins must be a list")
    if schema_version == 1:
        def legacy_entry(value: object, index: int) -> Registration:
            legacy_label = f"trusted Factory baseline Registry v1 plugin at index {index}"
            entry = require_object(value, legacy_label)
            require_exact_keys(entry, {"pluginId", "source", "policy", "category", "status"}, legacy_label)
            v2_entry = dict(entry)
            v2_entry["trustTier"] = "external"
            return parse_registration(v2_entry, index)

        registrations = tuple(legacy_entry(item, index) for index, item in enumerate(raw_plugins))
    else:
        registrations = tuple(parse_registration(item, index) for index, item in enumerate(raw_plugins))
    identifiers = [item.plugin_id for item in registrations]
    if len(identifiers) != len(set(identifiers)):
        fail("official Factory registry contains duplicate plugin IDs")
    return registrations


def registration_for(root: Path, plugin_id: str, *, active: bool = True) -> Registration:
    identifier = safe_plugin_id(plugin_id)
    for registration in load_registry(root):
        if registration.plugin_id == identifier:
            if active and registration.status != "active":
                if registration.status == "disabled":
                    fail(f"official external plugin {identifier} is disabled")
                fail(f"official Factory plugin {identifier} is not active")
            return registration
    fail(f"official external plugin {identifier} is not registered")


def reject_legacy_stable_promotion(root: Path, plugin_id: str) -> dict[str, str]:
    """Keep the legacy Stable workflow from bypassing external main proof."""

    identifier = safe_plugin_id(plugin_id)
    if any(registration.plugin_id == identifier for registration in load_registry(root)):
        fail(
            f"registered external plugin {identifier} must use publish.yml with "
            "channel=stable, source_sha and release_id"
        )
    return {"plugin_id": identifier, "legacy_stable_allowed": "true"}


def prepare(root: Path, plugin_id: str, channel: str, source_sha: str) -> dict[str, str]:
    registration = registration_for(root, plugin_id)
    sha = safe_sha(source_sha)
    owner, repository = registration.repository.split("/", 1)
    return {
        "plugin_id": registration.plugin_id,
        "trust_tier": registration.trust_tier,
        "source_sha": sha,
        "source_repository": registration.repository,
        "source_owner": owner,
        "source_repo": repository,
        "source_path": registration.source_path.as_posix(),
        "source_ref": registration.ref_for(channel),
        # Always emit the registered protected main ref from the allowlisted
        # Registry v2 row.  The beta publisher uses it only as a read-only
        # reproducibility gate; callers never choose a comparison branch.
        "stable_ref": registration.stable_ref,
    }


def snapshot_directory(root: Path, plugin_id: str) -> Path:
    plugin_id = safe_plugin_id(plugin_id)
    destination = root / SNAPSHOT_ROOT_RELATIVE_PATH / plugin_id
    try:
        destination.resolve(strict=False).relative_to((root / SNAPSHOT_ROOT_RELATIVE_PATH).resolve(strict=False))
    except ValueError as error:
        raise ExternalSourceFactoryError("plugin snapshot path escaped .xsec-factory/snapshots/") from error
    return destination


def release_path(root: Path, plugin_id: str) -> Path:
    return snapshot_directory(root, plugin_id) / ".xsec-market" / "releases.json"


def publication_path(root: Path, plugin_id: str) -> Path:
    return root / PUBLICATIONS_RELATIVE_PATH / f"{safe_plugin_id(plugin_id)}.json"


def adoption_path(root: Path, plugin_id: str) -> Path:
    return root / ADOPTIONS_RELATIVE_PATH / f"{safe_plugin_id(plugin_id)}.json"


def status_path(root: Path, plugin_id: str) -> Path:
    return root / ".xsec-factory" / "official-status" / f"{safe_plugin_id(plugin_id)}.json"


def optional_sha(value: object, label: str) -> str | None:
    if value is None:
        return None
    return safe_sha(value, label)


def release_pointer(value: object, label: str) -> str | None:
    if value is None:
        return None
    pointer = require_object(value, label)
    require_exact_keys(pointer, {"releaseId"}, label)
    identifier = pointer.get("releaseId")
    if not isinstance(identifier, str) or not RELEASE_ID_PATTERN.fullmatch(identifier):
        fail(f"{label}.releaseId must be canonical")
    return identifier


def safe_delivery_key(value: object, label: str = "delivery key") -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,159}", value):
        fail(f"{label} must be a bounded delivery identifier")
    return value


def prepare_reconcile_source(
    root: Path,
    *,
    delivery_key: str,
    plugin_id: str,
    source_repository: str,
    source_ref: str,
    source_sha: str,
) -> dict[str, str]:
    """Validate Cloud's source-event payload before any source-network access.

    The workflow still resolves the branch head itself after acquiring its
    publication slot.  This parser only accepts a fully-bound allowlist
    request, so untrusted delivery fields never decide a repository, ref or
    Factory publication mode.
    """

    registration = registration_for(root, plugin_id)
    if source_repository != registration.repository:
        fail("reconcile source repository does not match the official registry")
    ref = require_text(source_ref, "reconcile source ref", maximum=128)
    channel = "beta" if ref == registration.beta_ref else "stable" if ref == registration.stable_ref else None
    if channel is None:
        fail("reconcile source ref does not match a registered beta or stable branch")
    return {
        "delivery_key": safe_delivery_key(delivery_key),
        "plugin_id": registration.plugin_id,
        "trust_tier": registration.trust_tier,
        "source_repository": registration.repository,
        "source_ref": ref,
        "source_sha": safe_sha(source_sha, "reconcile source SHA"),
        "beta_ref": registration.beta_ref,
        "stable_ref": registration.stable_ref,
        "channel": channel,
    }


def prepare_adoption(root: Path, plugin_id: str, beta_sha: str, stable_sha: str) -> dict[str, str]:
    """Resolve a pending first-party migration without accepting caller metadata."""

    registration = registration_for(root, plugin_id, active=False)
    if registration.trust_tier != "first-party" or registration.status != "pending-adoption":
        fail("only a pending first-party registration can be adopted")
    owner, repository = registration.repository.split("/", 1)
    return {
        "plugin_id": registration.plugin_id,
        "source_repository": registration.repository,
        "source_owner": owner,
        "source_repo": repository,
        "beta_ref": registration.beta_ref,
        "stable_ref": registration.stable_ref,
        "beta_sha": safe_sha(beta_sha, "first-party adoption beta SHA"),
        "stable_sha": safe_sha(stable_sha, "first-party adoption stable SHA"),
    }


def prepare_reconcile_smoke(
    *,
    delivery_key: str,
    marketplace_revision: str,
    channel: str,
    smoke_workflow_run_id: str,
    smoke_workflow_run_attempt: str,
) -> dict[str, str]:
    """Validate the narrow Desktop callback shape before stable reconciliation."""

    if channel not in {"beta", "stable"}:
        fail("reconcile smoke channel must be beta or stable")
    run_id = require_text(smoke_workflow_run_id, "reconcile smoke workflow run ID", maximum=32)
    attempt = require_text(smoke_workflow_run_attempt, "reconcile smoke workflow run attempt", maximum=16)
    if not run_id.isdecimal() or not attempt.isdecimal() or int(run_id) <= 0 or int(attempt) <= 0:
        fail("reconcile smoke workflow run identity is invalid")
    return {
        "delivery_key": safe_delivery_key(delivery_key),
        "marketplace_revision": safe_sha(marketplace_revision, "reconcile smoke marketplace revision"),
        "channel": channel,
        "smoke_workflow_run_id": run_id,
        "smoke_workflow_run_attempt": attempt,
    }


def reserved_external_agent_tool(name: str) -> bool:
    """Return whether Desktop reserves an MCP name for XSEC host ownership."""

    return (
        name in RESERVED_OFFICIAL_AGENT_TOOLS
        or name in RESERVED_HOST_CORE_AGENT_TOOLS
        or name.startswith("xsec_")
        or name.startswith("browser_")
    )


def reserved_external_desktop_surface(name: str) -> bool:
    """Return whether an ID/path claims a Desktop-owned UI surface.

    Route paths may be written with a leading/trailing slash while Desktop's
    built-in contributions omit it. Treat that spelling as the same surface;
    other contribution identifiers remain exact, stable Desktop identities.
    """

    return name in RESERVED_DESKTOP_SURFACES or name.strip("/") in RESERVED_DESKTOP_SURFACES


def reject_reserved_external_surface(value: object, plugin_id: str, label: str) -> str:
    name = require_text(value, label, maximum=512)
    if reserved_external_desktop_surface(name):
        fail(f"external plugin {plugin_id} cannot claim reserved official Desktop surface {name}")
    return name


def require_external_contribution_map(
    value: object,
    plugin_id: str,
    label: str,
    *,
    reject_surface_identifiers: bool = True,
) -> dict[str, object]:
    if not isinstance(value, dict):
        fail(f"external plugin manifest {label} must be an object")
    for identifier, definition in value.items():
        if reject_surface_identifiers:
            reject_reserved_external_surface(identifier, plugin_id, f"external plugin manifest {label} ID")
        elif not isinstance(identifier, str):
            fail(f"external plugin manifest {label} IDs must be strings")
        if not isinstance(definition, dict):
            fail(f"external plugin manifest {label} entries must be objects")
    return value


def reject_reserved_external_contributions(desktop: object, plugin_id: str) -> None:
    """Keep optional external Factory packages out of Desktop-owned routes.

    Desktop gives all artifacts from the official pinned marketplace an
    ``OfficialMarketplace`` trust level. Its normal runtime check therefore
    permits the official reserved routes. The Factory's registry must preserve
    the distinction before an external package reaches that trust boundary.
    """

    if not isinstance(desktop, dict):
        fail("external plugin manifest has invalid XSEC Desktop metadata")
    contributes = desktop.get("contributes")
    if contributes is not None:
        if not isinstance(contributes, dict):
            fail("external plugin manifest contributions must be an object")
        workspace_tools = contributes.get("workspaceTools")
        if workspace_tools is not None:
            workspace_tools = require_external_contribution_map(
                workspace_tools,
                plugin_id,
                "workspaceTools",
                reject_surface_identifiers=False,
            )
            for name in workspace_tools:
                if name in RESERVED_OFFICIAL_WORKSPACE_CONTRIBUTIONS:
                    fail(
                        f"external plugin {plugin_id} cannot claim reserved official workspace contribution {name}"
                    )
        agent_tools = contributes.get("agentTools")
        if agent_tools is not None:
            agent_tools = require_external_contribution_map(
                agent_tools,
                plugin_id,
                "agentTools",
                reject_surface_identifiers=False,
            )
            for name, definition in agent_tools.items():
                if reserved_external_agent_tool(name):
                    fail(f"external plugin {plugin_id} cannot claim reserved Desktop MCP tool {name}")
                workspace_tool_id = definition.get("workspaceToolId")
                if workspace_tool_id is not None:
                    reject_reserved_external_surface(
                        workspace_tool_id,
                        plugin_id,
                        "external plugin manifest agentTools.workspaceToolId",
                    )

        navigation = contributes.get("navigation")
        if navigation is not None:
            if not isinstance(navigation, dict) or set(navigation) != {"items"}:
                fail("external plugin manifest navigation must contain only items")
            navigation_items = require_external_contribution_map(navigation.get("items"), plugin_id, "navigation.items")
            for definition in navigation_items.values():
                for field in ("route", "parent"):
                    if field in definition:
                        reject_reserved_external_surface(
                            definition[field],
                            plugin_id,
                            f"external plugin manifest navigation.items.{field}",
                        )

        routes = contributes.get("routes")
        if routes is not None:
            routes = require_external_contribution_map(routes, plugin_id, "routes")
            for definition in routes.values():
                for field in ("path", "page"):
                    if field in definition:
                        reject_reserved_external_surface(
                            definition[field],
                            plugin_id,
                            f"external plugin manifest routes.{field}",
                        )

        settings_pages = contributes.get("settingsPages")
        if settings_pages is not None:
            settings_pages = require_external_contribution_map(settings_pages, plugin_id, "settingsPages")
            for definition in settings_pages.values():
                if "page" in definition:
                    reject_reserved_external_surface(
                        definition["page"],
                        plugin_id,
                        "external plugin manifest settingsPages.page",
                    )

    activation_events = desktop.get("activationEvents")
    if activation_events is not None:
        if not isinstance(activation_events, list) or not all(isinstance(value, str) for value in activation_events):
            fail("external plugin manifest activationEvents must be a list of strings")
        for event in activation_events:
            if event.startswith("onWorkspaceTool:"):
                name = event.removeprefix("onWorkspaceTool:")
                if reserved_external_desktop_surface(name):
                    fail(f"external plugin {plugin_id} cannot activate reserved workspace contribution {name}")
            if event.startswith("onAgentTool:"):
                name = event.removeprefix("onAgentTool:")
                if reserved_external_agent_tool(name):
                    fail(f"external plugin {plugin_id} cannot activate reserved Desktop MCP tool {name}")
            if event.startswith("onRoute:"):
                reject_reserved_external_surface(
                    event.removeprefix("onRoute:"),
                    plugin_id,
                    "external plugin manifest onRoute activation",
                )
            if event.startswith("onSettingsPage:"):
                reject_reserved_external_surface(
                    event.removeprefix("onSettingsPage:"),
                    plugin_id,
                    "external plugin manifest onSettingsPage activation",
                )


def reject_unapproved_external_permissions(desktop: object, plugin_id: str) -> None:
    """Refuse capabilities that OfficialMarketplace would grant without a prompt."""

    if not isinstance(desktop, dict):
        fail("external plugin manifest has invalid XSEC Desktop metadata")
    permissions = desktop.get("permissions", {})
    if not isinstance(permissions, dict):
        fail("external plugin manifest permissions must be an object")
    for key in permissions:
        if not isinstance(key, str) or not key:
            fail("external plugin manifest permission keys must be non-empty strings")
        capability = key.split(":", 1)[0]
        if capability not in EXTERNAL_FACTORY_ALLOWED_CAPABILITIES:
            fail(
                f"external plugin {plugin_id} requests capability {capability}, "
                "which is not permitted for an automatic official Factory grant"
            )


def source_manifest(source_dir: Path, registration: Registration) -> dict[str, object]:
    try:
        # Validate the exact archive member namespace before this source is
        # copied into a Factory snapshot. `write_zip` repeats the check, but
        # failing here avoids committing a discoverable snapshot that Desktop
        # could never install. The shared walker also prunes excluded source
        # trees and applies source size/count limits before copytree or ZIP.
        iter_plugin_files(source_dir)
    except ValueError as error:
        raise ExternalSourceFactoryError(str(error)) from error
    manifest = read_json(source_dir / "plugin.json", f"external plugin manifest for {registration.plugin_id}")
    if manifest.get("name") != registration.plugin_id:
        fail("external plugin manifest name does not match registered plugin ID")
    version = manifest.get("version")
    if not isinstance(version, str) or not SEMVER_PATTERN.fullmatch(version):
        fail("external plugin manifest version must be valid SemVer")
    try:
        desktop = manifest["extensions"]["com.xsec.desktop"]
        engines = desktop["engines"]
        entrypoints = desktop["entrypoints"]
    except (KeyError, TypeError):
        fail("external plugin manifest lacks XSEC Desktop engine or entrypoint metadata")
    try:
        require_release_engines(engines, "external plugin manifest")
    except ValueError as error:
        raise ExternalSourceFactoryError(str(error)) from error
    # First-party registrations are a closed, compiled allowlist above.  They
    # deliberately retain the Desktop-owned routes/tools and capabilities in
    # their current manifests.  Every other registration remains on the
    # original restrictive external path.
    if registration.trust_tier == "external":
        reject_reserved_external_contributions(desktop, registration.plugin_id)
        reject_unapproved_external_permissions(desktop, registration.plugin_id)
    if not isinstance(entrypoints, dict) or not entrypoints:
        fail("external plugin manifest must declare XSEC Desktop entrypoints")
    for name, raw_path in entrypoints.items():
        if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", name):
            fail("external plugin manifest has an invalid XSEC Desktop entrypoint name")
        relative = safe_source_path(raw_path, f"external plugin entrypoint {name}")
        if any(part in SNAPSHOT_EXCLUDED_NAMES for part in relative.parts):
            fail(f"external plugin entrypoint {name} cannot point into excluded source content")
        current = source_dir
        if relative != PurePosixPath("."):
            for part in relative.parts:
                current = current / part
                if is_link(current):
                    fail(f"external plugin entrypoint {name} must not traverse symbolic links")
        require_below(source_dir, current, f"external plugin entrypoint {name}")
    return manifest


def ignored_names(_: str, names: list[str]) -> set[str]:
    return {name for name in names if name in SNAPSHOT_EXCLUDED_NAMES}


def swap_snapshot(root: Path, destination: Path, source_dir: Path) -> None:
    """Atomically-ish swap a staged snapshot while preserving release history.

    Windows cannot replace a non-empty directory with ``os.replace`` directly,
    so retain the old snapshot as a verified sibling until the staged directory
    is in place. This routine only operates below the checked-out Factory root.
    """

    plugin_root = root / SNAPSHOT_ROOT_RELATIVE_PATH
    if is_link(plugin_root):
        fail("plugins snapshot root must not be a symbolic link")
    plugin_root.mkdir(parents=True, exist_ok=True)
    try:
        plugin_root.resolve(strict=True).relative_to(root.resolve(strict=True))
    except (OSError, ValueError) as error:
        raise ExternalSourceFactoryError("plugins snapshot root escaped Factory root") from error
    if is_link(destination):
        fail("existing external plugin snapshot must not be a symbolic link")
    if destination.exists() and not destination.is_dir():
        fail("existing external plugin snapshot must be a directory")
    if destination.exists():
        require_link_free_tree(destination, "existing external plugin snapshot")
    with tempfile.TemporaryDirectory(prefix=f".{destination.name}.stage-", dir=plugin_root) as staging_parent:
        staging = Path(staging_parent) / destination.name
        shutil.copytree(source_dir, staging, ignore=ignored_names, copy_function=shutil.copy2)
        if destination.exists():
            history = destination / ".xsec-market"
            if history.exists():
                if is_link(history) or not history.is_dir():
                    fail("existing external release history must be a regular directory")
                require_link_free_tree(history, "existing external release history")
                shutil.copytree(history, staging / ".xsec-market", copy_function=shutil.copy2)
        # Re-check the staged snapshot before making the old source invisible.
        require_link_free_tree(staging, "staged external plugin snapshot")
        backup = plugin_root / f".{destination.name}.backup-{os.getpid()}"
        if backup.exists() or is_link(backup):
            fail("unexpected external snapshot backup path already exists")
        moved_old = False
        try:
            if destination.exists():
                os.replace(destination, backup)
                moved_old = True
            os.replace(staging, destination)
        except OSError as error:
            if moved_old and not destination.exists() and backup.exists():
                os.replace(backup, destination)
            raise ExternalSourceFactoryError(f"replace external plugin snapshot: {error}") from error
        finally:
            if backup.exists():
                shutil.rmtree(backup)


def marketplace_entry(registration: Registration) -> dict[str, object]:
    return {
        "name": registration.plugin_id,
        "source": {"source": "local", "path": f"./.xsec-factory/snapshots/{registration.plugin_id}"},
        "policy": {"installation": registration.installation, "authentication": registration.authentication},
        "category": registration.category,
    }


def require_owned_publication(root: Path, registration: Registration) -> None:
    """Refuse to claim an already discoverable plugin without Factory evidence."""

    if registration.trust_tier == "first-party":
        # A split built-in begins with its signed adoption rather than a
        # synthetic external-source evidence event.  The adoption locks the
        # retained release history and source identity before beta can replace
        # the snapshot; later source publications add normal evidence.
        validate_adoption(root, registration)
        return

    path = publication_path(root, registration.plugin_id)
    if not path.exists():
        fail(
            f"official external registry cannot claim existing plugin {registration.plugin_id} "
            "without Factory publication evidence"
        )
    evidence = read_json(path, f"official external publication evidence for {registration.plugin_id}")
    if (
        set(evidence) not in ({"schemaVersion", "pluginId", "events"}, {"schemaVersion", "pluginId", "events", "smokeOutcomes"})
        or evidence.get("schemaVersion") != 1
        or evidence.get("pluginId") != registration.plugin_id
        or not isinstance(evidence.get("events"), list)
        or not evidence["events"]
        or "smokeOutcomes" in evidence and not isinstance(evidence["smokeOutcomes"], list)
    ):
        fail(f"official external publication evidence for {registration.plugin_id} has invalid ownership metadata")


def update_marketplace_entry(root: Path, registration: Registration) -> None:
    path = root / MARKETPLACE_RELATIVE_PATH
    document = read_json(path, "official marketplace index")
    plugins = document.get("plugins")
    if not isinstance(plugins, list):
        fail("official marketplace index plugins must be a list")
    expected = marketplace_entry(registration)
    found = [index for index, value in enumerate(plugins) if isinstance(value, dict) and value.get("name") == registration.plugin_id]
    if len(found) > 1:
        fail("official marketplace index contains duplicate external plugin IDs")
    if found:
        # A registry can only own an entry it previously published. Merely
        # looking structurally like an external entry is not ownership: that
        # would allow a later registry edit to replace another publisher's
        # snapshot below the same local path.
        if registration.trust_tier == "first-party":
            # stage_beta already validated the prior snapshot/adoption before
            # replacing it.  At this point the new source has not yet been
            # packaged, so re-validating the old beta artifact against the
            # staged snapshot would reject every legitimate next release.
            proof = adoption_path(root, registration.plugin_id)
            if is_link(proof) or not proof.is_file():
                fail("first-party Factory snapshot is missing its adoption proof")
        else:
            require_owned_publication(root, registration)
        plugins[found[0]] = expected
    else:
        plugins.append(expected)
    stable_write(root, path, document, "official marketplace index")


def stage_beta(root: Path, plugin_id: str, source_root: Path) -> dict[str, str]:
    registration = registration_for(root, plugin_id)
    source_dir = resolve_source_directory(source_root, registration.source_path, f"external source for {registration.plugin_id}")
    source_manifest(source_dir, registration)
    destination = snapshot_directory(root, registration.plugin_id)
    if destination.exists() or is_link(destination):
        require_owned_publication(root, registration)
    swap_snapshot(root, destination, source_dir)
    update_marketplace_entry(root, registration)
    return {"plugin_id": registration.plugin_id, "snapshot_path": str(destination.resolve())}


def release_record(document: dict[str, object], release_id_value: str) -> dict[str, object]:
    releases = document.get("releases")
    if not isinstance(releases, list):
        fail("release metadata has invalid releases")
    for item in releases:
        if isinstance(item, dict) and item.get("releaseId") == release_id_value:
            return item
    fail("requested immutable release does not exist")


def current_beta_record(root: Path, plugin_id: str) -> tuple[dict[str, object], dict[str, object]]:
    path = release_path(root, plugin_id)
    try:
        document = load_release_document(path, plugin_id)
    except ValueError as error:
        raise ExternalSourceFactoryError(str(error)) from error
    channels = document.get("channels")
    if not isinstance(channels, dict):
        fail("release metadata has invalid channels")
    beta = channels.get("beta")
    identifier = beta.get("releaseId") if isinstance(beta, dict) else None
    if not isinstance(identifier, str) or not RELEASE_ID_PATTERN.fullmatch(identifier):
        fail("external beta release pointer is unavailable")
    return document, release_record(document, identifier)


def publication_event(registration: Registration, channel: str, source_sha: str, record: dict[str, object], publisher: str) -> dict[str, object]:
    source_sha = safe_sha(source_sha)
    publisher = require_text(publisher, "publication publisher", maximum=128)
    if channel not in {"beta", "stable"}:
        fail("publication channel must be beta or stable")
    artifact_list = record.get("artifacts")
    if not isinstance(artifact_list, list) or len(artifact_list) != 1 or not isinstance(artifact_list[0], dict):
        fail("external official release must have exactly one portable artifact")
    artifact = artifact_list[0]
    digest = artifact.get("sha256")
    url = artifact.get("url")
    if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest) or not isinstance(url, str):
        fail("external official release artifact is invalid")
    identifier = record.get("releaseId")
    if not isinstance(identifier, str) or not RELEASE_ID_PATTERN.fullmatch(identifier):
        fail("external official release ID is invalid")
    return {
        "channel": channel,
        "releaseId": identifier,
        "source": {
            "repository": registration.repository,
            "path": registration.source_path.as_posix(),
            "ref": registration.ref_for(channel),
            "sha": source_sha,
        },
        "artifact": {"sha256": digest, "url": url},
        "publisher": publisher,
    }


def append_evidence(root: Path, registration: Registration, event: dict[str, object]) -> None:
    path = publication_path(root, registration.plugin_id)
    smoke_outcomes: list[object] | None = None
    if path.exists():
        document = read_json(path, f"official external publication evidence for {registration.plugin_id}")
        if set(document) not in ({"schemaVersion", "pluginId", "events"}, {"schemaVersion", "pluginId", "events", "smokeOutcomes"}):
            fail(f"official external publication evidence for {registration.plugin_id} has invalid keys")
        if document.get("schemaVersion") != 1 or document.get("pluginId") != registration.plugin_id:
            fail("official external publication evidence has invalid identity")
        events = document.get("events")
        if not isinstance(events, list):
            fail("official external publication evidence events must be a list")
        if "smokeOutcomes" in document:
            smoke_outcomes = document.get("smokeOutcomes")
            if not isinstance(smoke_outcomes, list):
                fail("official external publication evidence smoke outcomes must be a list")
    else:
        events = []
    # A retry can be started by a different GitHub actor. Its immutable
    # publication identity is channel + release + source SHA, not the human
    # display identity. Keep the original audited publisher and avoid creating
    # a duplicate evidence key that the validator would rightly reject.
    source = event.get("source")
    source_sha = source.get("sha") if isinstance(source, dict) else None
    identity = (event.get("channel"), event.get("releaseId"), source_sha)
    for existing in events:
        if not isinstance(existing, dict):
            continue
        existing_source = existing.get("source")
        existing_identity = (
            existing.get("channel"),
            existing.get("releaseId"),
            existing_source.get("sha") if isinstance(existing_source, dict) else None,
        )
        if existing_identity == identity:
            return
    events.append(event)
    result: dict[str, object] = {"schemaVersion": 1, "pluginId": registration.plugin_id, "events": events}
    if smoke_outcomes is not None:
        result["smokeOutcomes"] = smoke_outcomes
    stable_write(root, path, result, f"official external publication evidence for {registration.plugin_id}")


def smoke_outcome(
    registration: Registration,
    *,
    beta_release_id: str,
    stable_release_id: str,
    beta_sha: str,
    stable_sha: str,
    smoke_run_url: str,
    marketplace_revision: str,
) -> dict[str, object]:
    """Build the KMS-bound record that proves one terminal smoke result.

    The status sidecar remains deliberately small and Desktop-readable, but it
    is authored in an ordinary generated Factory commit.  A terminal state
    therefore must also have this exact tuple inside the already KMS-signed
    publication evidence.  That makes a later hand-written status edit fail
    closed without giving the status file itself a second signing protocol.
    """

    if not isinstance(beta_release_id, str) or not RELEASE_ID_PATTERN.fullmatch(beta_release_id):
        fail("smoke outcome Beta release ID must be canonical")
    if not isinstance(stable_release_id, str) or not RELEASE_ID_PATTERN.fullmatch(stable_release_id):
        fail("smoke outcome Stable release ID must be canonical")
    return {
        "betaReleaseId": beta_release_id,
        "stableReleaseId": stable_release_id,
        "source": {
            "betaSha": safe_sha(beta_sha, "smoke outcome Beta source SHA"),
            "stableSha": safe_sha(stable_sha, "smoke outcome Stable source SHA"),
        },
        "smoke": {
            "runUrl": optional_url(smoke_run_url, "smoke outcome run URL"),
            "marketplaceRevision": safe_sha(marketplace_revision, "smoke outcome Marketplace revision"),
        },
    }


def evidence_event_matches(
    events: list[object],
    *,
    channel: str,
    release_id_value: str,
    source_sha: str,
) -> bool:
    """Return whether signed provenance has the exact source/release tuple."""

    return any(
        isinstance(event, dict)
        and event.get("channel") == channel
        and event.get("releaseId") == release_id_value
        and isinstance(event.get("source"), dict)
        and event["source"].get("sha") == source_sha
        for event in events
    )


def append_smoke_outcome(
    root: Path,
    registration: Registration,
    *,
    beta_release_id: str,
    stable_release_id: str,
    beta_sha: str,
    stable_sha: str,
    smoke_run_url: str,
    marketplace_revision: str,
) -> dict[str, object]:
    """Append one immutable, KMS-signed terminal smoke evidence record."""

    path = publication_path(root, registration.plugin_id)
    if is_link(path) or not path.is_file():
        fail("completed smoke status requires immutable publication evidence")
    document = read_json(path, f"official external publication evidence for {registration.plugin_id}")
    if set(document) not in ({"schemaVersion", "pluginId", "events"}, {"schemaVersion", "pluginId", "events", "smokeOutcomes"}):
        fail("completed smoke status publication evidence has invalid keys")
    if document.get("schemaVersion") != 1 or document.get("pluginId") != registration.plugin_id:
        fail("completed smoke status publication evidence has invalid identity")
    events = document.get("events")
    if not isinstance(events, list):
        fail("completed smoke status publication evidence events are invalid")
    outcome = smoke_outcome(
        registration,
        beta_release_id=beta_release_id,
        stable_release_id=stable_release_id,
        beta_sha=beta_sha,
        stable_sha=stable_sha,
        smoke_run_url=smoke_run_url,
        marketplace_revision=marketplace_revision,
    )
    source = require_object(outcome["source"], "smoke outcome source")
    if not evidence_event_matches(events, channel="beta", release_id_value=beta_release_id, source_sha=str(source["betaSha"])):
        fail("completed smoke status Beta source is not recorded in immutable publication evidence")
    if not evidence_event_matches(events, channel="stable", release_id_value=stable_release_id, source_sha=str(source["stableSha"])):
        fail("completed smoke status Stable source is not recorded in immutable publication evidence")
    outcomes = document.get("smokeOutcomes", [])
    if not isinstance(outcomes, list):
        fail("completed smoke status publication evidence smoke outcomes are invalid")
    identity = (beta_release_id, stable_release_id, str(source["betaSha"]), str(source["stableSha"]))
    for existing in outcomes:
        if not isinstance(existing, dict):
            continue
        existing_source = existing.get("source")
        existing_identity = (
            existing.get("betaReleaseId"),
            existing.get("stableReleaseId"),
            existing_source.get("betaSha") if isinstance(existing_source, dict) else None,
            existing_source.get("stableSha") if isinstance(existing_source, dict) else None,
        )
        if existing_identity == identity:
            # GitHub can redeliver the same accepted smoke completion with a
            # different run attempt URL. The original KMS-bound outcome is
            # the immutable audit record, so keep it rather than either
            # replacing it or treating the retry as a publication failure.
            return existing
    outcomes.append(outcome)
    stable_write(
        root,
        path,
        {"schemaVersion": 1, "pluginId": registration.plugin_id, "events": events, "smokeOutcomes": outcomes},
        f"official external publication evidence for {registration.plugin_id}",
    )
    return outcome


def record_beta(root: Path, plugin_id: str, source_sha: str, publisher: str) -> dict[str, str]:
    registration = registration_for(root, plugin_id)
    _, record = current_beta_record(root, registration.plugin_id)
    append_evidence(root, registration, publication_event(registration, "beta", source_sha, record, publisher))
    return {"plugin_id": registration.plugin_id, "release_id": str(record["releaseId"]), "channel": "beta"}


def candidate_release_id(source_dir: Path, registration: Registration) -> str:
    manifest = source_manifest(source_dir, registration)
    try:
        engines = require_release_engines(manifest["extensions"]["com.xsec.desktop"]["engines"], "external plugin manifest")
    except (KeyError, TypeError, ValueError) as error:
        raise ExternalSourceFactoryError("external plugin manifest engines are invalid") from error
    version = manifest.get("version")
    if not isinstance(version, str):
        fail("external plugin manifest version is invalid")
    with tempfile.TemporaryDirectory(prefix="xsec-official-external-package-") as directory:
        artifact = Path(directory) / "candidate.xsec-plugin"
        write_zip(source_dir, artifact)
        return release_id(
            version,
            engines,
            [{"os": "any", "arch": "any", "url": "ignored", "sha256": sha256(artifact)}],
        )


def verify_stable(
    root: Path,
    plugin_id: str,
    source_root: Path,
    release_id_value: str,
    *,
    expected_beta_sha: str | None = None,
) -> dict[str, str]:
    registration = registration_for(root, plugin_id)
    if not isinstance(release_id_value, str) or not RELEASE_ID_PATTERN.fullmatch(release_id_value):
        fail("stable promotion release ID must be canonical")
    source_dir = resolve_source_directory(source_root, registration.source_path, f"external stable source for {registration.plugin_id}")
    candidate = candidate_release_id(source_dir, registration)
    document, current_beta = current_beta_record(root, registration.plugin_id)
    if current_beta.get("releaseId") != release_id_value:
        fail("stable promotion release ID does not match the current Beta pointer")
    if expected_beta_sha is not None:
        expected = safe_sha(expected_beta_sha, "smoke-verified Beta source SHA")
        # This recheck runs in publish.yml after it acquired the shared
        # publication slot and checked out current protected Factory main.
        # A later beta commit can have identical artifact bytes/releaseId, so
        # releaseId alone cannot bind an older Desktop smoke callback.
        validate_status(root, registration)
        status = read_json(status_path(root, registration.plugin_id), f"official Factory status for {registration.plugin_id}")
        source = require_object(status.get("source"), "smoke-verified Factory status source")
        status_release = require_object(status.get("release"), "smoke-verified Factory status release")
        if source.get("betaSha") != expected or status_release.get("betaReleaseId") != release_id_value:
            fail("current Beta source SHA does not match the smoke-verified Beta")
    selected = release_record(document, release_id_value)
    if candidate != release_id_value:
        fail("external main source does not deterministically rebuild the selected Beta releaseId")
    if selected.get("releaseId") != candidate:
        fail("selected external Beta release is invalid")
    return {"plugin_id": registration.plugin_id, "release_id": release_id_value, "channel": "stable"}


def check_main_rebuild(root: Path, plugin_id: str, source_root: Path) -> dict[str, str]:
    """Classify whether registered main deterministically rebuilds current Beta.

    This is intentionally a read-only preflight for the beta lifecycle.  A
    nonmatching main is a normal release-ordering condition, not a Stable
    promotion failure: the caller records ``waiting_for_beta`` and must not
    create Stable provenance, move a channel pointer, or request Desktop
    smoke.  Malformed source, registry, or immutable release data still fails
    closed instead of being misreported as an ordinary mismatch.
    """

    registration = registration_for(root, plugin_id)
    source_dir = resolve_source_directory(
        source_root,
        registration.source_path,
        f"external main source for {registration.plugin_id}",
    )
    candidate = candidate_release_id(source_dir, registration)
    _, current_beta = current_beta_record(root, registration.plugin_id)
    beta_release_id = current_beta.get("releaseId")
    if not isinstance(beta_release_id, str) or not RELEASE_ID_PATTERN.fullmatch(beta_release_id):
        fail("external beta release pointer is unavailable")
    smoke_ready = candidate == beta_release_id
    return {
        "plugin_id": registration.plugin_id,
        "beta_release_id": beta_release_id,
        "candidate_release_id": candidate,
        "state": "waiting_for_smoke" if smoke_ready else "waiting_for_beta",
        "smoke_ready": "true" if smoke_ready else "false",
    }


def record_stable(root: Path, plugin_id: str, source_sha: str, release_id_value: str, publisher: str) -> dict[str, str]:
    registration = registration_for(root, plugin_id)
    if not isinstance(release_id_value, str) or not RELEASE_ID_PATTERN.fullmatch(release_id_value):
        fail("stable promotion release ID must be canonical")
    document, current_beta = current_beta_record(root, registration.plugin_id)
    if current_beta.get("releaseId") != release_id_value:
        fail("stable provenance can be recorded only for the current Beta release")
    channels = document.get("channels")
    stable = channels.get("stable") if isinstance(channels, dict) else None
    if not isinstance(stable, dict) or stable.get("releaseId") != release_id_value:
        fail("stable provenance can be recorded only after the selected stable pointer is written")
    record = release_record(document, release_id_value)
    append_evidence(root, registration, publication_event(registration, "stable", source_sha, record, publisher))
    return {"plugin_id": registration.plugin_id, "release_id": release_id_value, "channel": "stable"}


def release_channels(document: dict[str, object]) -> tuple[str, str | None]:
    channels = document.get("channels")
    if not isinstance(channels, dict) or set(channels) != {"beta", "stable"}:
        fail("release metadata has invalid channels")
    beta = release_pointer(channels.get("beta"), "release metadata channels.beta")
    stable = release_pointer(channels.get("stable"), "release metadata channels.stable")
    if beta is None:
        fail("release metadata beta pointer is unavailable")
    return beta, stable


def adoption_document(
    root: Path,
    registration: Registration,
    *,
    beta_sha: str,
    stable_sha: str,
    factory_revision: str,
) -> dict[str, object]:
    """Build the exact first-party migration assertion before KMS signing.

    This records no new release and never writes a channel pointer.  It binds
    the pre-existing immutable Factory history to two exact source heads so a
    later registry/source rewrite cannot silently claim those releases.
    """

    if registration.trust_tier != "first-party":
        fail("only a first-party registration can create an adoption proof")
    release = release_path(root, registration.plugin_id)
    try:
        document = load_release_document(release, registration.plugin_id)
    except ValueError as error:
        raise ExternalSourceFactoryError(str(error)) from error
    releases = document.get("releases")
    if not isinstance(releases, list) or not releases:
        fail("first-party adoption requires immutable release history")
    release_ids: list[str] = []
    for index, record in enumerate(releases):
        if not isinstance(record, dict):
            fail(f"first-party adoption release {index} is invalid")
        identifier = record.get("releaseId")
        if not isinstance(identifier, str) or not RELEASE_ID_PATTERN.fullmatch(identifier):
            fail(f"first-party adoption release {index} has an invalid releaseId")
        release_ids.append(identifier)
    if len(release_ids) != len(set(release_ids)):
        fail("first-party adoption release history contains duplicate release IDs")
    beta, stable = release_channels(document)
    return {
        "schemaVersion": 1,
        "pluginId": registration.plugin_id,
        "trustTier": "first-party",
        "source": {
            "repository": registration.repository,
            "path": registration.source_path.as_posix(),
            "refs": {"beta": registration.beta_ref, "stable": registration.stable_ref},
            "betaSha": safe_sha(beta_sha, "first-party adoption beta SHA"),
            "stableSha": safe_sha(stable_sha, "first-party adoption stable SHA"),
        },
        "legacy": {
            "factoryRevision": safe_sha(factory_revision, "first-party adoption Factory revision"),
            "releaseDocumentSha256": sha256(release),
            "releaseDocumentB64": base64.b64encode(release.read_bytes()).decode("ascii"),
            "releaseIds": release_ids,
            "releaseRecords": releases,
        },
        "channels": {
            "beta": {"releaseId": beta},
            "stable": None if stable is None else {"releaseId": stable},
        },
    }


def create_adoption(
    root: Path,
    plugin_id: str,
    *,
    beta_sha: str,
    stable_sha: str,
    factory_revision: str,
) -> dict[str, str]:
    registration = registration_for(root, plugin_id, active=False)
    if registration.status != "pending-adoption":
        fail("first-party adoption can be created only from a pending-adoption registration")
    document = adoption_document(
        root,
        registration,
        beta_sha=beta_sha,
        stable_sha=stable_sha,
        factory_revision=factory_revision,
    )
    path = adoption_path(root, registration.plugin_id)
    if path.exists():
        existing = read_json(path, f"first-party adoption proof for {registration.plugin_id}")
        if existing != document:
            fail("first-party adoption proof is immutable; create a new source publication instead")
    else:
        stable_write(root, path, document, f"first-party adoption proof for {registration.plugin_id}")
    return {"plugin_id": registration.plugin_id, "trust_tier": registration.trust_tier, "adoption": "created"}


def prepare_staged_adoption(
    root: Path,
    plugin_id: str,
    *,
    baseline_root: Path,
    factory_revision: str,
) -> dict[str, str]:
    """Rebuild and read the validated unsigned adoption assertion.

    The Cloud KMS broker reads the record from protected ``main`` before it
    signs it.  This accepts no caller-supplied source SHA: the source tuple is
    exclusively the immutable tuple previously validated in the staged proof.
    More importantly, the assertion's retained-history fields are rebuilt
    from the protected parent that existed *before* that proof was added.
    Keeping this separate from :func:`create_adoption` means the signing
    workflow can never introduce, amend, or merely structurally validate the
    bytes it asks KMS to attest.
    """

    registration = registration_for(root, plugin_id, active=False)
    if registration.trust_tier != "first-party" or registration.status != "pending-adoption":
        fail("only a pending first-party registration can be adopted")
    try:
        baseline = baseline_root.resolve(strict=True)
        current = root.resolve(strict=True)
    except OSError as error:
        raise ExternalSourceFactoryError("trusted pre-staging Factory baseline is unavailable") from error
    if baseline == current or is_link(baseline) or not baseline.is_dir():
        fail("trusted pre-staging Factory baseline must be a distinct regular directory")
    baseline_registration = registration_for(baseline, plugin_id, active=False)
    if baseline_registration != registration:
        fail("trusted pre-staging Factory registration does not match the staged registration")
    proof_path = adoption_path(root, registration.plugin_id)
    baseline_proof_path = adoption_path(baseline, registration.plugin_id)
    sidecar_path = root / ADOPTION_PROOFS_RELATIVE_PATH / f"{registration.plugin_id}.json"
    if is_link(proof_path) or not proof_path.is_file():
        fail("first-party adoption proof must be staged on protected Factory main before signing")
    if baseline_proof_path.exists() or is_link(baseline_proof_path):
        fail("trusted pre-staging Factory baseline already contains the adoption proof")
    if sidecar_path.exists() or is_link(sidecar_path):
        fail("first-party adoption proof is already signed; activation must use the existing validated proof")
    validate_adoption(root, registration, require_kms_proof=False)
    proof = read_json(proof_path, f"first-party adoption proof for {registration.plugin_id}")
    source = require_object(proof.get("source"), "first-party adoption proof source")
    beta_sha = safe_sha(source.get("betaSha"), "staged first-party adoption beta SHA")
    stable_sha = safe_sha(source.get("stableSha"), "staged first-party adoption stable SHA")
    expected = adoption_document(
        baseline,
        baseline_registration,
        beta_sha=beta_sha,
        stable_sha=stable_sha,
        factory_revision=safe_sha(factory_revision, "trusted pre-staging Factory revision"),
    )
    if proof_path.read_bytes() != stable_json(expected):
        fail("staged first-party adoption proof does not exactly match the protected pre-staging assertion")
    owner, repository = registration.repository.split("/", 1)
    return {
        "plugin_id": registration.plugin_id,
        "source_repository": registration.repository,
        "source_owner": owner,
        "source_repo": repository,
        "beta_ref": registration.beta_ref,
        "stable_ref": registration.stable_ref,
        "beta_sha": beta_sha,
        "stable_sha": stable_sha,
        "adoption_path": adoption_path(root, registration.plugin_id).relative_to(root).as_posix(),
        "adoption": "staged",
    }


def activate_first_party(root: Path, plugin_id: str) -> dict[str, str]:
    """Move one KMS-staged first-party registration to its active state."""

    registration = registration_for(root, plugin_id, active=False)
    if registration.trust_tier != "first-party" or registration.status != "pending-adoption":
        fail("only a pending first-party registration can be activated")
    proof = adoption_path(root, registration.plugin_id)
    if is_link(proof) or not proof.is_file():
        fail("first-party adoption proof must be staged before activation")
    # The unsigned staging record is intentionally harmless while the
    # Registry remains pending. Never let activation make it trusted until the
    # protected KMS workflow has signed those exact bytes.
    validate_adoption(root, registration, require_kms_proof=True)
    registry_path = root / REGISTRY_RELATIVE_PATH
    registry = read_json(registry_path, "official Factory registry")
    plugins = registry.get("plugins")
    if not isinstance(plugins, list):
        fail("official Factory registry plugins must be a list")
    changed = False
    for entry in plugins:
        if isinstance(entry, dict) and entry.get("pluginId") == registration.plugin_id:
            entry["status"] = "active"
            changed = True
    if not changed:
        fail("pending first-party registration disappeared before activation")
    stable_write(root, registry_path, registry, "official Factory registry")
    return {"plugin_id": registration.plugin_id, "status": "active"}


def validate_adoption(
    root: Path,
    registration: Registration,
    *,
    require_kms_proof: bool = True,
    require_active_release_sidecar: bool = True,
) -> None:
    if registration.trust_tier != "first-party":
        return
    path = adoption_path(root, registration.plugin_id)
    if not path.exists() or is_link(path) or not path.is_file():
        fail(f"first-party plugin {registration.plugin_id} has no KMS adoption proof")
    proof = read_json(path, f"first-party adoption proof for {registration.plugin_id}")
    require_exact_keys(proof, {"schemaVersion", "pluginId", "trustTier", "source", "legacy", "channels"}, "first-party adoption proof")
    if proof.get("schemaVersion") != 1 or proof.get("pluginId") != registration.plugin_id or proof.get("trustTier") != "first-party":
        fail("first-party adoption proof has an invalid identity")
    source = require_object(proof.get("source"), "first-party adoption proof source")
    require_exact_keys(source, {"repository", "path", "refs", "betaSha", "stableSha"}, "first-party adoption proof source")
    refs = require_object(source.get("refs"), "first-party adoption proof source.refs")
    require_exact_keys(refs, {"beta", "stable"}, "first-party adoption proof source.refs")
    if (
        source.get("repository") != registration.repository
        or source.get("path") != registration.source_path.as_posix()
        or refs.get("beta") != registration.beta_ref
        or refs.get("stable") != registration.stable_ref
    ):
        fail("first-party adoption proof source does not match the official registry")
    safe_sha(source.get("betaSha"), "first-party adoption proof beta SHA")
    safe_sha(source.get("stableSha"), "first-party adoption proof stable SHA")
    legacy = require_object(proof.get("legacy"), "first-party adoption proof legacy")
    require_exact_keys(legacy, {"factoryRevision", "releaseDocumentSha256", "releaseDocumentB64", "releaseIds", "releaseRecords"}, "first-party adoption proof legacy")
    safe_sha(legacy.get("factoryRevision"), "first-party adoption proof Factory revision")
    digest = legacy.get("releaseDocumentSha256")
    if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
        fail("first-party adoption proof release history digest is invalid")
    encoded_document = legacy.get("releaseDocumentB64")
    if not isinstance(encoded_document, str) or not encoded_document or len(encoded_document) % 4:
        fail("first-party adoption proof release history bytes are invalid")
    try:
        adopted_bytes = base64.b64decode(encoded_document, validate=True)
    except ValueError as error:
        raise ExternalSourceFactoryError("first-party adoption proof release history bytes are invalid") from error
    if base64.b64encode(adopted_bytes).decode("ascii") != encoded_document or hashlib.sha256(adopted_bytes).hexdigest() != digest:
        fail("first-party adoption proof release history digest does not match")
    try:
        release_document = load_release_document(release_path(root, registration.plugin_id), registration.plugin_id)
    except ValueError as error:
        raise ExternalSourceFactoryError(str(error)) from error
    records = release_document.get("releases")
    release_ids = [item.get("releaseId") for item in records] if isinstance(records, list) and all(isinstance(item, dict) for item in records) else []
    legacy_records = legacy.get("releaseRecords")
    if not isinstance(legacy_records, list) or not all(isinstance(item, dict) for item in legacy_records):
        fail("first-party adoption proof legacy release records are invalid")
    legacy_ids = legacy.get("releaseIds")
    if not isinstance(legacy_ids, list) or legacy_ids != [item.get("releaseId") for item in legacy_records]:
        fail("first-party adoption proof legacy release IDs are invalid")
    if release_ids[: len(legacy_ids)] != legacy_ids or records[: len(legacy_records)] != legacy_records:
        fail("first-party adoption proof release history does not match")
    beta, _ = release_channels(release_document)
    channels = require_object(proof.get("channels"), "first-party adoption proof channels")
    require_exact_keys(channels, {"beta", "stable"}, "first-party adoption proof channels")
    adopted_beta = release_pointer(channels.get("beta"), "first-party adoption proof channels.beta")
    adopted_stable = release_pointer(channels.get("stable"), "first-party adoption proof channels.stable")
    if adopted_beta not in legacy_ids or adopted_stable is not None and adopted_stable not in legacy_ids:
        fail("first-party adoption proof channel pointer is not historical")
    adopted_release_document = {
        "schemaVersion": 2,
        "pluginId": registration.plugin_id,
        "releases": legacy_records,
        "channels": {"beta": {"releaseId": adopted_beta}, "stable": None if adopted_stable is None else {"releaseId": adopted_stable}},
    }
    try:
        if json.loads(adopted_bytes) != adopted_release_document:
            fail("first-party adoption proof release history bytes do not match its semantic records")
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ExternalSourceFactoryError("first-party adoption proof release history bytes are invalid") from error
    validate_disabled_snapshot_artifacts(root, registration, snapshot_directory(root, registration.plugin_id), release_document, release_record(release_document, beta))
    release_sidecar = release_path(root, registration.plugin_id).with_name("releases.json.sig.jws.json")
    if is_link(release_sidecar):
        fail(f"first-party plugin {registration.plugin_id} KMS release sidecar is unavailable")
    if not release_sidecar.is_file():
        # ``build_market.py --clean`` deliberately removes active release
        # sidecars before the protected publisher replaces them through Cloud
        # KMS. Normal validation remains strict; this bounded pre-KMS staging
        # exception is an explicit caller choice. A present malformed sidecar
        # is never accepted.
        if require_active_release_sidecar:
            fail(f"first-party plugin {registration.plugin_id} KMS release sidecar is unavailable")
    else:
        release_subject = f".xsec-factory/snapshots/{registration.plugin_id}/.xsec-market/releases.json"
        try:
            verify_historical_sidecar_signature(
                release_sidecar.read_bytes(),
                MarketplaceDocument("xsec.plugin-marketplace.release", release_subject, release_path(root, registration.plugin_id)),
            )
        except (OSError, MarketplaceKmsPublisherError) as error:
            raise ExternalSourceFactoryError(f"first-party plugin {registration.plugin_id} KMS release sidecar is invalid") from error
    if not require_kms_proof:
        return
    try:
        kms_document = official_adoption_provenance_document(root, registration.plugin_id)
        sidecar = sidecar_path_for(kms_document)
        if is_link(sidecar) or not sidecar.is_file():
            fail(f"first-party plugin {registration.plugin_id} KMS adoption proof is unavailable")
        verify_historical_sidecar_signature(sidecar.read_bytes(), kms_document)
    except (OSError, MarketplaceKmsPublisherError) as error:
        raise ExternalSourceFactoryError(f"first-party plugin {registration.plugin_id} KMS adoption proof is invalid") from error


def adopted_release_ids(root: Path, registration: Registration, *, state_label: str) -> tuple[str, ...]:
    """Read the immutable release prefix covered by a first-party adoption.

    The adoption validator proves the complete record/byte binding. This
    narrow reader is also used by the trusted-baseline continuity pass, which
    must know when normal source-publication evidence becomes mandatory after
    the adopted history rather than treating adoption as a perpetual substitute.
    """

    if registration.trust_tier != "first-party":
        fail(f"{state_label} is not a first-party registration")
    path = adoption_path(root, registration.plugin_id)
    if is_link(path) or not path.is_file():
        fail(f"{state_label} first-party adoption proof for {registration.plugin_id} is unavailable")
    proof = read_json(path, f"{state_label} first-party adoption proof for {registration.plugin_id}")
    legacy = require_object(proof.get("legacy"), f"{state_label} first-party adoption proof legacy")
    identifiers = legacy.get("releaseIds")
    if not isinstance(identifiers, list) or not identifiers or not all(
        isinstance(identifier, str) and RELEASE_ID_PATTERN.fullmatch(identifier) for identifier in identifiers
    ):
        fail(f"{state_label} first-party adoption proof legacy release IDs are invalid")
    if len(set(identifiers)) != len(identifiers):
        fail(f"{state_label} first-party adoption proof legacy release IDs are duplicated")
    return tuple(identifiers)


def first_party_has_post_adoption_history(root: Path, registration: Registration, *, state_label: str) -> bool:
    """Whether split-source provenance exists beyond the signed adoption.

    A new source SHA may deterministically reproduce a retained adopted
    artifact, so it does not necessarily append a new release ID.  Its
    KMS-bound publication event is nevertheless the start of a new Beta
    lifecycle and must be retained by the trusted-baseline gate.
    """

    adopted_ids = adopted_release_ids(root, registration, state_label=state_label)
    try:
        document = load_release_document(release_path(root, registration.plugin_id), registration.plugin_id)
    except ValueError as error:
        raise ExternalSourceFactoryError(str(error)) from error
    records = document.get("releases")
    if not isinstance(records, list) or not all(isinstance(record, dict) for record in records):
        fail(f"{state_label} first-party release history is invalid")
    release_ids = tuple(record.get("releaseId") for record in records)
    if not all(isinstance(identifier, str) and RELEASE_ID_PATTERN.fullmatch(identifier) for identifier in release_ids):
        fail(f"{state_label} first-party release history IDs are invalid")
    if release_ids[: len(adopted_ids)] != adopted_ids:
        fail(f"{state_label} first-party release history does not retain its adopted prefix")
    evidence = publication_path(root, registration.plugin_id)
    return len(release_ids) > len(adopted_ids) or evidence.exists() or is_link(evidence)


def optional_url(value: object, label: str) -> str | None:
    if value is None:
        return None
    text = require_text(value, label, maximum=512)
    if not text.startswith("https://github.com/") or any(character in text for character in "\r\n\\"):
        fail(f"{label} must be a GitHub HTTPS URL")
    return text


def status_document(
    root: Path,
    registration: Registration,
    *,
    beta_sha: str | None,
    stable_sha: str | None,
    main_gate_sha: str | None,
    state: str,
    delivery_id: str,
    factory_run_url: str | None = None,
    smoke_run_url: str | None = None,
    marketplace_revision: str | None = None,
) -> dict[str, object]:
    if state not in PUBLICATION_STATES:
        fail("official Factory status state is invalid")
    delivery = require_text(delivery_id, "official Factory status deliveryId", maximum=160)
    beta: str | None = None
    stable: str | None = None
    release = release_path(root, registration.plugin_id)
    if release.exists() and not is_link(release):
        try:
            document = load_release_document(release, registration.plugin_id)
        except ValueError as error:
            raise ExternalSourceFactoryError(str(error)) from error
        beta, stable = release_channels(document)
    return {
        "schemaVersion": 1,
        "pluginId": registration.plugin_id,
        "trustTier": registration.trust_tier,
        "source": {
            "repository": registration.repository,
            "path": registration.source_path.as_posix(),
            "refs": {"beta": registration.beta_ref, "stable": registration.stable_ref},
            "betaSha": optional_sha(beta_sha, "official Factory status betaSha"),
            "stableSha": optional_sha(stable_sha, "official Factory status stableSha"),
            # This is the exact registered ``main`` head whose deterministic
            # package identity permitted the current Beta smoke cycle.  It is
            # deliberately distinct from stableSha: waiting states must not
            # claim that Stable was promoted or smoke-verified.
            "mainGateSha": optional_sha(main_gate_sha, "official Factory status mainGateSha"),
        },
        "release": {
            "betaReleaseId": beta,
            "stableReleaseId": stable,
        },
        "publication": {
            "state": state,
            "deliveryId": delivery,
            "factoryRunUrl": optional_url(factory_run_url, "official Factory status factoryRunUrl"),
            "smokeRunUrl": optional_url(smoke_run_url, "official Factory status smokeRunUrl"),
            "marketplaceRevision": optional_sha(marketplace_revision, "official Factory status marketplaceRevision"),
        },
    }


def record_status(
    root: Path,
    plugin_id: str,
    *,
    beta_sha: str | None,
    stable_sha: str | None,
    main_gate_sha: str | None = None,
    state: str,
    delivery_id: str,
    factory_run_url: str | None = None,
    smoke_run_url: str | None = None,
    marketplace_revision: str | None = None,
) -> dict[str, str]:
    registration = registration_for(root, plugin_id, active=False)
    path = status_path(root, registration.plugin_id)
    existing: dict[str, object] | None = None
    if path.exists():
        existing = read_json(path, f"official Factory status for {registration.plugin_id}")
        # A manual Stable recovery deliberately supplies only the newly
        # verified main SHA. It is not a new Beta delivery, so clearing the
        # already smoke-bound Beta SHA would make the later genuine smoke
        # callback fail its exact-pointer recheck. Preserve only this missing
        # value; a Beta publication always supplies a replacement explicitly
        # and therefore still clears stale Stable metadata as intended.
        if beta_sha is None:
            existing_source = existing.get("source")
            if isinstance(existing_source, dict):
                beta_sha = optional_sha(existing_source.get("betaSha"), "existing official Factory status betaSha")
        # Stable completion and a late smoke callback must retain the last
        # validated main-rebuild proof.  A Beta publication passes a new value
        # explicitly, so it can never inherit a proof for a different cycle.
        if main_gate_sha is None:
            existing_source = existing.get("source")
            if isinstance(existing_source, dict):
                main_gate_sha = optional_sha(
                    existing_source.get("mainGateSha"), "existing official Factory status mainGateSha"
                )
    document = status_document(
        root,
        registration,
        beta_sha=beta_sha,
        stable_sha=stable_sha,
        main_gate_sha=main_gate_sha,
        state=state,
        delivery_id=delivery_id,
        factory_run_url=factory_run_url,
        smoke_run_url=smoke_run_url,
        marketplace_revision=marketplace_revision,
    )
    if existing is not None:
        # A redelivered Beta event may arrive after its exact immutable
        # release has completed Desktop smoke and reached Stable.  Its
        # generated waiting_for_smoke document intentionally has no Stable
        # source/SHA or smoke fields, so comparing whole source/publication
        # objects would regress an audited terminal state. Preserve it only
        # when the current release pointers and Beta source SHA are exactly
        # identical; a new Beta, pointer movement, or source revision still
        # starts a new state transition.
        if (
            state in {"waiting_for_beta", "waiting_for_smoke"}
            and existing.get("schemaVersion") == document["schemaVersion"]
            and existing.get("pluginId") == document["pluginId"]
            and existing.get("trustTier") == document["trustTier"]
            and isinstance(existing.get("source"), dict)
            and isinstance(document.get("source"), dict)
            and existing["source"].get("repository") == document["source"].get("repository")
            and existing["source"].get("path") == document["source"].get("path")
            and existing["source"].get("refs") == document["source"].get("refs")
            and existing["source"].get("betaSha") == document["source"].get("betaSha")
            and existing.get("release") == document["release"]
            and isinstance(existing.get("publication"), dict)
            and existing["publication"].get("state") == "published"
        ):
            return {"plugin_id": registration.plugin_id, "state": "published", "unchanged": "true"}
        # Delivery/run URLs are observability hints, not release identity.  A
        # duplicate Cloud delivery must not create a fresh signed Factory
        # commit merely because it has a new Actions run id.  Keep the first
        # audited delivery whenever the source/release/state/revision tuple is
        # unchanged; a meaningful state transition still overwrites it.
        if (
            existing.get("schemaVersion") == document["schemaVersion"]
            and existing.get("pluginId") == document["pluginId"]
            and existing.get("trustTier") == document["trustTier"]
            and existing.get("source") == document["source"]
            and existing.get("release") == document["release"]
            and isinstance(existing.get("publication"), dict)
            and isinstance(document.get("publication"), dict)
            and existing["publication"].get("state") == document["publication"].get("state")
            and existing["publication"].get("marketplaceRevision") == document["publication"].get("marketplaceRevision")
        ):
            return {"plugin_id": registration.plugin_id, "state": state, "unchanged": "true"}
    stable_write(root, path, document, f"official Factory status for {registration.plugin_id}")
    return {"plugin_id": registration.plugin_id, "state": state}


def complete_smoke_status(
    root: Path,
    plugin_id: str,
    *,
    beta_release_id: str,
    stable_sha: str | None,
    delivery_id: str,
    smoke_run_url: str,
    marketplace_revision: str,
) -> dict[str, str]:
    """Write a terminal Beta-smoke status without accepting caller source data.

    ``reconcile-smoke`` has already established that ``marketplace_revision``
    is retained Factory main and that its Beta pointer still matches the
    current one. This function repeats the local pointer/status binding so a
    callback cannot overwrite the recorded Beta source SHA or Factory run URL
    while merely supplying a plausible display record.  ``stable_sha`` is
    supplied only by the protected Stable publisher after it has independently
    rebuilt this exact Beta release from the registered source ``main`` head.
    """

    registration = registration_for(root, plugin_id)
    if not isinstance(beta_release_id, str) or not RELEASE_ID_PATTERN.fullmatch(beta_release_id):
        fail("completed smoke Beta release ID must be canonical")
    path = status_path(root, registration.plugin_id)
    if is_link(path) or not path.is_file():
        fail("completed smoke status requires the prior Factory Beta status")
    existing = read_json(path, f"official Factory status for {registration.plugin_id}")
    require_exact_keys(
        existing,
        {"schemaVersion", "pluginId", "trustTier", "source", "release", "publication"},
        "completed smoke status",
    )
    if (
        existing.get("schemaVersion") != 1
        or existing.get("pluginId") != registration.plugin_id
        or existing.get("trustTier") != registration.trust_tier
    ):
        fail("completed smoke status has an invalid identity")
    source = require_object(existing.get("source"), "completed smoke status source")
    require_exact_keys(
        source,
        {"repository", "path", "refs", "betaSha", "stableSha", "mainGateSha"},
        "completed smoke status source",
    )
    refs = require_object(source.get("refs"), "completed smoke status source.refs")
    require_exact_keys(refs, {"beta", "stable"}, "completed smoke status source.refs")
    if (
        source.get("repository") != registration.repository
        or source.get("path") != registration.source_path.as_posix()
        or refs.get("beta") != registration.beta_ref
        or refs.get("stable") != registration.stable_ref
    ):
        fail("completed smoke status source does not match the official registry")
    beta_sha = optional_sha(source.get("betaSha"), "completed smoke status betaSha")
    prior_stable_sha = optional_sha(source.get("stableSha"), "completed smoke status stableSha")
    prior_main_gate_sha = optional_sha(source.get("mainGateSha"), "completed smoke status mainGateSha")
    if beta_sha is None:
        fail("completed smoke status has no Beta source SHA")
    release = require_object(existing.get("release"), "completed smoke status release")
    require_exact_keys(release, {"betaReleaseId", "stableReleaseId"}, "completed smoke status release")
    if release.get("betaReleaseId") != beta_release_id:
        fail("completed smoke status Beta release does not match the current Factory status")
    publication = require_object(existing.get("publication"), "completed smoke status publication")
    require_exact_keys(
        publication,
        {"state", "deliveryId", "factoryRunUrl", "smokeRunUrl", "marketplaceRevision"},
        "completed smoke status publication",
    )
    if publication.get("state") not in {"waiting_for_smoke", "promoting_stable", "published"}:
        fail("completed smoke status does not represent a smoke-gated publication")
    factory_run_url = optional_url(publication.get("factoryRunUrl"), "completed smoke status factoryRunUrl")
    current_release = release_path(root, registration.plugin_id)
    try:
        current_document = load_release_document(current_release, registration.plugin_id)
    except ValueError as error:
        raise ExternalSourceFactoryError(str(error)) from error
    current_beta, current_stable = release_channels(current_document)
    if current_beta != beta_release_id:
        fail("completed smoke status Beta release does not match immutable release metadata")
    if current_stable != beta_release_id:
        fail("completed smoke status requires the Stable pointer to match its smoke-verified Beta")
    resolved_stable_sha = optional_sha(stable_sha, "completed smoke status stableSha") if stable_sha is not None else prior_stable_sha
    if resolved_stable_sha is None:
        fail("completed smoke status has no Stable source SHA")
    signed_outcome = append_smoke_outcome(
        root,
        registration,
        beta_release_id=beta_release_id,
        stable_release_id=current_stable,
        beta_sha=beta_sha,
        stable_sha=resolved_stable_sha,
        smoke_run_url=smoke_run_url,
        marketplace_revision=marketplace_revision,
    )
    signed_source = require_object(signed_outcome.get("source"), "completed smoke signed outcome source")
    signed_smoke = require_object(signed_outcome.get("smoke"), "completed smoke signed outcome")
    signed_beta_sha = safe_sha(signed_source.get("betaSha"), "completed smoke signed outcome Beta source SHA")
    signed_stable_sha = safe_sha(signed_source.get("stableSha"), "completed smoke signed outcome Stable source SHA")
    signed_smoke_run_url = optional_url(signed_smoke.get("runUrl"), "completed smoke signed outcome run URL")
    signed_marketplace_revision = optional_sha(
        signed_smoke.get("marketplaceRevision"),
        "completed smoke signed outcome Marketplace revision",
    )
    if signed_smoke_run_url is None or signed_marketplace_revision is None:
        fail("completed smoke signed outcome is incomplete")
    return record_status(
        root,
        registration.plugin_id,
        beta_sha=signed_beta_sha,
        stable_sha=signed_stable_sha,
        main_gate_sha=prior_main_gate_sha,
        state="published",
        delivery_id=delivery_id,
        factory_run_url=factory_run_url,
        smoke_run_url=signed_smoke_run_url,
        marketplace_revision=signed_marketplace_revision,
    )


def validate_status(
    root: Path,
    registration: Registration,
    *,
    require_publication_proofs: bool = True,
    require_active_release_sidecar: bool = True,
) -> None:
    path = status_path(root, registration.plugin_id)
    if not path.exists():
        return
    status = read_json(path, f"official Factory status for {registration.plugin_id}")
    require_exact_keys(status, {"schemaVersion", "pluginId", "trustTier", "source", "release", "publication"}, "official Factory status")
    if status.get("schemaVersion") != 1 or status.get("pluginId") != registration.plugin_id or status.get("trustTier") != registration.trust_tier:
        fail("official Factory status has an invalid identity")
    source = require_object(status.get("source"), "official Factory status source")
    require_exact_keys(
        source,
        {"repository", "path", "refs", "betaSha", "stableSha", "mainGateSha"},
        "official Factory status source",
    )
    refs = require_object(source.get("refs"), "official Factory status source.refs")
    require_exact_keys(refs, {"beta", "stable"}, "official Factory status source.refs")
    if source.get("repository") != registration.repository or source.get("path") != registration.source_path.as_posix() or refs.get("beta") != registration.beta_ref or refs.get("stable") != registration.stable_ref:
        fail("official Factory status source does not match the official registry")
    beta_sha = optional_sha(source.get("betaSha"), "official Factory status betaSha")
    stable_sha = optional_sha(source.get("stableSha"), "official Factory status stableSha")
    main_gate_sha = optional_sha(source.get("mainGateSha"), "official Factory status mainGateSha")
    release = require_object(status.get("release"), "official Factory status release")
    require_exact_keys(release, {"betaReleaseId", "stableReleaseId"}, "official Factory status release")
    beta_id = release.get("betaReleaseId")
    stable_id = release.get("stableReleaseId")
    if beta_id is not None and (not isinstance(beta_id, str) or not RELEASE_ID_PATTERN.fullmatch(beta_id)):
        fail("official Factory status beta release ID is invalid")
    if stable_id is not None and (not isinstance(stable_id, str) or not RELEASE_ID_PATTERN.fullmatch(stable_id)):
        fail("official Factory status stable release ID is invalid")
    release_file = release_path(root, registration.plugin_id)
    if release_file.exists():
        try:
            releases = load_release_document(release_file, registration.plugin_id)
        except ValueError as error:
            raise ExternalSourceFactoryError(str(error)) from error
        actual_beta, actual_stable = release_channels(releases)
        if beta_id != actual_beta or stable_id != actual_stable:
            fail("official Factory status release pointers do not match immutable release metadata")
    elif beta_id is not None or stable_id is not None:
        fail("official Factory status claims a release without immutable release metadata")
    publication = require_object(status.get("publication"), "official Factory status publication")
    require_exact_keys(publication, {"state", "deliveryId", "factoryRunUrl", "smokeRunUrl", "marketplaceRevision"}, "official Factory status publication")
    if publication.get("state") not in PUBLICATION_STATES:
        fail("official Factory status publication state is invalid")
    state = publication["state"]
    require_text(publication.get("deliveryId"), "official Factory status deliveryId", maximum=160)
    optional_url(publication.get("factoryRunUrl"), "official Factory status factoryRunUrl")
    smoke_run_url = optional_url(publication.get("smokeRunUrl"), "official Factory status smokeRunUrl")
    marketplace_revision = optional_sha(publication.get("marketplaceRevision"), "official Factory status marketplaceRevision")
    # In-flight status is consumer-visible release state, not a free-form
    # progress label.  A status can be introduced after adoption without a
    # prior baseline file, so bind every waiting/promoting tuple directly to
    # KMS-signed Beta provenance instead of relying on a later diff check.
    if state in {"waiting_for_beta", "waiting_for_smoke", "promoting_stable"}:
        if beta_id is None or beta_sha is None:
            fail("in-flight Factory status must retain a Beta release ID and source SHA")
        if not release_file.exists():
            fail("in-flight Factory status must match immutable Beta provenance")
        if registration.trust_tier == "first-party":
            validate_adoption(
                root,
                registration,
                require_kms_proof=require_publication_proofs,
                require_active_release_sidecar=require_active_release_sidecar,
            )
            adopted_ids = frozenset(adopted_release_ids(root, registration, state_label="in-flight Factory status"))
        else:
            adopted_ids = frozenset()
        evidence_path = publication_path(root, registration.plugin_id)
        if is_link(evidence_path) or not evidence_path.is_file():
            fail("in-flight Factory status must match immutable Beta provenance")
        evidence = validate_evidence(root, registration, releases, adopted_release_ids=adopted_ids)
        if require_publication_proofs:
            validate_publication_proof(root, registration)
        events = evidence.get("events")
        if not isinstance(events, list) or not evidence_event_matches(
            events,
            channel="beta",
            release_id_value=beta_id,
            source_sha=beta_sha,
        ):
            fail("in-flight Factory status must match immutable Beta provenance")
        # A waiting status only says that a specific Beta has been accepted by
        # Factory.  It must not make the consumer-visible sidecar look as if
        # Stable or Desktop smoke evidence already exists.  Conversely, the
        # controlled manual-recovery state is allowed to describe Stable, but
        # only after its exact immutable Stable provenance was appended.
        if state in {"waiting_for_beta", "waiting_for_smoke"}:
            if stable_sha is not None or smoke_run_url is not None or marketplace_revision is not None:
                fail("waiting Factory status must not claim Stable or smoke evidence")
        elif state == "promoting_stable":
            if stable_id is None or stable_sha is None:
                fail("promoting Factory status must retain a Stable release ID and source SHA")
            if stable_id != beta_id:
                fail("promoting Factory status must promote the current Beta release")
            if smoke_run_url is not None or marketplace_revision is not None:
                fail("promoting Factory status must not claim Desktop smoke evidence")
            if not evidence_event_matches(
                events,
                channel="stable",
                release_id_value=stable_id,
                source_sha=stable_sha,
            ):
                fail("promoting Factory status must match immutable Stable provenance")
    # ``published`` is a terminal smoke result, never a cosmetic synonym for
    # a signed Beta. Validate all of the data written exclusively by the
    # smoke-gated Stable path before accepting the status sidecar; immutable
    # release provenance alone cannot establish that Desktop smoke completed.
    if state == "published":
        if beta_id is None or stable_id != beta_id:
            fail("published Factory status must bind the smoke-verified Beta to the Stable pointer")
        if beta_sha is None or stable_sha is None:
            fail("published Factory status must retain both Beta and Stable source SHAs")
        if marketplace_revision is None or smoke_run_url is None:
            fail("published Factory status must retain Desktop smoke evidence and Marketplace revision")
        if not smoke_run_url.startswith("https://github.com/tzf1003/xSecDesktop/actions/runs/"):
            fail("published Factory status smoke evidence must name the approved Desktop smoke workflow")
        # The readable status file is not itself a trust root. Bind every
        # terminal field to the KMS-signed publication evidence produced only
        # after reconcile-smoke accepted a retained Factory revision. The
        # adoption proof still validates a first-party's legacy prefix, but
        # it cannot on its own attest a later Desktop smoke run.
        adopted_ids = frozenset()
        if registration.trust_tier == "first-party":
            validate_adoption(root, registration, require_active_release_sidecar=require_active_release_sidecar)
            adopted_ids = frozenset(adopted_release_ids(root, registration, state_label="published Factory status"))
        evidence = validate_evidence(root, registration, releases, adopted_release_ids=adopted_ids)
        if require_publication_proofs:
            validate_publication_proof(root, registration)
        require_published_smoke_outcome(
            evidence,
            registration,
            beta_release_id=beta_id,
            stable_release_id=stable_id,
            beta_sha=beta_sha,
            stable_sha=stable_sha,
            smoke_run_url=smoke_run_url,
            marketplace_revision=marketplace_revision,
        )


def validate_evidence(
    root: Path,
    registration: Registration,
    document: dict[str, object],
    *,
    adopted_release_ids: frozenset[str] = frozenset(),
) -> dict[str, object]:
    path = publication_path(root, registration.plugin_id)
    if not path.exists():
        fail(f"external official plugin {registration.plugin_id} has no publication evidence")
    evidence = read_json(path, f"official external publication evidence for {registration.plugin_id}")
    if set(evidence) not in ({"schemaVersion", "pluginId", "events"}, {"schemaVersion", "pluginId", "events", "smokeOutcomes"}):
        fail(f"official external publication evidence for {registration.plugin_id} has invalid keys")
    if evidence.get("schemaVersion") != 1 or evidence.get("pluginId") != registration.plugin_id:
        fail("official external publication evidence has invalid identity")
    events = evidence.get("events")
    releases = document.get("releases")
    channels = document.get("channels")
    if not isinstance(events, list) or not isinstance(releases, list) or not isinstance(channels, dict):
        fail("official external publication evidence or release metadata is invalid")
    records = {item.get("releaseId"): item for item in releases if isinstance(item, dict) and isinstance(item.get("releaseId"), str)}
    beta_seen: set[str] = set()
    stable_seen: set[str] = set()
    event_keys: set[tuple[str, str, str]] = set()
    for index, raw_event in enumerate(events):
        label = f"official external publication evidence event {index}"
        event = require_object(raw_event, label)
        require_exact_keys(event, {"channel", "releaseId", "source", "artifact", "publisher"}, label)
        channel = event.get("channel")
        identifier = event.get("releaseId")
        if channel not in {"beta", "stable"} or not isinstance(identifier, str) or identifier not in records:
            fail(f"{label} references an invalid release or channel")
        source = require_object(event.get("source"), f"{label}.source")
        require_exact_keys(source, {"repository", "path", "ref", "sha"}, f"{label}.source")
        if (
            source.get("repository") != registration.repository
            or source.get("path") != registration.source_path.as_posix()
            or source.get("ref") != registration.ref_for(str(channel))
        ):
            fail(f"{label} source does not match the official registry")
        source_sha = safe_sha(source.get("sha"), f"{label}.source.sha")
        artifact = require_object(event.get("artifact"), f"{label}.artifact")
        require_exact_keys(artifact, {"sha256", "url"}, f"{label}.artifact")
        record_artifacts = records[identifier].get("artifacts")
        if not isinstance(record_artifacts, list) or not any(
            isinstance(item, dict) and item.get("sha256") == artifact.get("sha256") and item.get("url") == artifact.get("url")
            for item in record_artifacts
        ):
            fail(f"{label} artifact does not match its immutable release record")
        require_text(event.get("publisher"), f"{label}.publisher", maximum=128)
        key = (str(channel), identifier, source_sha)
        if key in event_keys:
            fail(f"{label} duplicates publication evidence")
        event_keys.add(key)
        (beta_seen if channel == "beta" else stable_seen).add(identifier)
    if set(records).difference(beta_seen).difference(adopted_release_ids):
        fail(f"external official plugin {registration.plugin_id} lacks Beta provenance")
    stable = channels.get("stable")
    stable_id = stable.get("releaseId") if isinstance(stable, dict) else None
    if isinstance(stable_id, str) and stable_id not in stable_seen and stable_id not in adopted_release_ids:
        fail(f"external official plugin {registration.plugin_id} lacks Stable provenance")
    validate_smoke_outcomes(evidence, registration, records)
    return evidence


def validate_smoke_outcomes(
    evidence: dict[str, object],
    registration: Registration,
    records: dict[object, dict[str, object]],
) -> None:
    """Validate immutable smoke outcomes embedded in KMS-signed provenance."""

    raw_outcomes = evidence.get("smokeOutcomes", [])
    if not isinstance(raw_outcomes, list):
        fail(f"external official plugin {registration.plugin_id} smoke outcomes are invalid")
    events = evidence.get("events")
    if not isinstance(events, list):
        fail(f"external official plugin {registration.plugin_id} evidence events are invalid")
    identities: set[tuple[str, str, str, str]] = set()
    for index, raw_outcome in enumerate(raw_outcomes):
        label = f"official external publication smoke outcome {index}"
        outcome = require_object(raw_outcome, label)
        require_exact_keys(outcome, {"betaReleaseId", "stableReleaseId", "source", "smoke"}, label)
        beta_release_id = outcome.get("betaReleaseId")
        stable_release_id = outcome.get("stableReleaseId")
        if (
            not isinstance(beta_release_id, str)
            or not RELEASE_ID_PATTERN.fullmatch(beta_release_id)
            or not isinstance(stable_release_id, str)
            or not RELEASE_ID_PATTERN.fullmatch(stable_release_id)
            or beta_release_id not in records
            or stable_release_id not in records
        ):
            fail(f"{label} has invalid release pointers")
        source = require_object(outcome.get("source"), f"{label}.source")
        require_exact_keys(source, {"betaSha", "stableSha"}, f"{label}.source")
        beta_sha = safe_sha(source.get("betaSha"), f"{label}.source.betaSha")
        stable_sha = safe_sha(source.get("stableSha"), f"{label}.source.stableSha")
        smoke = require_object(outcome.get("smoke"), f"{label}.smoke")
        require_exact_keys(smoke, {"runUrl", "marketplaceRevision"}, f"{label}.smoke")
        run_url = optional_url(smoke.get("runUrl"), f"{label}.smoke.runUrl")
        revision = optional_sha(smoke.get("marketplaceRevision"), f"{label}.smoke.marketplaceRevision")
        if run_url is None or revision is None or not run_url.startswith("https://github.com/tzf1003/xSecDesktop/actions/runs/"):
            fail(f"{label} does not contain approved Desktop smoke evidence")
        if not evidence_event_matches(events, channel="beta", release_id_value=beta_release_id, source_sha=beta_sha):
            fail(f"{label} Beta source is not bound to immutable publication evidence")
        if not evidence_event_matches(events, channel="stable", release_id_value=stable_release_id, source_sha=stable_sha):
            fail(f"{label} Stable source is not bound to immutable publication evidence")
        identity = (beta_release_id, stable_release_id, beta_sha, stable_sha)
        if identity in identities:
            fail(f"{label} duplicates an immutable smoke outcome")
        identities.add(identity)


def require_published_smoke_outcome(
    evidence: dict[str, object],
    registration: Registration,
    *,
    beta_release_id: str,
    stable_release_id: str,
    beta_sha: str,
    stable_sha: str,
    smoke_run_url: str,
    marketplace_revision: str,
) -> None:
    """Require a terminal status to be exactly represented in signed evidence."""

    outcomes = evidence.get("smokeOutcomes", [])
    if not isinstance(outcomes, list):
        fail(f"published Factory status for {registration.plugin_id} has invalid smoke evidence")
    for raw_outcome in outcomes:
        if not isinstance(raw_outcome, dict):
            continue
        source = raw_outcome.get("source")
        smoke = raw_outcome.get("smoke")
        if (
            raw_outcome.get("betaReleaseId") == beta_release_id
            and raw_outcome.get("stableReleaseId") == stable_release_id
            and isinstance(source, dict)
            and source.get("betaSha") == beta_sha
            and source.get("stableSha") == stable_sha
            and isinstance(smoke, dict)
            and smoke.get("runUrl") == smoke_run_url
            and smoke.get("marketplaceRevision") == marketplace_revision
        ):
            return
    fail(f"published Factory status for {registration.plugin_id} does not match KMS-bound smoke evidence")


def validate_publication_proof(root: Path, registration: Registration) -> None:
    """Require a KMS signature over the exact external provenance document.

    The release sidecar only binds ``releases.json``.  It cannot prove which
    external source SHA or publisher produced an evidence event, so a normal
    pull request could otherwise append fabricated provenance while retaining
    a valid release sidecar.  This additional fixed-purpose KMS document binds
    the whole append-only evidence history to the protected publish workflow.
    """

    try:
        document = official_publication_provenance_document(root, registration.plugin_id)
        sidecar = sidecar_path_for(document)
    except MarketplaceKmsPublisherError as error:
        raise ExternalSourceFactoryError(
            f"external official plugin {registration.plugin_id} KMS provenance proof is unavailable"
        ) from error
    if is_link(sidecar) or not sidecar.is_file():
        fail(f"external official plugin {registration.plugin_id} KMS provenance proof is unavailable")
    try:
        verify_historical_sidecar_signature(sidecar.read_bytes(), document)
    except (OSError, MarketplaceKmsPublisherError) as error:
        raise ExternalSourceFactoryError(
            f"external official plugin {registration.plugin_id} KMS provenance proof is invalid"
        ) from error


def validate_disabled_release_sidecar(
    root: Path,
    registration: Registration,
    *,
    require_release_sidecar: bool = True,
) -> None:
    """Require the signed immutable release document retained by a withdrawal."""

    release = release_path(root, registration.plugin_id)
    sidecar = release.with_name(release.name + ".sig.jws.json")
    if is_link(sidecar):
        fail(f"disabled external official plugin {registration.plugin_id} KMS release sidecar is unavailable")
    if not sidecar.is_file():
        if require_release_sidecar:
            fail(f"disabled external official plugin {registration.plugin_id} KMS release sidecar is unavailable")
        return
    subject = f".xsec-factory/snapshots/{registration.plugin_id}/.xsec-market/releases.json"
    document = MarketplaceDocument("xsec.plugin-marketplace.release", subject, release)
    try:
        verify_historical_sidecar_signature(sidecar.read_bytes(), document)
    except (OSError, MarketplaceKmsPublisherError) as error:
        raise ExternalSourceFactoryError(
            f"disabled external official plugin {registration.plugin_id} KMS release sidecar is invalid"
        ) from error


def beta_snapshot_artifact_digest(registration: Registration, beta: dict[str, object]) -> str:
    """Return the one portable artifact digest that binds a retained snapshot.

    The external bridge deliberately publishes exactly one portable package per
    release.  Keeping that rule here makes the retained-source comparison
    unambiguous and prevents a withdrawal from relaxing the active Factory
    publication contract.
    """

    artifacts = beta.get("artifacts")
    if (
        not isinstance(artifacts, list)
        or len(artifacts) != 1
        or not isinstance(artifacts[0], dict)
        or artifacts[0].get("os") != "any"
        or artifacts[0].get("arch") != "any"
    ):
        fail(f"external official plugin {registration.plugin_id} has an invalid Beta artifact")
    digest = artifacts[0].get("sha256")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        fail(f"external official plugin {registration.plugin_id} has an invalid Beta artifact digest")
    return digest


def validate_disabled_snapshot_artifacts(
    root: Path,
    registration: Registration,
    snapshot: Path,
    document: dict[str, object],
    beta: dict[str, object],
) -> None:
    """Keep a withdrawn snapshot and every archived release byte-addressable.

    A disabled package is intentionally absent from the generated marketplace,
    so the ordinary marketplace source gate no longer walks it.  Validate the
    retained source against its selected Beta record here, then independently
    validate each immutable artifact path and digest retained in its complete
    release history.  This prevents withdrawal from becoming an unpublication
    or a way to erase an append-only release record before a later re-enable.
    """

    require_link_free_tree(snapshot, f"disabled external official plugin {registration.plugin_id} snapshot")
    expected_beta_digest = beta_snapshot_artifact_digest(registration, beta)
    with tempfile.TemporaryDirectory(prefix="xsec-disabled-external-snapshot-") as directory:
        candidate = Path(directory) / "candidate.xsec-plugin"
        try:
            write_zip(snapshot, candidate)
        except ValueError as error:
            raise ExternalSourceFactoryError(str(error)) from error
        if sha256(candidate) != expected_beta_digest:
            fail(
                f"disabled external official plugin {registration.plugin_id} snapshot does not reproduce "
                "its immutable Beta artifact"
            )

    releases = document.get("releases")
    if not isinstance(releases, list) or not releases:
        fail(f"disabled external official plugin {registration.plugin_id} has no immutable release history")
    release_root = release_path(root, registration.plugin_id).parent
    for record_index, record in enumerate(releases):
        if not isinstance(record, dict):
            fail(f"disabled external official plugin {registration.plugin_id} has an invalid immutable release")
        artifacts = record.get("artifacts")
        if not isinstance(artifacts, list) or not artifacts:
            fail(f"disabled external official plugin {registration.plugin_id} has an invalid immutable artifact list")
        for artifact_index, artifact in enumerate(artifacts):
            if not isinstance(artifact, dict):
                fail(f"disabled external official plugin {registration.plugin_id} has an invalid immutable artifact")
            label = (
                f"disabled external official plugin {registration.plugin_id} release {record_index} "
                f"artifact {artifact_index}"
            )
            relative = safe_source_path(artifact.get("url"), f"{label} path")
            candidate = release_root.joinpath(*relative.parts)
            current = release_root
            for part in relative.parts:
                current = current / part
                if is_link(current):
                    fail(f"{label} must not traverse symbolic links")
            if not candidate.is_file():
                fail(f"{label} is unavailable")
            artifact_path = require_below(release_root, candidate, label)
            expected_digest = artifact.get("sha256")
            if not isinstance(expected_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_digest):
                fail(f"{label} has an invalid SHA-256 digest")
            if sha256(artifact_path) != expected_digest:
                fail(f"{label} SHA-256 does not match its immutable release record")


def published_release_history(
    root: Path,
    registrations: tuple[Registration, ...],
    *,
    state_label: str,
) -> dict[str, tuple[str, ...]]:
    """Return ordered immutable release IDs from a trusted Factory state."""

    histories: dict[str, tuple[str, ...]] = {}
    for registration in registrations:
        path = release_path(root, registration.plugin_id)
        if is_link(path):
            fail(f"{state_label} release metadata for {registration.plugin_id} must not use symbolic links")
        if not path.is_file():
            continue
        try:
            document = load_release_document(path, registration.plugin_id)
        except ValueError as error:
            raise ExternalSourceFactoryError(
                f"{state_label} release metadata for {registration.plugin_id} is invalid"
            ) from error
        releases = document.get("releases")
        if not isinstance(releases, list):
            fail(f"{state_label} release metadata for {registration.plugin_id} has an invalid release list")
        identifiers = tuple(
            record.get("releaseId")
            for record in releases
            if isinstance(record, dict) and isinstance(record.get("releaseId"), str)
        )
        if len(set(identifiers)) != len(identifiers):
            fail(f"{state_label} release metadata for {registration.plugin_id} duplicates an immutable release")
        if identifiers:
            histories[registration.plugin_id] = identifiers
    return histories


def publication_evidence_history(root: Path, registration: Registration, *, state_label: str) -> tuple[str, ...]:
    """Return canonical immutable evidence events for one published plugin.

    Publication evidence binds a release to the source commit and publisher,
    neither of which is represented by the release ID. Preserve whole ordered
    events rather than just the evidence file so an attacker cannot rewrite an
    old source SHA/publisher or reorder prior evidence while retaining a
    syntactically valid document.
    """

    path = publication_path(root, registration.plugin_id)
    if is_link(path) or not path.is_file():
        fail(f"{state_label} publication evidence for {registration.plugin_id} is unavailable")
    evidence = read_json(path, f"{state_label} publication evidence for {registration.plugin_id}")
    if set(evidence) not in ({"schemaVersion", "pluginId", "events"}, {"schemaVersion", "pluginId", "events", "smokeOutcomes"}):
        fail(f"{state_label} publication evidence for {registration.plugin_id} has invalid keys")
    if evidence.get("schemaVersion") != 1 or evidence.get("pluginId") != registration.plugin_id:
        fail(f"{state_label} publication evidence for {registration.plugin_id} has an invalid identity")
    events = evidence.get("events")
    if not isinstance(events, list):
        fail(f"{state_label} publication evidence for {registration.plugin_id} has an invalid event list")
    canonical_events = tuple(
        json.dumps(
            require_object(event, f"{state_label} publication evidence event {index}"),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        for index, event in enumerate(events)
    )
    if len(set(canonical_events)) != len(canonical_events):
        fail(f"{state_label} publication evidence for {registration.plugin_id} duplicates an immutable event")
    return canonical_events


def publication_smoke_outcome_history(root: Path, registration: Registration, *, state_label: str) -> tuple[str, ...]:
    """Return separately append-only terminal smoke evidence.

    Publication events and smoke outcomes are stored in distinct ordered arrays:
    a later Beta event may be appended after an earlier smoke outcome. Compare
    their histories independently, otherwise a valid new event would appear to
    insert before an older outcome in a synthetic flattened list.
    """

    path = publication_path(root, registration.plugin_id)
    if is_link(path) or not path.is_file():
        fail(f"{state_label} publication evidence for {registration.plugin_id} is unavailable")
    evidence = read_json(path, f"{state_label} publication evidence for {registration.plugin_id}")
    if set(evidence) not in ({"schemaVersion", "pluginId", "events"}, {"schemaVersion", "pluginId", "events", "smokeOutcomes"}):
        fail(f"{state_label} publication evidence for {registration.plugin_id} has invalid keys")
    outcomes = evidence.get("smokeOutcomes", [])
    if not isinstance(outcomes, list):
        fail(f"{state_label} publication evidence for {registration.plugin_id} has an invalid smoke outcome list")
    canonical_outcomes = tuple(
        json.dumps(
            require_object(outcome, f"{state_label} publication smoke outcome {index}"),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        for index, outcome in enumerate(outcomes)
    )
    if len(set(canonical_outcomes)) != len(canonical_outcomes):
        fail(f"{state_label} publication evidence for {registration.plugin_id} duplicates an immutable smoke outcome")
    return canonical_outcomes


def ownership_history(root: Path, registration: Registration, *, state_label: str) -> tuple[str, ...]:
    """Return immutable source-ownership assertions for baseline continuity."""

    if registration.trust_tier == "external":
        return publication_evidence_history(root, registration, state_label=state_label)
    path = adoption_path(root, registration.plugin_id)
    if is_link(path) or not path.is_file():
        fail(f"{state_label} first-party adoption proof for {registration.plugin_id} is unavailable")
    proof = read_json(path, f"{state_label} first-party adoption proof for {registration.plugin_id}")
    ownership = (json.dumps(proof, ensure_ascii=False, sort_keys=True, separators=(",", ":")),)
    # Adoption authenticates only the retained legacy prefix. Once a split
    # source records post-adoption provenance (including a new source SHA that
    # reproduces an adopted artifact), append-only evidence is equally
    # immutable and must survive every trusted-baseline comparison.
    if first_party_has_post_adoption_history(root, registration, state_label=state_label):
        return ownership + publication_evidence_history(root, registration, state_label=state_label)
    return ownership


def status_beta_identity(
    root: Path,
    registration: Registration,
    *,
    state_label: str,
) -> tuple[str, str | None, str | None] | None:
    """Read the status state plus its current Beta release/source identity.

    This deliberately parses only the fields needed by the protected-baseline
    continuity rule.  Full status/provenance validation still runs later in
    :func:`validate_registry_and_snapshots`; malformed data must not be
    mistaken for a legitimate transition away from a terminal result.
    """

    path = status_path(root, registration.plugin_id)
    if is_link(path):
        fail(f"{state_label} Factory status for {registration.plugin_id} must not use a symbolic link")
    if not path.exists():
        return None
    if not path.is_file():
        fail(f"{state_label} Factory status for {registration.plugin_id} must be a regular file")
    status = read_json(path, f"{state_label} Factory status for {registration.plugin_id}")
    source = require_object(status.get("source"), f"{state_label} Factory status source")
    release = require_object(status.get("release"), f"{state_label} Factory status release")
    publication = require_object(status.get("publication"), f"{state_label} Factory status publication")
    state = publication.get("state")
    if not isinstance(state, str) or state not in PUBLICATION_STATES:
        fail(f"{state_label} Factory status for {registration.plugin_id} has an invalid publication state")
    beta_release_id = release.get("betaReleaseId")
    if beta_release_id is not None and (
        not isinstance(beta_release_id, str) or not RELEASE_ID_PATTERN.fullmatch(beta_release_id)
    ):
        fail(f"{state_label} Factory status for {registration.plugin_id} has an invalid Beta release ID")
    beta_sha = optional_sha(source.get("betaSha"), f"{state_label} Factory status betaSha")
    return state, beta_release_id, beta_sha


def published_status_identity(
    root: Path,
    registration: Registration,
    *,
    state_label: str,
) -> tuple[str, tuple[str, str, str, str, str, str]] | None:
    """Return a canonical published sidecar and its smoke-bound identity.

    The status file is ordinary generated content, so it cannot replace the
    append-only KMS proof.  It nevertheless represents the *current* consumer
    outcome.  A protected baseline may retain it verbatim, or replace it only
    with a tuple represented by a smoke outcome appended after that baseline.
    Keeping the full canonical document here also prevents a normal PR from
    silently rewriting delivery or observability fields for the same outcome.
    """

    path = status_path(root, registration.plugin_id)
    if is_link(path):
        fail(f"{state_label} Factory status for {registration.plugin_id} must not use a symbolic link")
    if not path.exists():
        return None
    if not path.is_file():
        fail(f"{state_label} Factory status for {registration.plugin_id} must be a regular file")
    status = read_json(path, f"{state_label} Factory status for {registration.plugin_id}")
    source = require_object(status.get("source"), f"{state_label} Factory status source")
    release = require_object(status.get("release"), f"{state_label} Factory status release")
    publication = require_object(status.get("publication"), f"{state_label} Factory status publication")
    if publication.get("state") != "published":
        return None
    beta_release_id = release.get("betaReleaseId")
    stable_release_id = release.get("stableReleaseId")
    if (
        not isinstance(beta_release_id, str)
        or not RELEASE_ID_PATTERN.fullmatch(beta_release_id)
        or not isinstance(stable_release_id, str)
        or not RELEASE_ID_PATTERN.fullmatch(stable_release_id)
    ):
        fail(f"{state_label} published Factory status for {registration.plugin_id} has invalid release IDs")
    beta_sha = safe_sha(source.get("betaSha"), f"{state_label} published Factory status betaSha")
    stable_sha = safe_sha(source.get("stableSha"), f"{state_label} published Factory status stableSha")
    smoke_run_url = optional_url(publication.get("smokeRunUrl"), f"{state_label} published Factory status smokeRunUrl")
    marketplace_revision = optional_sha(
        publication.get("marketplaceRevision"),
        f"{state_label} published Factory status marketplaceRevision",
    )
    if smoke_run_url is None or marketplace_revision is None:
        fail(f"{state_label} published Factory status for {registration.plugin_id} has incomplete smoke evidence")
    document = json.dumps(status, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return document, (
        beta_release_id,
        stable_release_id,
        beta_sha,
        stable_sha,
        smoke_run_url,
        marketplace_revision,
    )


def latest_appended_smoke_outcome_matches(
    baseline_outcomes: tuple[str, ...],
    current_outcomes: tuple[str, ...],
    *,
    published_identity: tuple[str, str, str, str, str, str],
) -> bool:
    """Require the current terminal sidecar to name the newest appended result."""

    appended = current_outcomes[len(baseline_outcomes) :]
    if not appended:
        return False
    try:
        outcome = json.loads(appended[-1])
    except json.JSONDecodeError as error:
        raise ExternalSourceFactoryError("current Factory smoke outcome provenance is invalid") from error
    source = outcome.get("source") if isinstance(outcome, dict) else None
    smoke = outcome.get("smoke") if isinstance(outcome, dict) else None
    if not isinstance(source, dict) or not isinstance(smoke, dict):
        return False
    outcome_identity = (
        outcome.get("betaReleaseId"),
        outcome.get("stableReleaseId"),
        source.get("betaSha"),
        source.get("stableSha"),
        smoke.get("runUrl"),
        smoke.get("marketplaceRevision"),
    )
    return outcome_identity == published_identity


def appended_beta_provenance_matches(
    baseline_events: tuple[str, ...],
    current_events: tuple[str, ...],
    *,
    beta_release_id: str,
    beta_sha: str,
) -> bool:
    """Require a next-cycle status tuple to be newly recorded provenance.

    A readable ``waiting_for_smoke`` sidecar is not signed on its own.  When
    it replaces a trusted terminal status, permit it only if an immutable Beta
    event with the exact release/source tuple was appended after the trusted
    baseline.  The full validator later checks that event's registry/ref and
    artifact binding before the generated publication PR can merge.
    """

    for encoded_event in current_events[len(baseline_events) :]:
        try:
            event = json.loads(encoded_event)
        except json.JSONDecodeError as error:
            raise ExternalSourceFactoryError("current Factory publication provenance is invalid") from error
        source = event.get("source") if isinstance(event, dict) else None
        if (
            isinstance(event, dict)
            and event.get("channel") == "beta"
            and event.get("releaseId") == beta_release_id
            and isinstance(source, dict)
            and source.get("sha") == beta_sha
        ):
            return True
    return False


def needs_smoke_redispatch(
    root: Path,
    plugin_id: str,
    *,
    beta_sha: str,
    beta_release_id: str,
) -> dict[str, str]:
    """Report whether an already-signed Beta needs its lost smoke dispatch replayed.

    This is intentionally narrow: it never changes a channel, sidecar or
    status.  The protected workflow calls it only after finding no Factory
    diff for a duplicate Beta delivery.  Re-dispatching is safe only while
    that exact immutable release/source tuple is still the current
    waiting-for-smoke Beta.
    """

    registration = registration_for(root, plugin_id)
    expected_beta_sha = safe_sha(beta_sha, "smoke redispatch Beta source SHA")
    if not isinstance(beta_release_id, str) or not RELEASE_ID_PATTERN.fullmatch(beta_release_id):
        fail("smoke redispatch Beta release ID must be canonical")
    validate_status(root, registration)
    identity = status_beta_identity(root, registration, state_label="current Factory")
    if identity is None:
        return {"redispatch": "false"}
    state, recorded_beta_release_id, recorded_beta_sha = identity
    if (
        state != "waiting_for_smoke"
        or recorded_beta_release_id != beta_release_id
        or recorded_beta_sha != expected_beta_sha
    ):
        return {"redispatch": "false"}
    return {"redispatch": "true"}


def validate_trusted_baseline_continuity(
    root: Path,
    registrations: tuple[Registration, ...],
    baseline_root: Path | None,
) -> None:
    """Prevent a PR from erasing a released Factory package before reusing it.

    A registry/snapshot/evidence deletion has no remaining state in the new
    tree to distinguish it from a never-published authorization. CI supplies a
    separately materialized protected base revision, so a published plugin may
    be withdrawn only by retaining its registry entry with ``status=disabled``.
    The release IDs themselves are also append-only across that trusted state.
    """

    if baseline_root is None:
        return
    try:
        baseline = baseline_root.resolve(strict=True)
        current = root.resolve(strict=True)
    except OSError as error:
        raise ExternalSourceFactoryError("trusted Factory baseline is unavailable") from error
    if baseline == current or is_link(baseline) or not baseline.is_dir():
        fail("trusted Factory baseline must be a distinct regular directory")

    baseline_registry_directory = baseline / REGISTRY_RELATIVE_PATH.parent
    baseline_registry_path = baseline / REGISTRY_RELATIVE_PATH
    if is_link(baseline_registry_directory):
        fail("trusted Factory baseline registry directory must not be a symbolic link")
    if baseline_registry_directory.exists() and not baseline_registry_directory.is_dir():
        fail("trusted Factory baseline registry directory must be a regular directory")
    if is_link(baseline_registry_path):
        fail("trusted Factory baseline registry must not be a symbolic link")
    if not baseline_registry_path.exists():
        # The first Factory-enabled change may be compared with a protected
        # revision that predates the Factory itself. It has no publication
        # history to preserve, while a baseline that does contain a registry
        # remains subject to the strict append-only checks below.
        return

    baseline_registrations = load_registry(baseline, allow_legacy_v1=True)
    baseline_histories = published_release_history(
        baseline,
        baseline_registrations,
        state_label="trusted Factory baseline",
    )
    if not baseline_histories:
        return

    current_by_id = {registration.plugin_id: registration for registration in registrations}
    baseline_by_id = {registration.plugin_id: registration for registration in baseline_registrations}
    current_histories = published_release_history(root, registrations, state_label="current Factory")
    for plugin_id, baseline_ids in baseline_histories.items():
        registration = current_by_id.get(plugin_id)
        if registration is None:
            fail(
                f"published external official plugin {plugin_id} cannot be removed from the registry; "
                "retain it with status=disabled"
            )
        baseline_registration = baseline_by_id[plugin_id]
        if (
            registration.trust_tier != baseline_registration.trust_tier
            or registration.repository != baseline_registration.repository
            or registration.source_path != baseline_registration.source_path
            or registration.beta_ref != baseline_registration.beta_ref
            or registration.stable_ref != baseline_registration.stable_ref
        ):
            fail(
                f"published official Factory plugin {plugin_id} cannot change its registered source "
                "identity from the trusted baseline"
            )
        snapshot = snapshot_directory(root, plugin_id)
        if is_link(snapshot) or not snapshot.is_dir():
            fail(
                f"published official Factory plugin {plugin_id} must retain its immutable snapshot, "
                "release history, and source-ownership evidence recorded in the trusted baseline"
            )
        current_ids = current_histories.get(plugin_id, ())
        if current_ids[: len(baseline_ids)] != baseline_ids:
            fail(
                f"published external official plugin {plugin_id} must retain every immutable release "
                "recorded in the trusted baseline in append-only order"
            )
        # The protected materializer first adds an exact first-party Registry
        # v2 row as pending-adoption. Its retained Marketplace snapshot and
        # release history predate the adoption proof by design; the following
        # protected adoption PR supplies that KMS-bound proof. Do not demand a
        # proof that cannot exist in this precise baseline state, but keep all
        # identity and append-only release checks above and forbid unrelated
        # state transitions from using this exception.
        if baseline_registration.trust_tier == "first-party" and baseline_registration.status == "pending-adoption":
            if registration.status not in {"pending-adoption", "active"}:
                fail(
                    f"pending first-party official plugin {plugin_id} must remain pending or be activated "
                    "with an immutable adoption proof"
                )
            continue
        evidence = publication_path(root, plugin_id)
        ownership = adoption_path(root, plugin_id) if registration.trust_tier == "first-party" else evidence
        if is_link(ownership) or not ownership.is_file():
            fail(
                f"published official Factory plugin {plugin_id} must retain its immutable snapshot, "
                "release history, and source-ownership evidence recorded in the trusted baseline"
            )
        baseline_events = ownership_history(
            baseline,
            baseline_registration,
            state_label="trusted Factory baseline",
        )
        current_events = ownership_history(
            root,
            registration,
            state_label="current Factory",
        )
        if current_events[: len(baseline_events)] != baseline_events:
            if registration.trust_tier == "external":
                fail(
                    f"published external official plugin {plugin_id} must retain every immutable publication "
                    "evidence event recorded in the trusted baseline in append-only order"
                )
            if first_party_has_post_adoption_history(
                baseline,
                baseline_registration,
                state_label="trusted Factory baseline",
            ):
                fail(
                    f"published first-party official plugin {plugin_id} must retain every immutable publication "
                    "evidence event recorded in the trusted baseline in append-only order"
                )
            fail(
                f"published first-party official plugin {plugin_id} must retain its immutable adoption "
                "proof recorded in the trusted baseline"
            )
        # Terminal smoke outcomes are a second append-only evidence stream.
        # They cannot be flattened behind normal publication events because a
        # later Beta event is legitimately appended to ``events`` after an
        # earlier smoke result. Compare the two ordered arrays independently
        # so the first smoke completion (which adds the optional field) and
        # subsequent source releases both pass while deletion/rewrite fails.
        baseline_evidence = publication_path(baseline, plugin_id)
        baseline_outcomes: tuple[str, ...] = ()
        current_outcomes: tuple[str, ...] = ()
        if baseline_evidence.exists() or is_link(baseline_evidence):
            baseline_outcomes = publication_smoke_outcome_history(
                baseline,
                baseline_registration,
                state_label="trusted Factory baseline",
            )
            current_outcomes = publication_smoke_outcome_history(
                root,
                registration,
                state_label="current Factory",
            )
            if current_outcomes[: len(baseline_outcomes)] != baseline_outcomes:
                fail(
                    f"published official Factory plugin {plugin_id} must retain every immutable smoke outcome "
                    "recorded in the trusted baseline in append-only order"
                )
        # A complete smoke-gated result is also durable consumer state. Losing
        # it makes Desktop show an apparent unpublished plugin and prevents a
        # later callback from repairing the record (completion requires the
        # prior Beta status). A generated workflow may update observability
        # fields, but it must never delete or downgrade a published baseline.
        baseline_status = status_beta_identity(
            baseline,
            baseline_registration,
            state_label="trusted Factory baseline",
        )
        current_status = status_beta_identity(root, registration, state_label="current Factory")
        if baseline_status is not None and baseline_status[0] in {"waiting_for_beta", "waiting_for_smoke", "promoting_stable"}:
            # A smoke callback needs its preceding Factory status to bind the
            # Beta source/release identity. Do not let an ordinary PR delete
            # or replace that in-flight state with a cosmetic failure record.
            # A newer Beta is the sole nonterminal replacement: it must have
            # an appended exact provenance event, which supersedes the old
            # callback rather than stranding it.
            if current_status is None:
                fail(
                    f"in-flight official Factory plugin {plugin_id} must retain its smoke-gated Factory status "
                    "recorded in the trusted baseline"
                )
            if current_status[0] == "published":
                # Full status validation below requires the KMS-bound smoke
                # outcome, so a genuine terminal completion is allowed.
                continue
            if current_status == baseline_status:
                continue
            if (
                baseline_status[0] == "waiting_for_smoke"
                and current_status[0] == "promoting_stable"
                and current_status[1:] == baseline_status[1:]
            ):
                continue
            if (
                baseline_status[0] in {"waiting_for_beta", "waiting_for_smoke"}
                and current_status[0] in {"waiting_for_beta", "waiting_for_smoke"}
                and current_status[1:] == baseline_status[1:]
            ):
                # A registered main update may make the same accepted Beta
                # become reproducible (or cease to be reproducible) while a
                # smoke callback is in flight. Preserve its exact Beta
                # identity and allow only this nonterminal gate transition.
                continue
            if (
                current_status[0] in {"waiting_for_beta", "waiting_for_smoke"}
                and current_status[1] is not None
                and current_status[2] is not None
                and current_status[1:] != baseline_status[1:]
                and appended_beta_provenance_matches(
                    baseline_events,
                    current_events,
                    beta_release_id=current_status[1],
                    beta_sha=current_status[2],
                )
            ):
                continue
            fail(
                f"in-flight official Factory plugin {plugin_id} must retain its smoke-gated Factory status "
                "unless an exact new Beta smoke cycle is recorded by appended immutable provenance"
            )
        if baseline_status is not None and baseline_status[0] == "published":
            if current_status is not None and current_status[0] == "published":
                baseline_published = published_status_identity(
                    baseline,
                    baseline_registration,
                    state_label="trusted Factory baseline",
                )
                current_published = published_status_identity(
                    root,
                    registration,
                    state_label="current Factory",
                )
                if baseline_published is not None and current_published is not None:
                    if (
                        current_published[0] == baseline_published[0]
                        and current_outcomes == baseline_outcomes
                    ):
                        # The preserved current outcome is byte-for-byte the
                        # one users saw at the trusted baseline, including
                        # delivery observability fields.
                        continue
                    if latest_appended_smoke_outcome_matches(
                        baseline_outcomes,
                        current_outcomes,
                        published_identity=current_published[1],
                    ):
                        # A later smoke-gated Stable promotion legitimately
                        # replaces the one current Desktop status only when
                        # its exact terminal tuple was appended after the
                        # baseline.  Selecting an older valid outcome would
                        # otherwise be an unaudited rollback.
                        continue
            if (
                current_status is not None
                and current_status[0] in {"waiting_for_beta", "waiting_for_smoke"}
                and current_status[1] is not None
                and current_status[2] is not None
                and current_status[1:] != baseline_status[1:]
                and appended_beta_provenance_matches(
                    baseline_events,
                    current_events,
                    beta_release_id=current_status[1],
                    beta_sha=current_status[2],
                )
            ):
                # A distinct Beta release or source SHA begins a new smoke
                # cycle. Retaining the old terminal document verbatim would
                # incorrectly make future legitimate Beta publications fail
                # the protected source gate.
                continue
            fail(
                f"published official Factory plugin {plugin_id} must retain its terminal published status "
                "unless an exact new Beta smoke cycle is recorded by appended immutable provenance"
            )


def factory_git_lines(root: Path, arguments: list[str]) -> list[str]:
    environment = os.environ.copy()
    for name in tuple(environment):
        if name in {"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"} or name.startswith("GIT_CONFIG"):
            environment.pop(name, None)
    environment.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0"})
    try:
        result = subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", *arguments],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
    except (OSError, UnicodeDecodeError) as error:
        raise ExternalSourceFactoryError("Factory Git metadata is unavailable") from error
    if result.returncode:
        fail("Factory Git metadata is invalid")
    return [line for line in result.stdout.splitlines() if line]


def first_party_gitlinks(root: Path) -> dict[str, str]:
    revisions: dict[str, str] = {}
    for line in factory_git_lines(root, ["ls-files", "--stage"]):
        try:
            header, path = line.split("\t", 1)
            mode, revision, stage = header.split(" ")
        except ValueError as error:
            raise ExternalSourceFactoryError("Factory plugin Git index is invalid") from error
        if stage != "0":
            fail("Factory Git index has an unmerged entry")
        if mode == "160000":
            if not GIT_SHA_PATTERN.fullmatch(revision):
                fail("Factory Git subproject revision is invalid")
            if path in revisions:
                fail("Factory Git subprojects must not repeat")
            revisions[path] = revision
        elif path.startswith("plugins/"):
            fail("Factory plugins must be Git subprojects")
    return revisions


def first_party_submodule_settings(root: Path) -> dict[str, dict[str, str]]:
    manifest = root / ".gitmodules"
    if is_link(manifest) or not manifest.is_file():
        fail("Factory subproject manifest is unavailable")
    settings: dict[str, dict[str, str]] = {}
    for line in factory_git_lines(root, ["config", "--file", ".gitmodules", "--get-regexp", r"^submodule\..+"]):
        try:
            key, value = line.split(maxsplit=1)
            prefix, field = key.rsplit(".", 1)
            name = prefix.removeprefix("submodule.")
        except ValueError as error:
            raise ExternalSourceFactoryError("Factory subproject manifest is invalid") from error
        if field not in {"path", "url", "branch"}:
            fail("Factory subproject manifest has an unsupported field")
        item = settings.setdefault(name, {})
        if field in item:
            fail("Factory subproject manifest repeats a field")
        item[field] = value
    return settings


def validate_first_party_subprojects(
    root: Path,
    registrations: tuple[Registration, ...],
) -> None:
    expected = {item.plugin_id: item.repository for item in registrations if item.trust_tier == "first-party"}
    git_metadata = root / ".git"
    layouts = (root / SNAPSHOT_ROOT_RELATIVE_PATH, root / ".gitmodules")
    if not expected or not (git_metadata.exists() or is_link(git_metadata)) or not any(path.exists() or is_link(path) for path in layouts):
        return
    expected_paths = {f"plugins/{plugin_id}" for plugin_id in expected}
    revisions = first_party_gitlinks(root)
    if set(revisions) != expected_paths:
        fail("Factory Git subprojects do not match first-party plugins")
    settings = first_party_submodule_settings(root)
    if set(settings) != expected_paths:
        fail("Factory subproject manifest does not match first-party plugins")
    for plugin_id, repository in expected.items():
        path = f"plugins/{plugin_id}"
        if settings[path] != {"path": path, "url": f"https://github.com/{repository}.git", "branch": "beta"}:
            fail(f"Factory subproject source is invalid for {plugin_id}")


def validate_registry_and_snapshots(
    root: Path,
    *,
    baseline_root: Path | None = None,
    require_publication_proofs: bool = True,
    require_active_release_sidecars: bool = True,
) -> None:
    """Validate external records in addition to the existing generic market gate.

    Source-gate validation sets ``require_publication_proofs``.  The only
    exception is the protected publisher's short pre-KMS staging window: it
    validates structure with the explicit opt-out, obtains the new sidecars,
    and sends the generated branch through this strict gate before merge.
    """

    registrations = load_registry(root)
    validate_trusted_baseline_continuity(root, registrations, baseline_root)
    validate_first_party_subprojects(root, registrations)
    registered_ids = {registration.plugin_id for registration in registrations}
    index = read_json(root / MARKETPLACE_RELATIVE_PATH, "official marketplace index")
    entries = index.get("plugins")
    if not isinstance(entries, list):
        fail("official marketplace index plugins must be a list")
    entries_by_id: dict[str, dict[str, object]] = {}
    for value in entries:
        if not isinstance(value, dict) or not isinstance(value.get("name"), str):
            continue
        plugin_id = value["name"]
        if plugin_id in entries_by_id:
            fail(f"official marketplace index contains duplicate plugin {plugin_id}")
        entries_by_id[plugin_id] = value

    # An external Factory package is never allowed to become an ordinary local
    # official package merely because a PR deletes its registry/evidence files.
    # The only packages permitted outside the external registry are the
    # statically mirrored Desktop-owned package IDs. This intentionally makes
    # registry ownership sticky for every non-Desktop package that has reached
    # the official marketplace; use status=disabled to withdraw it instead of
    # deregistering a published snapshot.
    for plugin_id in entries_by_id:
        if plugin_id not in registered_ids and plugin_id not in RESERVED_DESKTOP_PLUGIN_IDS:
            fail(
                f"official marketplace plugin {plugin_id} is neither Desktop-owned nor registered "
                "as an external Factory package"
            )

    snapshot_root = root / SNAPSHOT_ROOT_RELATIVE_PATH
    if snapshot_root.exists():
        if is_link(snapshot_root) or not snapshot_root.is_dir():
            fail("official plugin snapshot directory must be a regular directory")
        for snapshot in snapshot_root.iterdir():
            if is_link(snapshot):
                fail(f"official plugin snapshot directory must not contain symbolic links: {snapshot.name}")
            if not snapshot.is_dir():
                continue
            if snapshot.name not in registered_ids and snapshot.name not in RESERVED_DESKTOP_PLUGIN_IDS:
                fail(
                    f"official plugin snapshot {snapshot.name} is neither Desktop-owned nor registered "
                    "as an external Factory package"
                )

    publication_root = root / PUBLICATIONS_RELATIVE_PATH
    if publication_root.exists():
        if is_link(publication_root) or not publication_root.is_dir():
            fail("official external publication directory must be a regular directory")
        allowed_files = {f"{item.plugin_id}.json" for item in registrations}
        for path in publication_root.iterdir():
            if is_link(path) or not path.is_file() or path.name not in allowed_files:
                fail(f"official external publication directory has an unregistered entry: {path.name}")
    publication_proof_root = root / PUBLICATION_PROOFS_RELATIVE_PATH
    if publication_proof_root.exists():
        if is_link(publication_proof_root) or not publication_proof_root.is_dir():
            fail("official external publication proof directory must be a regular directory")
        allowed_proofs = {f"{item.plugin_id}.json" for item in registrations}
        for path in publication_proof_root.iterdir():
            if is_link(path) or not path.is_file() or path.name not in allowed_proofs:
                fail(f"official external publication proof directory has an unregistered entry: {path.name}")
    adoption_root = root / ADOPTIONS_RELATIVE_PATH
    if adoption_root.exists():
        if is_link(adoption_root) or not adoption_root.is_dir():
            fail("official first-party adoption directory must be a regular directory")
        allowed_adoptions = {f"{item.plugin_id}.json" for item in registrations if item.trust_tier == "first-party"}
        for path in adoption_root.iterdir():
            if is_link(path) or not path.is_file() or path.name not in allowed_adoptions:
                fail(f"official first-party adoption directory has an unregistered entry: {path.name}")
    adoption_proof_root = root / ADOPTION_PROOFS_RELATIVE_PATH
    if adoption_proof_root.exists():
        if is_link(adoption_proof_root) or not adoption_proof_root.is_dir():
            fail("official first-party adoption proof directory must be a regular directory")
        allowed_proofs = {f"{item.plugin_id}.json" for item in registrations if item.trust_tier == "first-party"}
        for path in adoption_proof_root.iterdir():
            if is_link(path) or not path.is_file() or path.name not in allowed_proofs:
                fail(f"official first-party adoption proof directory has an unregistered entry: {path.name}")
    status_root = root / STATUSES_RELATIVE_PATH
    status_names: set[str] = set()
    if status_root.exists():
        if is_link(status_root) or not status_root.is_dir():
            fail("official Factory status directory must be a regular directory")
        allowed_statuses = {f"{item.plugin_id}.json" for item in registrations}
        for path in status_root.iterdir():
            if is_link(path) or not path.is_file() or path.name not in allowed_statuses:
                fail(f"official Factory status directory has an unregistered entry: {path.name}")
            status_names.add(path.name)
    status_proof_root = root / STATUS_PROOFS_RELATIVE_PATH
    if status_proof_root.exists():
        if is_link(status_proof_root) or not status_proof_root.is_dir():
            fail("official Factory status proof directory must be a regular directory")
        allowed_status_proofs = {f"{item.plugin_id}.json" for item in registrations}
        for path in status_proof_root.iterdir():
            if is_link(path) or not path.is_file() or path.name not in allowed_status_proofs:
                fail(f"official Factory status proof directory has an unregistered entry: {path.name}")
            if path.name not in status_names:
                fail(f"official Factory status proof has no matching status document: {path.name}")
    for registration in registrations:
        entry = entries_by_id.get(registration.plugin_id)
        snapshot = snapshot_directory(root, registration.plugin_id)
        evidence = publication_path(root, registration.plugin_id)
        proof = publication_proof_root / f"{registration.plugin_id}.json"
        if registration.status == "pending-adoption":
            if registration.trust_tier != "first-party":
                fail("only a first-party registration may be pending adoption")
            if entry != marketplace_entry(registration):
                fail(f"pending first-party plugin {registration.plugin_id} must retain its existing marketplace entry")
            if not snapshot.is_dir() or is_link(snapshot):
                fail(f"pending first-party plugin {registration.plugin_id} snapshot is unavailable")
            adoption = adoption_path(root, registration.plugin_id)
            adoption_sidecar = root / ADOPTION_PROOFS_RELATIVE_PATH / f"{registration.plugin_id}.json"
            has_adoption = adoption.exists() or is_link(adoption)
            has_adoption_sidecar = adoption_sidecar.exists() or is_link(adoption_sidecar)
            if has_adoption or has_adoption_sidecar:
                # A protected staging PR merges only this unsigned, semantic
                # record. Cloud reads those exact bytes from protected main
                # before KMS signs them. A pending Registry can never retain a
                # sidecar: the generated activation PR adds it atomically with
                # the status transition.
                if not has_adoption or is_link(adoption) or not adoption.is_file() or has_adoption_sidecar:
                    fail(f"pending first-party plugin {registration.plugin_id} must retain only one unsigned staged adoption proof")
                validate_adoption(
                    root,
                    registration,
                    require_kms_proof=False,
                    require_active_release_sidecar=require_active_release_sidecars,
                )
            manifest = source_manifest(snapshot, registration)
            try:
                document = load_release_document(release_path(root, registration.plugin_id), registration.plugin_id)
            except ValueError as error:
                raise ExternalSourceFactoryError(str(error)) from error
            _, beta = current_beta_record(root, registration.plugin_id)
            if manifest.get("version") != beta.get("version"):
                fail(f"pending first-party plugin {registration.plugin_id} snapshot does not match its Beta release")
            validate_disabled_snapshot_artifacts(root, registration, snapshot, document, beta)
            validate_disabled_release_sidecar(
                root,
                registration,
                require_release_sidecar=require_active_release_sidecars,
            )
            validate_status(
                root,
                registration,
                require_publication_proofs=require_publication_proofs,
                require_active_release_sidecar=require_active_release_sidecars,
            )
            continue
        if registration.status == "disabled":
            if entry is not None:
                fail(f"disabled official Factory plugin {registration.plugin_id} remains in marketplace index")
            # A disabled external package is a withdrawal from discovery, not
            # an unpublication. Keep the snapshot (including releases.json)
            # and its append-only source evidence so the same SemVer can never
            # be republished with different bytes after a later re-enable.
            # An un-published registration can simply be removed instead of
            # being recorded as disabled.
            if not snapshot.is_dir() or is_link(snapshot):
                fail(
                    f"disabled official Factory plugin {registration.plugin_id} must retain its immutable snapshot and release history"
                )
            if registration.trust_tier == "external" and (not evidence.is_file() or is_link(evidence)):
                fail(f"disabled external official plugin {registration.plugin_id} must retain publication evidence")
        elif entry is None:
            if snapshot.exists() or evidence.exists() or proof.exists() or is_link(proof):
                fail(f"active external official plugin {registration.plugin_id} has an incomplete publication")
            continue
        elif entry != marketplace_entry(registration):
            fail(f"official marketplace entry for {registration.plugin_id} does not match the external registry")
        if not snapshot.is_dir() or is_link(snapshot):
            fail(f"external official plugin {registration.plugin_id} snapshot is unavailable")
        manifest = source_manifest(snapshot, registration)
        try:
            document = load_release_document(release_path(root, registration.plugin_id), registration.plugin_id)
        except ValueError as error:
            raise ExternalSourceFactoryError(str(error)) from error
        _, beta = current_beta_record(root, registration.plugin_id)
        if manifest.get("version") != beta.get("version"):
            fail(f"external official plugin {registration.plugin_id} snapshot does not match its Beta release")
        try:
            snapshot_engines = require_release_engines(
                manifest["extensions"]["com.xsec.desktop"]["engines"],
                f"external official plugin {registration.plugin_id} snapshot manifest",
            )
        except (KeyError, TypeError, ValueError) as error:
            raise ExternalSourceFactoryError(
                f"external official plugin {registration.plugin_id} snapshot engines are invalid"
            ) from error
        if snapshot_engines != beta.get("engines"):
            fail(f"external official plugin {registration.plugin_id} snapshot engines do not match its Beta release")
        if registration.trust_tier == "external":
            validate_evidence(root, registration, document)
            if require_publication_proofs:
                validate_publication_proof(root, registration)
        else:
            # A first-party entry starts from a signed adoption, preserving
            # its historical release record/artifacts and existing pointers.
            # It is not allowed to self-authorise by adding a registry row.
            validate_adoption(
                root,
                registration,
                require_kms_proof=require_publication_proofs,
                require_active_release_sidecar=require_active_release_sidecars,
            )
            # Once a split source records provenance, retain the same
            # append-only source evidence/proof used by external packages in
            # addition to (never instead of) its migration adoption. This
            # includes a new source SHA that reproduces an adopted artifact.
            adopted_ids = adopted_release_ids(root, registration, state_label="current Factory")
            has_post_adoption_history = first_party_has_post_adoption_history(
                root,
                registration,
                state_label="current Factory",
            )
            if has_post_adoption_history and (is_link(evidence) or not evidence.is_file()):
                fail(
                    f"first-party plugin {registration.plugin_id} must retain publication evidence "
                    "after its adopted release history"
                )
            if evidence.exists() or is_link(evidence):
                validate_evidence(root, registration, document, adopted_release_ids=frozenset(adopted_ids))
                if require_publication_proofs:
                    validate_publication_proof(root, registration)
        if registration.status == "disabled" and registration.trust_tier == "external":
            validate_disabled_snapshot_artifacts(root, registration, snapshot, document, beta)
            validate_disabled_release_sidecar(root, registration)
        validate_status(
            root,
            registration,
            require_publication_proofs=require_publication_proofs,
            require_active_release_sidecar=require_active_release_sidecars,
        )


def write_outputs(values: dict[str, str], output_path: Path | None) -> None:
    if output_path is None:
        return
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("a", encoding="utf-8", newline="\n") as handle:
        for key, value in values.items():
            if not key.isidentifier() or "\n" in value or "\r" in value:
                fail("unsafe GitHub Actions output")
            handle.write(f"{key}={value}\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit the command result as one canonical JSON document",
    )
    parser.add_argument(
        "--github-output",
        type=Path,
        default=Path(os.environ["GITHUB_OUTPUT"]) if os.environ.get("GITHUB_OUTPUT") else None,
    )
    commands = parser.add_subparsers(dest="command", required=True)
    prepare_parser = commands.add_parser("prepare")
    prepare_parser.add_argument("--plugin-id", required=True)
    prepare_parser.add_argument("--channel", choices=("beta", "stable"), required=True)
    prepare_parser.add_argument("--source-sha", required=True)
    stage_parser = commands.add_parser("stage-beta")
    stage_parser.add_argument("--plugin-id", required=True)
    stage_parser.add_argument("--source-root", type=Path, required=True)
    beta_parser = commands.add_parser("record-beta")
    beta_parser.add_argument("--plugin-id", required=True)
    beta_parser.add_argument("--source-sha", required=True)
    beta_parser.add_argument("--publisher", required=True)
    verify_parser = commands.add_parser("verify-stable")
    verify_parser.add_argument("--plugin-id", required=True)
    verify_parser.add_argument("--source-root", type=Path, required=True)
    verify_parser.add_argument("--release-id", required=True)
    verify_parser.add_argument("--expected-beta-sha")
    main_rebuild_parser = commands.add_parser("check-main-rebuild")
    main_rebuild_parser.add_argument("--plugin-id", required=True)
    main_rebuild_parser.add_argument("--source-root", type=Path, required=True)
    stable_parser = commands.add_parser("record-stable")
    stable_parser.add_argument("--plugin-id", required=True)
    stable_parser.add_argument("--source-sha", required=True)
    stable_parser.add_argument("--release-id", required=True)
    stable_parser.add_argument("--publisher", required=True)
    adoption_parser = commands.add_parser("adopt-first-party")
    adoption_parser.add_argument("--plugin-id", required=True)
    adoption_parser.add_argument("--beta-sha", required=True)
    adoption_parser.add_argument("--stable-sha", required=True)
    adoption_parser.add_argument("--factory-revision", required=True)
    activate_parser = commands.add_parser("activate-first-party")
    activate_parser.add_argument("--plugin-id", required=True)
    status_parser = commands.add_parser("record-status")
    status_parser.add_argument("--plugin-id", required=True)
    status_parser.add_argument("--beta-sha")
    status_parser.add_argument("--stable-sha")
    status_parser.add_argument(
        "--main-gate-sha",
        help="exact registered main head used for a Beta deterministic-rebuild gate",
    )
    status_parser.add_argument("--state", required=True, choices=sorted(PUBLICATION_STATES))
    status_parser.add_argument("--delivery-id", required=True)
    status_parser.add_argument("--factory-run-url")
    status_parser.add_argument("--smoke-run-url")
    status_parser.add_argument("--marketplace-revision")
    complete_status_parser = commands.add_parser("complete-smoke-status")
    complete_status_parser.add_argument("--plugin-id", required=True)
    complete_status_parser.add_argument("--beta-release-id", required=True)
    complete_status_parser.add_argument("--stable-sha")
    complete_status_parser.add_argument("--delivery-id", required=True)
    complete_status_parser.add_argument("--smoke-run-url", required=True)
    complete_status_parser.add_argument("--marketplace-revision", required=True)
    redispatch_parser = commands.add_parser("needs-smoke-redispatch")
    redispatch_parser.add_argument("--plugin-id", required=True)
    redispatch_parser.add_argument("--beta-sha", required=True)
    redispatch_parser.add_argument("--beta-release-id", required=True)
    source_reconcile_parser = commands.add_parser("prepare-reconcile-source")
    source_reconcile_parser.add_argument("--delivery-key", required=True)
    source_reconcile_parser.add_argument("--plugin-id", required=True)
    source_reconcile_parser.add_argument("--source-repository", required=True)
    source_reconcile_parser.add_argument("--source-ref", required=True)
    source_reconcile_parser.add_argument("--source-sha", required=True)
    adoption_prepare_parser = commands.add_parser("prepare-adoption")
    adoption_prepare_parser.add_argument("--plugin-id", required=True)
    adoption_prepare_parser.add_argument("--beta-sha", required=True)
    adoption_prepare_parser.add_argument("--stable-sha", required=True)
    staged_adoption_parser = commands.add_parser("prepare-staged-adoption")
    staged_adoption_parser.add_argument("--plugin-id", required=True)
    staged_adoption_parser.add_argument(
        "--baseline-root",
        required=True,
        type=Path,
        help="trusted Factory checkout from immediately before the staged proof was added",
    )
    staged_adoption_parser.add_argument(
        "--factory-revision",
        required=True,
        help="exact trusted Factory baseline Git revision used to build the assertion",
    )
    smoke_reconcile_parser = commands.add_parser("prepare-reconcile-smoke")
    smoke_reconcile_parser.add_argument("--delivery-key", required=True)
    smoke_reconcile_parser.add_argument("--marketplace-revision", required=True)
    smoke_reconcile_parser.add_argument("--channel", required=True)
    smoke_reconcile_parser.add_argument("--smoke-workflow-run-id", required=True)
    smoke_reconcile_parser.add_argument("--smoke-workflow-run-attempt", required=True)
    legacy_parser = commands.add_parser(
        "reject-legacy-stable",
        help="reject an external plugin in the legacy built-in Stable workflow",
    )
    legacy_parser.add_argument("--plugin-id", required=True)
    validate_parser = commands.add_parser("validate")
    validate_parser.add_argument(
        "--baseline-root",
        type=Path,
        help="trusted pre-change Factory checkout used to prevent publication-history deletion",
    )
    validate_parser.add_argument(
        "--allow-unsigned-publication-proofs",
        action="store_true",
        help="only for the protected publisher's pre-KMS staging window",
    )
    validate_parser.add_argument(
        "--allow-unsigned-active-release-sidecars",
        action="store_true",
        help="only for the protected publisher's pre-KMS staging window after build_market --clean",
    )
    args = parser.parse_args()
    if (
        args.command == "validate"
        and args.allow_unsigned_active_release_sidecars
        and not args.allow_unsigned_publication_proofs
    ):
        parser.error("--allow-unsigned-active-release-sidecars requires --allow-unsigned-publication-proofs")
    root = args.root.resolve()
    try:
        if args.command == "prepare":
            result = prepare(root, args.plugin_id, args.channel, args.source_sha)
        elif args.command == "stage-beta":
            result = stage_beta(root, args.plugin_id, args.source_root)
        elif args.command == "record-beta":
            result = record_beta(root, args.plugin_id, args.source_sha, args.publisher)
        elif args.command == "verify-stable":
            result = verify_stable(
                root,
                args.plugin_id,
                args.source_root,
                args.release_id,
                expected_beta_sha=args.expected_beta_sha,
            )
        elif args.command == "check-main-rebuild":
            result = check_main_rebuild(root, args.plugin_id, args.source_root)
        elif args.command == "record-stable":
            result = record_stable(root, args.plugin_id, args.source_sha, args.release_id, args.publisher)
        elif args.command == "adopt-first-party":
            result = create_adoption(
                root,
                args.plugin_id,
                beta_sha=args.beta_sha,
                stable_sha=args.stable_sha,
                factory_revision=args.factory_revision,
            )
        elif args.command == "activate-first-party":
            result = activate_first_party(root, args.plugin_id)
        elif args.command == "record-status":
            result = record_status(
                root,
                args.plugin_id,
                beta_sha=args.beta_sha,
                stable_sha=args.stable_sha,
                main_gate_sha=args.main_gate_sha,
                state=args.state,
                delivery_id=args.delivery_id,
                factory_run_url=args.factory_run_url,
                smoke_run_url=args.smoke_run_url,
                marketplace_revision=args.marketplace_revision,
            )
        elif args.command == "complete-smoke-status":
            result = complete_smoke_status(
                root,
                args.plugin_id,
                beta_release_id=args.beta_release_id,
                stable_sha=args.stable_sha,
                delivery_id=args.delivery_id,
                smoke_run_url=args.smoke_run_url,
                marketplace_revision=args.marketplace_revision,
            )
        elif args.command == "needs-smoke-redispatch":
            result = needs_smoke_redispatch(
                root,
                args.plugin_id,
                beta_sha=args.beta_sha,
                beta_release_id=args.beta_release_id,
            )
        elif args.command == "prepare-reconcile-source":
            result = prepare_reconcile_source(
                root,
                delivery_key=args.delivery_key,
                plugin_id=args.plugin_id,
                source_repository=args.source_repository,
                source_ref=args.source_ref,
                source_sha=args.source_sha,
            )
        elif args.command == "prepare-adoption":
            result = prepare_adoption(root, args.plugin_id, args.beta_sha, args.stable_sha)
        elif args.command == "prepare-staged-adoption":
            result = prepare_staged_adoption(
                root,
                args.plugin_id,
                baseline_root=args.baseline_root,
                factory_revision=args.factory_revision,
            )
        elif args.command == "prepare-reconcile-smoke":
            result = prepare_reconcile_smoke(
                delivery_key=args.delivery_key,
                marketplace_revision=args.marketplace_revision,
                channel=args.channel,
                smoke_workflow_run_id=args.smoke_workflow_run_id,
                smoke_workflow_run_attempt=args.smoke_workflow_run_attempt,
            )
        elif args.command == "reject-legacy-stable":
            result = reject_legacy_stable_promotion(root, args.plugin_id)
        else:
            baseline_root = args.baseline_root.resolve() if args.baseline_root is not None else None
            validate_registry_and_snapshots(
                root,
                baseline_root=baseline_root,
                require_publication_proofs=not args.allow_unsigned_publication_proofs,
                require_active_release_sidecars=not args.allow_unsigned_active_release_sidecars,
            )
            result = {"valid": "true"}
        write_outputs(result, args.github_output)
    except ExternalSourceFactoryError as error:
        raise SystemExit(f"official external source Factory failed: {error}") from error
    if args.json:
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    else:
        print(" ".join(f"{key}={value}" for key, value in result.items()))


if __name__ == "__main__":
    main()
