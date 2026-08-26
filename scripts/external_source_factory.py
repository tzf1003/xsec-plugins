#!/usr/bin/env python3
"""Bridge approved external plugin repositories into the official KMS market.

This script is deliberately used only by the protected ``publish.yml``
workflow.  It never obtains GitHub credentials, runs source build scripts, or
signs anything.  The workflow supplies an exact, already-checked-out commit;
this bridge snapshots that package below ``plugins/<id>/`` so the existing
official builder, KMS publisher, release index, and Desktop marketplace reader
keep one compatible on-disk contract.

The snapshot is a published source/cache record, not the external repository's
development authority.  Its provenance is kept separately in
``.xsec-factory/official-publications/<id>.json``.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import tempfile

from build_market import (
    MARKETPLACE_RELATIVE_PATH,
    RELEASE_ID_PATTERN,
    ROOT,
    is_link,
    iter_plugin_files,
    load_release_document,
    release_id,
    require_release_engines,
    sha256,
    stable_json,
    write_zip,
)


REGISTRY_RELATIVE_PATH = Path(".xsec-factory") / "official-registry.json"
PUBLICATIONS_RELATIVE_PATH = Path(".xsec-factory") / "official-publications"
PLUGIN_ROOT_RELATIVE_PATH = Path("plugins")
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
    label = f"official external registry plugin at index {index}"
    entry = require_object(value, label)
    require_exact_keys(entry, {"pluginId", "source", "policy", "category", "status"}, label)
    plugin_id = safe_external_plugin_id(entry.get("pluginId"), f"{label}.pluginId")
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
    # The installed-by-default official set is compiled into Desktop. An
    # external registry edit must never silently extend that set.
    if policy.get("installation") != "AVAILABLE":
        fail(f"{label}.policy.installation must be AVAILABLE")
    if policy.get("authentication") != "ON_INSTALL":
        fail(f"{label}.policy.authentication must be ON_INSTALL")
    category = require_text(entry.get("category"), f"{label}.category", maximum=80)
    status = entry.get("status")
    if status not in {"active", "disabled"}:
        fail(f"{label}.status must be active or disabled")
    return Registration(
        plugin_id=plugin_id,
        repository=repository,
        source_path=source_path,
        beta_ref="refs/heads/beta",
        stable_ref="refs/heads/main",
        installation="AVAILABLE",
        authentication="ON_INSTALL",
        category=category,
        status=status,
    )


def load_registry(root: Path) -> tuple[Registration, ...]:
    path = root / REGISTRY_RELATIVE_PATH
    if is_link(path.parent):
        fail("official external registry directory must not be a symbolic link")
    document = read_json(path, "official external registry")
    require_exact_keys(document, {"schemaVersion", "plugins"}, "official external registry")
    if document.get("schemaVersion") != 1:
        fail("official external registry schemaVersion must be 1")
    raw_plugins = document.get("plugins")
    if not isinstance(raw_plugins, list):
        fail("official external registry plugins must be a list")
    registrations = tuple(parse_registration(item, index) for index, item in enumerate(raw_plugins))
    identifiers = [item.plugin_id for item in registrations]
    if len(identifiers) != len(set(identifiers)):
        fail("official external registry contains duplicate plugin IDs")
    return registrations


def registration_for(root: Path, plugin_id: str, *, active: bool = True) -> Registration:
    identifier = safe_plugin_id(plugin_id)
    for registration in load_registry(root):
        if registration.plugin_id == identifier:
            if active and registration.status != "active":
                fail(f"official external plugin {identifier} is disabled")
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
        "source_sha": sha,
        "source_repository": registration.repository,
        "source_owner": owner,
        "source_repo": repository,
        "source_path": registration.source_path.as_posix(),
        "source_ref": registration.ref_for(channel),
    }


def snapshot_directory(root: Path, plugin_id: str) -> Path:
    plugin_id = safe_plugin_id(plugin_id)
    destination = root / PLUGIN_ROOT_RELATIVE_PATH / plugin_id
    try:
        destination.resolve(strict=False).relative_to((root / PLUGIN_ROOT_RELATIVE_PATH).resolve(strict=False))
    except ValueError as error:
        raise ExternalSourceFactoryError("plugin snapshot path escaped plugins/") from error
    return destination


def release_path(root: Path, plugin_id: str) -> Path:
    return snapshot_directory(root, plugin_id) / ".xsec-market" / "releases.json"


def publication_path(root: Path, plugin_id: str) -> Path:
    return root / PUBLICATIONS_RELATIVE_PATH / f"{safe_plugin_id(plugin_id)}.json"


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

    plugin_root = root / PLUGIN_ROOT_RELATIVE_PATH
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
        "source": {"source": "local", "path": f"./plugins/{registration.plugin_id}"},
        "policy": {"installation": registration.installation, "authentication": registration.authentication},
        "category": registration.category,
    }


def require_owned_publication(root: Path, registration: Registration) -> None:
    """Refuse to claim an already discoverable plugin without Factory evidence."""

    path = publication_path(root, registration.plugin_id)
    if not path.exists():
        fail(
            f"official external registry cannot claim existing plugin {registration.plugin_id} "
            "without Factory publication evidence"
        )
    evidence = read_json(path, f"official external publication evidence for {registration.plugin_id}")
    if (
        set(evidence) != {"schemaVersion", "pluginId", "events"}
        or evidence.get("schemaVersion") != 1
        or evidence.get("pluginId") != registration.plugin_id
        or not isinstance(evidence.get("events"), list)
        or not evidence["events"]
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
    if path.exists():
        document = read_json(path, f"official external publication evidence for {registration.plugin_id}")
        require_exact_keys(document, {"schemaVersion", "pluginId", "events"}, f"official external publication evidence for {registration.plugin_id}")
        if document.get("schemaVersion") != 1 or document.get("pluginId") != registration.plugin_id:
            fail("official external publication evidence has invalid identity")
        events = document.get("events")
        if not isinstance(events, list):
            fail("official external publication evidence events must be a list")
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
    stable_write(
        root,
        path,
        {"schemaVersion": 1, "pluginId": registration.plugin_id, "events": events},
        f"official external publication evidence for {registration.plugin_id}",
    )


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


def verify_stable(root: Path, plugin_id: str, source_root: Path, release_id_value: str) -> dict[str, str]:
    registration = registration_for(root, plugin_id)
    if not isinstance(release_id_value, str) or not RELEASE_ID_PATTERN.fullmatch(release_id_value):
        fail("stable promotion release ID must be canonical")
    source_dir = resolve_source_directory(source_root, registration.source_path, f"external stable source for {registration.plugin_id}")
    candidate = candidate_release_id(source_dir, registration)
    document, _ = current_beta_record(root, registration.plugin_id)
    selected = release_record(document, release_id_value)
    if candidate != release_id_value:
        fail("external main source does not deterministically rebuild the selected Beta releaseId")
    if selected.get("releaseId") != candidate:
        fail("selected external Beta release is invalid")
    return {"plugin_id": registration.plugin_id, "release_id": release_id_value, "channel": "stable"}


def record_stable(root: Path, plugin_id: str, source_sha: str, release_id_value: str, publisher: str) -> dict[str, str]:
    registration = registration_for(root, plugin_id)
    if not isinstance(release_id_value, str) or not RELEASE_ID_PATTERN.fullmatch(release_id_value):
        fail("stable promotion release ID must be canonical")
    document, _ = current_beta_record(root, registration.plugin_id)
    channels = document.get("channels")
    stable = channels.get("stable") if isinstance(channels, dict) else None
    if not isinstance(stable, dict) or stable.get("releaseId") != release_id_value:
        fail("stable provenance can be recorded only after the selected stable pointer is written")
    record = release_record(document, release_id_value)
    append_evidence(root, registration, publication_event(registration, "stable", source_sha, record, publisher))
    return {"plugin_id": registration.plugin_id, "release_id": release_id_value, "channel": "stable"}


def validate_evidence(root: Path, registration: Registration, document: dict[str, object]) -> None:
    path = publication_path(root, registration.plugin_id)
    if not path.exists():
        fail(f"external official plugin {registration.plugin_id} has no publication evidence")
    evidence = read_json(path, f"official external publication evidence for {registration.plugin_id}")
    require_exact_keys(evidence, {"schemaVersion", "pluginId", "events"}, f"official external publication evidence for {registration.plugin_id}")
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
    if set(records).difference(beta_seen):
        fail(f"external official plugin {registration.plugin_id} lacks Beta provenance")
    stable = channels.get("stable")
    stable_id = stable.get("releaseId") if isinstance(stable, dict) else None
    if isinstance(stable_id, str) and stable_id not in stable_seen:
        fail(f"external official plugin {registration.plugin_id} lacks Stable provenance")


def validate_registry_and_snapshots(root: Path) -> None:
    """Validate external records in addition to the existing generic market gate."""

    registrations = load_registry(root)
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
    publication_root = root / PUBLICATIONS_RELATIVE_PATH
    if publication_root.exists():
        if is_link(publication_root) or not publication_root.is_dir():
            fail("official external publication directory must be a regular directory")
        allowed_files = {f"{item.plugin_id}.json" for item in registrations}
        for path in publication_root.iterdir():
            if is_link(path) or not path.is_file() or path.name not in allowed_files:
                fail(f"official external publication directory has an unregistered entry: {path.name}")
    for registration in registrations:
        entry = entries_by_id.get(registration.plugin_id)
        snapshot = snapshot_directory(root, registration.plugin_id)
        evidence = publication_path(root, registration.plugin_id)
        if registration.status == "disabled":
            if entry is not None:
                fail(f"disabled external official plugin {registration.plugin_id} remains in marketplace index")
            continue
        if entry is None:
            if snapshot.exists() or evidence.exists():
                fail(f"active external official plugin {registration.plugin_id} has an incomplete publication")
            continue
        if entry != marketplace_entry(registration):
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
        validate_evidence(root, registration, document)


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
    stable_parser = commands.add_parser("record-stable")
    stable_parser.add_argument("--plugin-id", required=True)
    stable_parser.add_argument("--source-sha", required=True)
    stable_parser.add_argument("--release-id", required=True)
    stable_parser.add_argument("--publisher", required=True)
    legacy_parser = commands.add_parser(
        "reject-legacy-stable",
        help="reject an external plugin in the legacy built-in Stable workflow",
    )
    legacy_parser.add_argument("--plugin-id", required=True)
    commands.add_parser("validate")
    args = parser.parse_args()
    root = args.root.resolve()
    try:
        if args.command == "prepare":
            result = prepare(root, args.plugin_id, args.channel, args.source_sha)
        elif args.command == "stage-beta":
            result = stage_beta(root, args.plugin_id, args.source_root)
        elif args.command == "record-beta":
            result = record_beta(root, args.plugin_id, args.source_sha, args.publisher)
        elif args.command == "verify-stable":
            result = verify_stable(root, args.plugin_id, args.source_root, args.release_id)
        elif args.command == "record-stable":
            result = record_stable(root, args.plugin_id, args.source_sha, args.release_id, args.publisher)
        elif args.command == "reject-legacy-stable":
            result = reject_legacy_stable_promotion(root, args.plugin_id)
        else:
            validate_registry_and_snapshots(root)
            result = {"valid": "true"}
        write_outputs(result, args.github_output)
    except ExternalSourceFactoryError as error:
        raise SystemExit(f"official external source Factory failed: {error}") from error
    print(" ".join(f"{key}={value}" for key, value in result.items()))


if __name__ == "__main__":
    main()
