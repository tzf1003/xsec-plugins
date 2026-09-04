"""Non-secret trust and compatibility rules for the official marketplace."""

from __future__ import annotations

import json
from pathlib import Path


# This is the raw Ed25519 public key pinned by XSEC Desktop. It is public trust
# data, not a signing secret. A change requires a Desktop compatibility release.
OFFICIAL_MARKETPLACE_PUBLIC_KEY_B64 = "KLOHLCxQiEgPiGLwX2RJh/DlkGT/4dLr0z8y9WQrIPI="

# Every retained first-party package keeps the stronger manifest/frontend
# checks even after it leaves Marketplace discovery.
OFFICIAL_PLUGIN_IDS = (
    "com.xsec.asset-discovery",
    "com.xsec.attack-path",
    "com.xsec.system-terminal",
    "com.xsec.workspace.approvals",
    "com.xsec.workspace.browser",
    "com.xsec.workspace.conversation-tree",
    "com.xsec.workspace.files",
    "com.xsec.workspace.project-outcomes",
    "com.xsec.workspace.sub-agent",
    "com.xsec.workspace.traffic",
)

REGISTRY_RELATIVE_PATH = Path(".xsec-factory") / "official-registry.json"
DEFAULT_INSTALLATION_POLICY = {"installation": "INSTALLED_BY_DEFAULT", "authentication": "ON_INSTALL"}
AVAILABLE_INSTALLATION_POLICY = {"installation": "AVAILABLE", "authentication": "ON_INSTALL"}


def active_official_plugin_policies(root: Path) -> tuple[tuple[str, dict[str, str]], ...]:
    """Return active first-party Marketplace entries from the protected Registry."""

    path = root / REGISTRY_RELATIVE_PATH
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("official Factory registry cannot be read") from error
    if not isinstance(document, dict) or document.get("schemaVersion") != 2:
        raise ValueError("official Factory registry must use schemaVersion 2")
    entries = document.get("plugins")
    if not isinstance(entries, list):
        raise ValueError("official Factory registry plugins must be a list")
    active: list[tuple[str, dict[str, str]]] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError(f"official Factory registry plugin at index {index} must be an object")
        if entry.get("trustTier") != "first-party" or entry.get("status") != "active":
            continue
        plugin_id = entry.get("pluginId")
        policy = entry.get("policy")
        if not isinstance(plugin_id, str) or not plugin_id or not isinstance(policy, dict):
            raise ValueError(f"active first-party Registry plugin at index {index} is invalid")
        if policy not in (DEFAULT_INSTALLATION_POLICY, AVAILABLE_INSTALLATION_POLICY):
            raise ValueError(f"active first-party Registry plugin {plugin_id} has an invalid installation policy")
        active.append((plugin_id, dict(policy)))
    if len(active) != len({plugin_id for plugin_id, _ in active}):
        raise ValueError("official Factory registry contains duplicate active first-party plugin IDs")
    return tuple(active)


def active_default_official_plugin_ids(root: Path) -> tuple[str, ...]:
    """Return active first-party plugins installed in a fresh Desktop profile."""

    return tuple(
        plugin_id
        for plugin_id, policy in active_official_plugin_policies(root)
        if policy == DEFAULT_INSTALLATION_POLICY
    )
