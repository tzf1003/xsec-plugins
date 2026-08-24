"""Non-secret trust and compatibility constants for the official marketplace."""

from __future__ import annotations


# This is the raw Ed25519 public key pinned by XSEC Desktop. It is public trust
# data, not a signing secret. A change requires a Desktop compatibility release.
OFFICIAL_MARKETPLACE_PUBLIC_KEY_B64 = "KLOHLCxQiEgPiGLwX2RJh/DlkGT/4dLr0z8y9WQrIPI="

# The first-online installer relies on this exact default set. New marketplace
# entries may be optional, but cannot silently become installed by default.
DEFAULT_OFFICIAL_PLUGIN_IDS = (
    "com.xsec.asset-discovery",
    "com.xsec.attack-path",
    "com.xsec.project-workspace",
    "com.xsec.system-terminal",
    "com.xsec.workspace.approvals",
    "com.xsec.workspace.browser",
    "com.xsec.workspace.conversation-tree",
    "com.xsec.workspace.files",
    "com.xsec.workspace.project-outcomes",
    "com.xsec.workspace.sub-agent",
    "com.xsec.workspace.traffic",
)
