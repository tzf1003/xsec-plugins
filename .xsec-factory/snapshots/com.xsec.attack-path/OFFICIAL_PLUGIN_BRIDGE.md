# Official plugin bridge

This package owns the signed plugin manifest, permissions and release lifecycle.
XSEC Desktop binds its compatible renderer only after this package is installed
and enabled. Package state, rather than the application installer, is the source
of truth.

## Portable MCP and Skill boundary

The root `mcp.json` and `skills/attack-path/SKILL.md` are portable Agent Plugins
components. Desktop discovers them, asks for the declared `mcp.servers.register`
and `native.execute` permissions, and exposes the sidecar through its authenticated
MCP Fabric. Oh My Pi receives only that session projection; it does not install or
start a second copy of the sidecar.

The sidecar forwards `tools/call` to the XSec Host domain RPC named by
`XSEC_ATTACK_PATH_HOST_RPC`. The Host derives assignment/project/lease context from
the authenticated session and validates parent ownership, node relationships,
revision conflicts, and audit events before writing AttackPathStore. Plugin package
files stay immutable; nodes and findings are runtime data under the host-owned
plugin data directory.
