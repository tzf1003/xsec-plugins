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

Release artifacts inject the platform-native `bin/attack-path-mcp`; source
directories remain binary-free. The MCP Fabric supplies task identity and
permissions, while the sidecar stores nodes and findings in `PLUGIN_DATA`.
Package files stay immutable; Host APIs retain browser, proxy, evidence, report,
terminal, audit and sub-agent operations.
