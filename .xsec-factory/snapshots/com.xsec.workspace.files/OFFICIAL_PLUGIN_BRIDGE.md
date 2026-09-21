# Official plugin bridge

This package owns the signed plugin manifest, permissions and release lifecycle. When it is installed and enabled, XSEC Desktop loads its declared frontend in an opaque sandbox. The package owns the project-file UI and interaction state; Desktop exposes only the declared, capability-bound workspace read and Composer write RPCs. Package state, rather than the application installer, remains the source of truth.

The root manifest uses Agent Plugins v1 with a `com.xsec.desktop` schema v2 extension. Project files remains a Host package: workspace paths, file contents and Composer writes remain protected by Desktop project and context validation. The artifact declares no portable MCP server, Skill or `agentTools`.
