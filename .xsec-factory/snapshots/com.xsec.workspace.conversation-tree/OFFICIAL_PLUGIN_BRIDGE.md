# Official plugin frontend

This package owns the signed manifest, permissions, committed `single-esm`
frontend and release lifecycle for the XSEC conversation-tree workspace tool.
Desktop executes the plugin frontend directly; the previous built-in React
renderer is only a historical behavior reference and is not part of this
implementation.

## Restored behavior

Desktop publishes the session snapshot on the dedicated
`xsec.conversation-tree.snapshot` binary stream. The plugin reassembles the
latest revision and uses it for the deterministic branch graph, active-path
display, Agent visibility filter, search dimming, canvas pan/zoom, node
inspector and exact branch navigation. Desktop republishes the current
snapshot after the frontend module becomes ready. The **加载完整对话树** action
uses the same host-bound data flow and installs its result only for the
still-active session.

When Desktop marks the tool context as hidden or sends malformed context, the
plugin revokes navigation authority, stops in-flight UI state and disables the
surface until a valid visible context is published.

Navigation is fail-closed. The plugin sends
`xsec.conversation-tree.navigate` only when the current streamed snapshot
contains the authoritative `treeHash`, the session is quiescent and
synchronized, no interaction is pending, and the Provider declares navigation
support. A newly selected branch remains browseable while Desktop publishes
the next authoritative snapshot.

## Host boundary

The current Desktop frontend API exposes only:

- host-published `xsec.conversation-tree.snapshot` data packets for the
  currently bound session
- `xsec.conversation-tree.read`
- `xsec.conversation-tree.navigate` with exact target semantics

Desktop selects the session binding before it mounts the iframe, then provides
the compact display context and scoped snapshot stream independently.
Consequently this plugin cannot open a different project session, request a
live-only refresh, edit a user message, or create an Agent continuation intent.
Those behaviors require new explicit host APIs; the frontend does not emulate
them.

## Source and release checks

Editable modules live under `src/`. `npm run build` bundles them into the
committed frontend entrypoint because Factory installs the artifact without
running a build. `npm run check` runs the real pure-logic tests and verifies
that the committed bundle matches source. Both plugin manifests must carry the
same name and version.

The plugin has no account-level persistent configuration. Range filters,
search and viewport state belong to the current tool instance, so no empty
settings page is contributed.

The root manifest uses Agent Plugins v1 with a `com.xsec.desktop` schema v2
extension. Conversation Tree is a Host package: its two frontend methods read
and navigate the Desktop-owned session tree. The artifact carries no portable
MCP server or Skill because session graphs, navigation authority and their
audit trail remain under Desktop session validation.
