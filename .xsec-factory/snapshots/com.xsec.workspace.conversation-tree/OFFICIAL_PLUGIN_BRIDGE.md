# Official plugin frontend

This package owns the signed manifest, permissions, committed `single-esm`
frontend and release lifecycle for the XSEC conversation-tree workspace tool.
Desktop executes the plugin frontend directly; the previous built-in React
renderer is only a historical behavior reference and is not part of this
implementation.

## Restored behavior

The plugin renders the cached `workspace.session.conversation_tree` projection
without issuing an RPC during mount or context updates. It restores the
deterministic branch graph, active-path display, Agent visibility filter,
search dimming, canvas pan/zoom, node inspector and exact branch navigation.
If no projection is cached, recovering the full tree requires the user to
select **加载完整对话树**.

When Desktop marks the tool context as hidden or sends malformed context, the
plugin revokes navigation authority, stops in-flight UI state and disables the
surface until a valid visible context is published.

Navigation is fail-closed. The plugin only sends
`xsec.conversation-tree.navigate` when the current context includes the
authoritative `treeHash`, the session is quiescent and synchronized, no
interaction is pending, and the Provider declares navigation support. A tree
returned by `xsec.conversation-tree.read` remains browseable, but navigation
stays disabled until Desktop publishes a context projection with its hash.

## Host boundary

The current Desktop frontend API exposes only:

- `xsec.conversation-tree.read`
- `xsec.conversation-tree.navigate` with exact target semantics

Consequently this plugin cannot open a different project session, request a
live-only refresh, edit a user message, or create an Agent continuation intent.
Those behaviors require new explicit host APIs; the frontend does not emulate
them. When the 64 KiB sandbox context limit removes session data, any already
loaded tree stays browseable and navigation remains disabled.

## Source and release checks

Editable modules live under `src/`. `npm run build` bundles them into the
committed frontend entrypoint because Factory installs the artifact without
running a build. `npm run check` runs the real pure-logic tests and verifies
that the committed bundle matches source. Both plugin manifests must carry the
same name and version.

The plugin has no account-level persistent configuration. Range filters,
search and viewport state belong to the current tool instance, so no empty
settings page is contributed.
