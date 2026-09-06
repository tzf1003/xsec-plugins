export function message(entryId, options = {}) {
  return {
    entryId,
    parentId: options.parentId ?? null,
    branchGroupId: options.branchGroupId ?? null,
    role: options.role ?? "user",
    text: options.text ?? entryId,
    thought: options.thought ?? "",
    timestamp: options.timestamp ?? 1,
    active: options.active ?? false,
  };
}

export function tree(messages, options = {}) {
  return {
    protocolVersion: 1,
    sessionId: options.sessionId ?? "session-1",
    activeLeafId: options.activeLeafId ?? null,
    messages,
  };
}

export function context(projection, options = {}) {
  return {
    kind: "workspace-tool",
    visible: options.visible ?? true,
    workspace: {
      session: {
        session_id: projection.sessionId,
        status: options.status ?? "idle",
        consistency: options.consistency ?? "synchronized",
        pending_interactions: options.pendingInteractions ?? {},
        tree_capability: { snapshot: options.snapshot ?? true, navigate: options.navigate ?? true },
        conversation_tree: { ...projection, treeHash: options.treeHash ?? "hash-1" },
        messages: [],
        conversation_contexts: {},
      },
    },
  };
}
