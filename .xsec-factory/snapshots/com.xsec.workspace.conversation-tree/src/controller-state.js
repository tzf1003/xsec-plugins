import { activeLeafId, DEFAULT_SCALE, validateTree } from "./core.js";

const READ_STATUS_LABELS = {
  verification_pending: "核验中",
  conflict_deferred: "有冲突",
  busy: "运行中",
  runtime_unavailable: "待加载",
  unverifiable: "不可核验",
  streamed: "正在接收",
};

export function errorMessage(value) {
  return value instanceof Error ? value.message : String(value);
}

export function initialControllerState(context, source) {
  return {
    context,
    tree: context.tree,
    treeHash: context.treeHash,
    source,
    error: context.error ?? null,
    notice: null,
    loading: false,
    navigating: false,
    loadedTree: false,
    navigationBaseHash: null,
    selectedId: null,
    mode: "all",
    showAgentMessages: false,
    query: "",
    contextExpanded: true,
    view: { x: 24, y: 24, scale: DEFAULT_SCALE },
    drag: null,
    generation: 0,
  };
}

export function canStartRead({ disposed, loading, navigating, readSupported, visible }) {
  return !disposed && !loading && !navigating && readSupported && visible;
}

export function canStartNavigation({ disposed, loading, navigating, visible }) {
  return !disposed && !loading && !navigating && visible;
}

export function treeViewRevision(tree) {
  if (!tree) return null;
  const nodes = tree.messages.map((message) => [
    message.entryId,
    message.parentId,
    message.branchGroupId,
    message.role,
    message.timestamp,
    message.active,
  ]);
  return JSON.stringify([tree.sessionId, tree.activeLeafId, nodes]);
}

export function requestAuthorityRevision(context) {
  const session = context.session;
  const leafId = context.tree
    ? activeLeafId(context.tree.messages, context.tree.activeLeafId)
    : null;
  return stableSerialize([
    context.sessionId,
    context.treeHash,
    context.visible,
    context.truncated,
    leafId,
    Boolean(session),
    session?.status,
    session?.consistency,
    session?.pending_interactions,
    session?.tree_capability?.snapshot,
    session?.tree_capability?.navigate,
  ]);
}

function stableSerialize(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(stableSerialize).join(",")}]`;
  return `{${Object.entries(value)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, item]) => `${JSON.stringify(key)}:${stableSerialize(item)}`)
    .join(",")}}`;
}

export function contextRevision(value) {
  const source = value && typeof value === "object" && "raw" in value
    ? value.raw
    : value;
  return stableSerialize(source);
}

export function isRequestCurrent({ disposed, state, fence }) {
  return !disposed
    && fence.generation === state.generation
    && fence.sessionId === state.context.sessionId;
}

export function contextFailurePatch({ context, raw, message }) {
  return {
    context: { ...context, raw, visible: false },
    treeHash: null,
    error: `读取宿主上下文失败：${message}`,
    loading: false,
    navigating: false,
    drag: null,
  };
}

export function readResponsePatch(response, expectedSessionId, navigationBaseHash = null) {
  if (!response || typeof response !== "object" || typeof response.status !== "string") {
    throw new Error("conversation_tree_invalid_read_response");
  }
  if (response.status === "ready") {
    return {
      tree: validateResponseTree(response.tree, expectedSessionId),
      treeHash: null,
      loadedTree: true,
      navigationBaseHash,
      source: { availability: "ready", label: "已读取" },
      selectedId: null,
    };
  }
  const label = READ_STATUS_LABELS[response.status];
  if (!label) throw new Error(`conversation_tree_unknown_read_status: ${response.status}`);
  return {
    treeHash: null,
    source: { availability: response.status, label },
    notice: `对话树暂不可读：${label}`,
  };
}

export function validateResponseTree(value, expectedSessionId) {
  const tree = validateTree(value);
  if (!expectedSessionId || tree.sessionId !== expectedSessionId) {
    throw new Error("conversation_tree_response_session_mismatch");
  }
  return tree;
}

export function validateNavigationTree(value, expectedSessionId, targetEntryId) {
  const tree = validateResponseTree(value, expectedSessionId);
  if (activeLeafId(tree.messages, tree.activeLeafId) !== targetEntryId) {
    throw new Error("conversation_tree_navigation_target_mismatch");
  }
  return tree;
}
