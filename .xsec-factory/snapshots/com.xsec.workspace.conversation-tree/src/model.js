import {
  activeLeafId,
  activePath,
  layoutTree,
  matchesQuery,
  nodeDepths,
  preferredSelection,
  treePath,
  visibleMessages,
} from "./core.js";
import { inspectorContextResult, navigationBlock } from "./context.js";

export function graphModel(state) {
  if (!state.tree) return null;
  const messages = state.tree.messages;
  const leafId = activeLeafId(messages, state.tree.activeLeafId);
  const active = activePath(messages, leafId);
  const activeIds = new Set(active.map((message) => message.entryId));
  const scoped = state.mode === "active" ? messages.filter((message) => activeIds.has(message.entryId)) : messages;
  const visible = visibleMessages(scoped, state.showAgentMessages);
  const visibleIds = new Set(visible.map((message) => message.entryId));
  const selectedId = state.selectedId && visibleIds.has(state.selectedId)
    ? state.selectedId
    : preferredSelection(messages, visible, leafId);
  const layout = layoutTree(visible);
  const depths = nodeDepths(visible, layout.parentById);
  const positioned = visible.flatMap((message) => {
    const point = layout.positions.get(message.entryId);
    return point ? [{ message, ...point }] : [];
  });
  const positions = new Map(positioned.map((item) => [item.message.entryId, item]));
  return { messages, leafId, active, activeIds, visible, selectedId, layout, depths, positioned, positions };
}

export function selectedModel(state, graph) {
  if (!graph?.selectedId) return null;
  const selected = graph.messages.find((message) => message.entryId === graph.selectedId);
  if (!selected) throw new Error(`conversation_tree_selection_missing: ${graph.selectedId}`);
  const path = treePath(graph.messages, selected.entryId);
  return {
    selected,
    path,
    inspector: inspectorContextResult(state.context.session, path),
    navigationBlock: navigationBlock(state.context, state.tree, state.treeHash),
  };
}

export function orderedNodeIds(graph) {
  return [...graph.positioned]
    .sort((left, right) => left.y - right.y || left.x - right.x || left.message.entryId.localeCompare(right.message.entryId))
    .map((item) => item.message.entryId);
}

export function queryMatches(graph, query) {
  return new Map(graph.visible.map((message) => [message.entryId, matchesQuery(message, query)]));
}
