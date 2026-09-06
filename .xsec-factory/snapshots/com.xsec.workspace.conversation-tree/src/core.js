export const NODE_WIDTH = 166;
export const NODE_HEIGHT = 66;
export const MIN_SCALE = 0.45;
export const MAX_SCALE = 1.6;
export const DEFAULT_SCALE = 0.85;
export const SUPPORTED_PROTOCOL_VERSION = 1;

const COLUMN_GAP = 34;
const ROW_GAP = 34;
const LAYOUT_PAD = 40;
const TOP_SAFE_AREA = 24;
const BOTTOM_SAFE_AREA = 54;
const HORIZONTAL_SAFE_AREA = 24;
const ROLES = new Set(["user", "assistant"]);

function requiredString(value, field) {
  if (typeof value !== "string" || !value) throw new Error(`conversation_tree_invalid_${field}`);
  return value;
}

function optionalId(value, field) {
  if (value === null) return null;
  return requiredString(value, field);
}

function validateMessage(value, index) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`conversation_tree_invalid_message_${index}`);
  }
  const role = requiredString(value.role, `role_${index}`);
  if (!ROLES.has(role)) throw new Error(`conversation_tree_invalid_role_${index}`);
  if (!Number.isFinite(value.timestamp)) throw new Error(`conversation_tree_invalid_timestamp_${index}`);
  if (typeof value.text !== "string" || typeof value.thought !== "string" || typeof value.active !== "boolean") {
    throw new Error(`conversation_tree_invalid_content_${index}`);
  }
  return {
    ...value,
    entryId: requiredString(value.entryId, `entry_id_${index}`),
    parentId: optionalId(value.parentId, `parent_id_${index}`),
    branchGroupId: optionalId(value.branchGroupId, `branch_group_id_${index}`),
    role,
  };
}

function assertUniqueIds(messages) {
  const ids = new Set();
  for (const message of messages) {
    if (ids.has(message.entryId)) throw new Error(`conversation_tree_duplicate_id: ${message.entryId}`);
    ids.add(message.entryId);
  }
  return ids;
}

function resolvedParent(message, ids) {
  if (message.parentId && ids.has(message.parentId)) return message.parentId;
  if (message.branchGroupId && ids.has(message.branchGroupId)) return message.branchGroupId;
  if (message.parentId || message.branchGroupId) {
    throw new Error(`conversation_tree_parent_missing: ${message.entryId}`);
  }
  return null;
}

function assertAcyclic(parentById) {
  const complete = new Set();
  for (const entryId of parentById.keys()) {
    if (complete.has(entryId)) continue;
    const visiting = new Set();
    let current = entryId;
    while (current && !complete.has(current)) {
      if (visiting.has(current)) throw new Error(`conversation_tree_cycle: ${current}`);
      visiting.add(current);
      current = parentById.get(current);
    }
    for (const visited of visiting) complete.add(visited);
  }
}

export function parentMap(messages) {
  const ids = assertUniqueIds(messages);
  const result = new Map();
  for (const message of messages) {
    const parent = resolvedParent(message, ids);
    if (parent === message.entryId) throw new Error(`conversation_tree_cycle: ${message.entryId}`);
    if (parent) result.set(message.entryId, parent);
  }
  assertAcyclic(result);
  return result;
}

export function validateTree(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) || !Array.isArray(value.messages)) {
    throw new Error("conversation_tree_invalid_snapshot");
  }
  if (value.protocolVersion !== SUPPORTED_PROTOCOL_VERSION) {
    throw new Error(`conversation_tree_unsupported_protocol: ${String(value.protocolVersion)}`);
  }
  const messages = value.messages.map(validateMessage);
  parentMap(messages);
  const activeLeafId = value.activeLeafId === null ? null : optionalId(value.activeLeafId, "active_leaf_id");
  if (activeLeafId && !messages.some((message) => message.entryId === activeLeafId)) {
    throw new Error(`conversation_tree_active_leaf_missing: ${activeLeafId}`);
  }
  return {
    ...value,
    sessionId: requiredString(value.sessionId, "session_id"),
    messages,
    activeLeafId,
  };
}

export function activeLeafId(messages, preferred) {
  if (preferred && messages.some((message) => message.entryId === preferred)) return preferred;
  return messages.filter((message) => message.active).at(-1)?.entryId ?? null;
}

export function treePath(messages, entryId) {
  const parents = parentMap(messages);
  const byId = new Map(messages.map((message) => [message.entryId, message]));
  const path = [];
  let current = byId.get(entryId);
  while (current) {
    path.unshift(current);
    current = byId.get(parents.get(current.entryId));
  }
  return path;
}

export function activePath(messages, preferred) {
  const leaf = activeLeafId(messages, preferred);
  return leaf ? treePath(messages, leaf) : [];
}

function nearestUserParent(message, parents, byId) {
  let parentId = parents.get(message.entryId);
  while (parentId) {
    const parent = byId.get(parentId);
    if (!parent) throw new Error(`conversation_tree_parent_missing: ${message.entryId}`);
    if (parent.role === "user") return parent.entryId;
    parentId = parents.get(parent.entryId);
  }
  return null;
}

export function visibleMessages(messages, showAgentMessages) {
  const parents = parentMap(messages);
  if (showAgentMessages) return [...messages];
  const byId = new Map(messages.map((message) => [message.entryId, message]));
  return messages.filter((message) => message.role === "user").map((message) => {
    const parentId = nearestUserParent(message, parents, byId);
    return { ...message, parentId, branchGroupId: parentId };
  });
}

function resolveDepth(entryId, parents, depths) {
  const trail = [];
  let current = entryId;
  while (current && !depths.has(current)) {
    trail.push(current);
    current = parents.get(current) ?? null;
  }
  let depth = current ? depths.get(current) : 0;
  while (trail.length) depths.set(trail.pop(), ++depth);
  return depths.get(entryId);
}

export function nodeDepths(messages, parents = parentMap(messages)) {
  const depths = new Map();
  for (const message of messages) resolveDepth(message.entryId, parents, depths);
  return depths;
}

export function preferredSelection(messages, visible, leafId) {
  const parents = parentMap(messages);
  const visibleIds = new Set(visible.map((message) => message.entryId));
  let current = leafId;
  while (current) {
    if (visibleIds.has(current)) return current;
    current = parents.get(current) ?? null;
  }
  return visible.at(-1)?.entryId ?? null;
}

function childrenByParent(messages, parents) {
  const children = new Map();
  for (const message of messages) {
    const parent = parents.get(message.entryId);
    if (!parent) continue;
    const siblings = children.get(parent) ?? [];
    siblings.push(message);
    children.set(parent, siblings);
  }
  for (const siblings of children.values()) {
    siblings.sort((left, right) => left.timestamp - right.timestamp || left.entryId.localeCompare(right.entryId));
  }
  return children;
}

function sortedRoots(messages, parents) {
  return messages.filter((message) => !parents.has(message.entryId)).sort((left, right) => (
    Number(right.active) - Number(left.active)
    || left.timestamp - right.timestamp
    || left.entryId.localeCompare(right.entryId)
  ));
}

function placeRoot({ root, children, positions, initialLeafColumn }) {
  const stack = [{ message: root, depth: 0, expanded: false }];
  let leafColumn = initialLeafColumn;
  while (stack.length) {
    const frame = stack.pop();
    const descendants = children.get(frame.message.entryId) ?? [];
    if (!frame.expanded && descendants.length) {
      stack.push({ ...frame, expanded: true });
      for (let index = descendants.length - 1; index >= 0; index -= 1) {
        stack.push({ message: descendants[index], depth: frame.depth + 1, expanded: false });
      }
      continue;
    }
    const center = descendants.length
      ? descendants.reduce((sum, child) => sum + positions.get(child.entryId).x + NODE_WIDTH / 2, 0) / descendants.length
      : LAYOUT_PAD + NODE_WIDTH / 2 + leafColumn++ * (NODE_WIDTH + COLUMN_GAP);
    positions.set(frame.message.entryId, {
      x: center - NODE_WIDTH / 2,
      y: LAYOUT_PAD + frame.depth * (NODE_HEIGHT + ROW_GAP),
    });
  }
  return leafColumn;
}

export function layoutTree(messages) {
  const positions = new Map();
  const parents = parentMap(messages);
  if (!messages.length) return { positions, parentById: parents, width: 0, height: 0 };
  const children = childrenByParent(messages, parents);
  let leafColumn = 0;
  for (const root of sortedRoots(messages, parents)) {
    leafColumn = placeRoot({ root, children, positions, initialLeafColumn: leafColumn });
    leafColumn += 1;
  }
  let width = 0;
  let height = 0;
  for (const point of positions.values()) {
    width = Math.max(width, point.x + NODE_WIDTH + LAYOUT_PAD);
    height = Math.max(height, point.y + NODE_HEIGHT + LAYOUT_PAD);
  }
  return { positions, parentById: parents, width, height };
}

export function clampScale(scale) {
  return Math.max(MIN_SCALE, Math.min(MAX_SCALE, scale));
}

export function panView(view, deltaX, deltaY) {
  return { ...view, x: view.x - deltaX, y: view.y - deltaY };
}

export function zoomView(view, scale, focus) {
  const nextScale = clampScale(scale);
  const worldX = (focus.x - view.x) / view.scale;
  const worldY = (focus.y - view.y) / view.scale;
  return { scale: nextScale, x: focus.x - worldX * nextScale, y: focus.y - worldY * nextScale };
}

export function focusPath(viewport, activePoint, pathPoints) {
  const points = pathPoints.length ? pathPoints : [activePoint];
  let minX = activePoint.x;
  let maxX = activePoint.x + NODE_WIDTH;
  let minY = activePoint.y;
  for (const point of points) {
    minX = Math.min(minX, point.x);
    maxX = Math.max(maxX, point.x + NODE_WIDTH);
    minY = Math.min(minY, point.y);
  }
  const activeBottom = activePoint.y + NODE_HEIGHT;
  const availableWidth = Math.max(1, viewport.width - HORIZONTAL_SAFE_AREA * 2);
  const availableHeight = Math.max(1, viewport.height - TOP_SAFE_AREA - BOTTOM_SAFE_AREA);
  const scale = clampScale(Math.min(
    DEFAULT_SCALE,
    availableWidth / Math.max(NODE_WIDTH, maxX - minX),
    availableHeight / Math.max(NODE_HEIGHT, activeBottom - minY),
  ));
  return {
    scale,
    x: viewport.width / 2 - ((minX + maxX) / 2) * scale,
    y: viewport.height - BOTTOM_SAFE_AREA - activeBottom * scale,
  };
}

export function matchesQuery(message, query) {
  const normalized = query.trim().toLocaleLowerCase("zh-CN");
  if (!normalized) return true;
  return `${message.text} ${message.thought}`.toLocaleLowerCase("zh-CN").includes(normalized);
}
