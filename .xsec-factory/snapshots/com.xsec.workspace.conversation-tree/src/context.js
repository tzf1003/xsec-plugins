import { activeLeafId, validateTree } from "./core.js";

const QUIESCENT_STATUSES = new Set(["idle", "error"]);

function isRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

export function isHiddenContext(value) {
  return isRecord(value) && value.visible === false;
}

function inactiveContext(raw, error = null) {
  return {
    raw,
    workspace: null,
    session: null,
    tree: null,
    treeHash: null,
    sessionId: null,
    truncated: raw?.truncated === true,
    visible: false,
    error,
  };
}

export function parseMountContext(value) {
  if (isHiddenContext(value)) return inactiveContext(value);
  try {
    return parseContext(value);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return inactiveContext(value, `读取宿主上下文失败：${message}`);
  }
}

function optionalRecord(value, field) {
  if (value === undefined || value === null) return null;
  if (!isRecord(value)) throw new Error(`conversation_tree_invalid_${field}`);
  return value;
}

function optionalString(value, field) {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string" || !value) throw new Error(`conversation_tree_invalid_${field}`);
  return value;
}

function optionalBoolean(value, field, fallback) {
  if (value === undefined || value === null) return fallback;
  if (typeof value !== "boolean") throw new Error(`conversation_tree_invalid_${field}`);
  return value;
}

function referenceString(reference, field) {
  const value = optionalString(reference[field], `reference_${field}`);
  if (!value) throw new Error(`conversation_tree_invalid_reference_${field}`);
  return value;
}

function parseProjection(session) {
  const projection = optionalRecord(session?.conversation_tree, "projection");
  if (!projection) return { tree: null, treeHash: null };
  const tree = validateTree(projection);
  const treeHash = optionalString(projection.treeHash, "tree_hash");
  return { tree, treeHash };
}

function resolveSessionId(session, tree) {
  const sessionId = optionalString(session?.session_id, "session_id");
  if (sessionId) return sessionId;
  return tree?.sessionId ?? null;
}

export function parseContext(value) {
  if (value !== null && value !== undefined && !isRecord(value)) {
    throw new Error("conversation_tree_invalid_context");
  }
  const context = value ?? {};
  const truncated = optionalBoolean(context.truncated, "truncated", false);
  const visible = optionalBoolean(context.visible, "visible", true);
  const workspace = optionalRecord(context.workspace, "workspace");
  const session = optionalRecord(workspace?.session, "session");
  const { tree, treeHash } = parseProjection(session);
  const sessionId = resolveSessionId(session, tree);
  if (tree?.sessionId && sessionId && tree.sessionId !== sessionId) {
    throw new Error("conversation_tree_session_mismatch");
  }
  return {
    raw: context,
    workspace,
    session,
    tree,
    treeHash,
    sessionId,
    truncated,
    visible,
  };
}

export function sourceState(context, hasLoadedTree = false) {
  if (context.tree) return { availability: "cached", label: "缓存" };
  if (hasLoadedTree) return { availability: "ready", label: "已读取" };
  if (!context.sessionId) return { availability: "missing_session", label: "无会话" };
  if (!supportsTreeSnapshot(context)) {
    return { availability: "unsupported", label: "不可用" };
  }
  return { availability: "requires_restore", label: "待加载" };
}

export function supportsTreeSnapshot(context) {
  return context.session?.tree_capability?.snapshot !== false;
}

export function canReadTree(context) {
  return Boolean(context.sessionId) && supportsTreeSnapshot(context);
}

export function navigationBlock(context, tree, treeHash) {
  if (!context.visible) return "对话树当前不可见";
  if (context.truncated) return "宿主上下文已截断，仅可浏览";
  if (!treeHash) return "缺少宿主发布的权威树摘要，仅可浏览";
  const sessionBlock = sessionNavigationBlock(context.session);
  if (sessionBlock) return sessionBlock;
  const leaf = activeLeafId(tree.messages, tree.activeLeafId);
  return leaf ? null : "对话树没有活动分支";
}

function sessionNavigationBlock(session) {
  if (!session) return "宿主上下文不包含当前会话状态";
  if (session.tree_capability?.navigate !== true) return "当前 Provider 不支持分支切换";
  if (!QUIESCENT_STATUSES.has(session.status)) return "会话运行中，暂不能切换分支";
  if (session.consistency !== "synchronized") return "会话状态尚未同步";
  const pending = session.pending_interactions;
  if (pending !== undefined && pending !== null && !isRecord(pending)) return "会话待处理交互状态无效";
  if (pending && Object.keys(pending).length) return "会话存在待处理交互";
  return null;
}

function messageForEntry(session, entryId) {
  const messages = Array.isArray(session?.messages) ? session.messages : [];
  return messages.find((message) => message?.entry_id === entryId || message?.turn_key === entryId) ?? null;
}

function lineReferenceLabel(reference) {
  if (!Number.isInteger(reference.line) || reference.line < 1) {
    throw new Error("conversation_tree_invalid_reference_line");
  }
  return `${referenceString(reference, "name")}:${reference.line}`;
}

const REFERENCE_LABELS = {
  path: (reference) => referenceString(reference, "name"),
  "line-comment": lineReferenceLabel,
  finding: (reference) => referenceString(reference, "title"),
  "project-outcome": (reference) => referenceString(reference, "title"),
  "project-outcomes": (reference) => `${referenceString(reference, "projectName")}/成果`,
  "traffic-flow": (reference) => `${referenceString(reference, "method")} ${referenceString(reference, "host")}`,
  "project-findings": (reference) => `${referenceString(reference, "projectName")}/漏洞`,
  project: (reference) => referenceString(reference, "projectName"),
};

function referenceLabel(reference) {
  if (!isRecord(reference)) throw new Error("conversation_tree_invalid_reference");
  const format = REFERENCE_LABELS[reference.kind];
  if (!format) throw new Error(`conversation_tree_unknown_reference: ${String(reference.kind)}`);
  return format(reference);
}

function referencesFromMessage(message) {
  if (!message?.content) return [];
  if (!isRecord(message.content) || !Array.isArray(message.content.parts)) {
    throw new Error("conversation_tree_invalid_composer_document");
  }
  return message.content.parts.flatMap((part) => {
    if (!isRecord(part)) throw new Error("conversation_tree_invalid_composer_part");
    return part.kind === "reference" ? [referenceLabel(part.reference)] : [];
  });
}

export function inspectorContext(session, selectedPath) {
  const selectedUser = [...selectedPath].reverse().find((message) => message.role === "user");
  const entryId = selectedUser?.entryId ?? null;
  const checkpoint = optionalEntryRecord(session?.conversation_contexts, entryId, "checkpoint");
  const message = optionalEntryMessage(session, entryId);
  const characters = selectedPath.reduce((total, item) => total + item.text.length + item.thought.length, 0);
  const commands = commandNames(checkpoint);
  return {
    model: recordedValue(checkpoint?.model, session?.model),
    mode: recordedValue(checkpoint?.mode, session?.mode),
    thinking: recordedValue(checkpoint?.thinking, session?.thinking),
    characters,
    tokens: recordedValue(checkpoint?.usage?.total_tokens, session?.usage?.total_tokens),
    commands,
    references: referencesFromMessage(message),
  };
}

export function inspectorContextResult(session, selectedPath) {
  try {
    return { status: "ready", value: inspectorContext(session, selectedPath) };
  } catch (error) {
    return { status: "error", message: error instanceof Error ? error.message : String(error) };
  }
}

function optionalEntryRecord(records, entryId, field) {
  if (!entryId) return null;
  return optionalRecord(records?.[entryId], field);
}

function optionalEntryMessage(session, entryId) {
  if (!entryId) return null;
  return messageForEntry(session, entryId);
}

function commandNames(checkpoint) {
  const commands = checkpoint?.command_names ?? [];
  if (!Array.isArray(commands) || commands.some((command) => typeof command !== "string")) {
    throw new Error("conversation_tree_invalid_command_names");
  }
  return commands;
}

function recordedValue(primary, secondary) {
  return primary ?? secondary ?? null;
}
