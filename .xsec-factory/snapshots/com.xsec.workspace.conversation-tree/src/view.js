import { MAX_SCALE, MIN_SCALE, NODE_HEIGHT, NODE_WIDTH, matchesQuery } from "./core.js";
import { canReadTree } from "./context.js";
import { button, displayValue, element, factList, formatTime, shortText, svgElement } from "./elements.js";

const MIN_STAGE_WIDTH = 520;
const MIN_STAGE_HEIGHT = 360;
const CURVE_MINIMUM = 20;

function setHidden(node, hidden) {
  node.hidden = hidden;
}

function renderNotice(controls, state) {
  let message = state.error;
  let error = Boolean(message);
  if (!message && state.notice) message = state.notice;
  if (!message && state.context.truncated) message = "宿主上下文已截断；可浏览已读取内容，分支切换保持禁用。";
  if (!message && state.tree && !state.treeHash) message = "缺少宿主发布的权威树摘要；当前仅可浏览。";
  controls.notice.textContent = message ?? "";
  controls.notice.className = `ct-notice${error ? " is-error" : ""}`;
  setHidden(controls.notice, !message);
}

function renderHeader(controls, state) {
  controls.badge.textContent = state.source.label;
  controls.badge.className = `ct-badge is-${state.source.availability}`;
  controls.refresh.disabled = state.loading || state.navigating || !canReadTree(state.context) || !state.context.visible;
  controls.refresh.textContent = state.loading ? "◌" : "↻";
  controls.refresh.setAttribute("aria-busy", String(state.loading));
  controls.search.value = state.query;
  controls.all.setAttribute("aria-pressed", String(state.mode === "all"));
  controls.active.setAttribute("aria-pressed", String(state.mode === "active"));
  controls.checkbox.checked = state.showAgentMessages;
  renderNotice(controls, state);
}

export function emptyContent(state, graph) {
  if (state.loading) return ["正在读取对话树", "正在从当前会话读取真实 Provider 消息树。", false];
  if (state.source.availability === "unsupported") {
    return ["当前 Provider 不支持对话树", state.context.session?.tree_capability?.reason ?? "宿主明确报告该会话不支持消息树快照。", false];
  }
  if (state.source.availability === "missing_session") return ["当前未绑定会话", "打开或选择一个会话后可读取对话树。", false];
  if (graph && !graph.messages.length) return ["当前对话树没有消息节点", "宿主返回了一个有效的空对话树快照。", false];
  if (graph && !graph.visible.length) return ["当前范围没有可见节点", "可调整范围或开启“显示 Agent 消息”查看其他节点。", false];
  return ["尚未缓存对话树", "加载完整树是显式操作，可能恢复当前会话的本地运行时。", true];
}

function renderEmpty(controls, state, graph) {
  const [title, detail, canLoad] = emptyContent(state, graph);
  controls.emptyTitle.textContent = title;
  controls.emptyDetail.textContent = detail;
  setHidden(controls.load, !canLoad);
  controls.load.disabled = state.loading || state.navigating || !canReadTree(state.context) || !state.context.visible;
  setHidden(controls.empty, Boolean(graph?.visible.length));
}

function linkPath(item, parent) {
  const startX = parent.x + NODE_WIDTH / 2;
  const startY = parent.y + NODE_HEIGHT;
  const endX = item.x + NODE_WIDTH / 2;
  const endY = item.y;
  const middle = startY + Math.max(CURVE_MINIMUM, (endY - startY) / 2);
  return `M ${startX} ${startY} C ${startX} ${middle}, ${endX} ${middle}, ${endX} ${endY}`;
}

function renderLinks(graph, width, height) {
  const svg = svgElement("svg", { class: "ct-links", width, height, "aria-hidden": "true" });
  for (const item of graph.positioned) {
    const parentId = graph.layout.parentById.get(item.message.entryId);
    const parent = parentId ? graph.positions.get(parentId) : null;
    if (!parent) continue;
    const path = svgElement("path", { d: linkPath(item, parent) });
    if (graph.activeIds.has(item.message.entryId) && graph.activeIds.has(parentId)) path.classList.add("is-active");
    svg.append(path);
  }
  return svg;
}

function nodeClass(item, graph, state) {
  const classes = ["ct-node", `role-${item.message.role}`];
  if (graph.activeIds.has(item.message.entryId)) classes.push("is-active");
  if (graph.selectedId === item.message.entryId) classes.push("is-selected");
  if (!matchesQuery(item.message, state.query)) classes.push("is-dimmed");
  return classes.join(" ");
}

function renderNode({ item, graph, state, actions }) {
  const node = button(nodeClass(item, graph, state));
  node.disabled = !state.context.visible;
  node.dataset.entryId = item.message.entryId;
  node.setAttribute("role", "treeitem");
  node.setAttribute("aria-selected", String(graph.selectedId === item.message.entryId));
  node.setAttribute("aria-level", String(graph.depths.get(item.message.entryId)));
  if (item.message.entryId === graph.leafId) node.setAttribute("aria-current", "true");
  node.tabIndex = graph.selectedId === item.message.entryId ? 0 : -1;
  node.style.transform = `translate(${item.x}px, ${item.y}px)`;
  node.title = item.message.text || item.message.thought || "空消息";
  const meta = element("span", "ct-node-meta");
  meta.append(document.createTextNode(item.message.role === "user" ? "用户" : "Agent"));
  if (item.message.entryId === graph.leafId) meta.append(element("i", "", "当前"));
  node.append(meta, element("strong", "", shortText(item.message.text || item.message.thought)), element("small", "", formatTime(item.message.timestamp)));
  node.addEventListener("click", () => actions.select(item.message.entryId));
  node.addEventListener("keydown", (event) => actions.key(event, item.message.entryId));
  return node;
}

export function applyTransform(controls, state) {
  controls.stage.style.transform = `translate(${state.view.x}px, ${state.view.y}px) scale(${state.view.scale})`;
  controls.reset.textContent = `${Math.round(state.view.scale * 100)}%`;
  controls.minus.disabled = state.view.scale <= MIN_SCALE || !state.context.visible;
  controls.plus.disabled = state.view.scale >= MAX_SCALE || !state.context.visible;
}

function renderGraph({ controls, state, graph, actions }) {
  controls.stage.replaceChildren();
  if (!graph?.visible.length) {
    setHidden(controls.canvas, true);
    return;
  }
  setHidden(controls.canvas, false);
  const width = Math.max(graph.layout.width, MIN_STAGE_WIDTH);
  const height = Math.max(graph.layout.height, MIN_STAGE_HEIGHT);
  controls.stage.style.width = `${width}px`;
  controls.stage.style.height = `${height}px`;
  controls.stage.append(renderLinks(graph, width, height));
  for (const item of graph.positioned) controls.stage.append(renderNode({ item, graph, state, actions }));
  applyTransform(controls, state);
}

function tag(text, current = false) {
  return element("span", `ct-tag${current ? " is-current" : ""}`, text);
}

function pills(label, values) {
  const row = element("div", "ct-pills");
  row.append(element("strong", "", label));
  for (const value of values) row.append(tag(value));
  return row;
}

function renderKnownContext(container, value) {
  container.append(factList("", [
    ["模型", displayValue(value.model)],
    ["模式", displayValue(value.mode)],
    ["Thinking", displayValue(value.thinking)],
    ["已知字符", value.characters.toLocaleString("zh-CN")],
    ["Token", value.tokens ?? "未提供"],
  ]));
  if (value.references.length) container.append(pills("引用", value.references));
  if (value.commands.length) container.append(element("div", "ct-context-note", `可用命令：${value.commands.join("、")}`));
  container.append(element("div", "ct-context-note", "这里只展示 xSec 已记录的消息、配置与引用；Provider 内部隐藏上下文可能不在其中。"));
}

function renderInspectorContext(container, inspector) {
  if (inspector.status === "error") {
    container.append(element("div", "ct-notice is-error", `读取节点上下文失败：${inspector.message}`));
    return;
  }
  renderKnownContext(container, inspector.value);
}

function navigationButton({ state, graph, selected, actions }) {
  const isCurrent = selected.selected.entryId === graph.leafId;
  const label = isCurrent ? "当前分支" : "切换到此分支";
  const action = button("ct-action", state.navigating ? "正在切换…" : label);
  const blocked = selected.navigationBlock;
  action.disabled = isCurrent || Boolean(blocked) || state.loading || state.navigating;
  action.title = isCurrent ? "该节点已是当前分支" : blocked ?? "精确切换到所选分支";
  action.addEventListener("click", () => actions.navigate(selected.selected.entryId));
  return action;
}

function renderInspector({ controls, state, graph, selected, actions }) {
  controls.inspector.replaceChildren();
  setHidden(controls.inspector, !selected);
  if (!selected) return;
  const header = element("header");
  const tags = element("span", "ct-tags");
  tags.append(tag(selected.selected.role === "user" ? "用户" : "Agent"));
  if (selected.selected.entryId === graph.leafId) tags.append(tag("当前分支", true));
  header.append(tags, navigationButton({ state, graph, selected, actions }));
  const preview = element("p", "ct-preview", selected.selected.text || selected.selected.thought || "（空消息）");
  const facts = factList("ct-facts", [
    ["路径", `${selected.path.length} 个消息节点`],
    ["时间", formatTime(selected.selected.timestamp, true)],
    ["节点", selected.selected.entryId.slice(0, 12), selected.selected.entryId],
  ]);
  const toggle = button("ct-context-toggle", `${state.contextExpanded ? "⌄" : "›"}  已知上下文`);
  toggle.disabled = !state.context.visible;
  toggle.setAttribute("aria-expanded", String(state.contextExpanded));
  toggle.addEventListener("click", actions.context);
  const context = element("div", "ct-context");
  setHidden(context, !state.contextExpanded);
  renderInspectorContext(context, selected.inspector);
  controls.inspector.append(header, preview, facts, toggle, context);
}

export function renderView({ controls, state, graph, selected, actions }) {
  controls.shell.inert = !state.context.visible;
  renderHeader(controls, state);
  renderEmpty(controls, state, graph);
  controls.summary.textContent = graph ? `${graph.visible.length} 个可见节点 · 全树 ${graph.messages.length} 个节点` : "";
  setHidden(controls.summary, !graph);
  controls.search.disabled = !graph || !state.context.visible;
  controls.all.disabled = !graph || !state.context.visible;
  controls.active.disabled = !graph || !state.context.visible;
  controls.checkbox.disabled = !graph || !state.context.visible;
  renderGraph({ controls, state, graph, actions });
  renderInspector({ controls, state, graph, selected, actions });
}

export function renderFatal(controls, message) {
  controls.notice.textContent = message;
  controls.notice.className = "ct-notice is-error";
  setHidden(controls.notice, false);
  setHidden(controls.canvas, true);
  setHidden(controls.inspector, true);
  setHidden(controls.empty, true);
}
