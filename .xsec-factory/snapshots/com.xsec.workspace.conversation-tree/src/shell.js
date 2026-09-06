import { button, element } from "./elements.js";

function buildToolbar(actions) {
  const toolbar = element("header", "ct-toolbar");
  const title = element("span", "ct-title");
  title.append(element("strong", "", "对话树"), element("small", "", "真实 Provider 消息树"));
  const badge = element("span", "ct-badge", "待加载");
  const refresh = button("ct-icon-button", "↻", "读取对话树");
  refresh.title = "显式读取当前会话的完整对话树";
  refresh.addEventListener("click", actions.load);
  toolbar.append(title, badge, refresh);
  return { toolbar, badge, refresh };
}

function buildFilters(actions) {
  const filters = element("div", "ct-filters");
  const search = element("input", "ct-search");
  search.type = "search";
  search.placeholder = "搜索节点";
  search.setAttribute("aria-label", "搜索对话树节点");
  search.addEventListener("input", () => actions.query(search.value));
  const segments = element("div", "ct-segments");
  segments.setAttribute("role", "group");
  segments.setAttribute("aria-label", "对话树范围");
  const all = button("", "全部");
  const active = button("", "当前路径");
  all.addEventListener("click", () => actions.mode("all"));
  active.addEventListener("click", () => actions.mode("active"));
  segments.append(all, active);
  filters.append(search, segments);
  const role = element("label", "ct-role-filter");
  const checkbox = element("input");
  checkbox.type = "checkbox";
  checkbox.addEventListener("change", () => actions.agents(checkbox.checked));
  role.append(checkbox, document.createTextNode("显示 Agent 节点"));
  return { filters, search, all, active, role, checkbox };
}

function buildCanvas(actions) {
  const canvas = element("div", "ct-canvas");
  canvas.setAttribute("role", "tree");
  canvas.setAttribute("aria-label", "对话节点");
  canvas.tabIndex = -1;
  const stage = element("div", "ct-stage");
  const zoom = element("div", "ct-zoom");
  zoom.setAttribute("data-tree-control", "");
  const minus = button("", "−", "缩小对话树");
  const reset = button("", "85%", "定位当前路径");
  const plus = button("", "+", "放大对话树");
  minus.addEventListener("click", () => actions.zoom(-0.1));
  reset.addEventListener("click", actions.reset);
  plus.addEventListener("click", () => actions.zoom(0.1));
  zoom.append(minus, reset, plus);
  canvas.append(stage, zoom);
  canvas.addEventListener("pointerdown", actions.pointerDown);
  canvas.addEventListener("pointermove", actions.pointerMove);
  canvas.addEventListener("pointerup", actions.pointerUp);
  canvas.addEventListener("pointercancel", actions.pointerUp);
  canvas.addEventListener("wheel", actions.wheel, { passive: false });
  return { canvas, stage, minus, reset, plus };
}

function buildEmpty(actions) {
  const empty = element("section", "ct-empty");
  const emptyTitle = element("strong");
  const emptyDetail = element("span");
  const load = button("ct-action", "加载完整对话树");
  load.addEventListener("click", actions.load);
  empty.append(emptyTitle, emptyDetail, load);
  return { empty, emptyTitle, emptyDetail, load };
}

export function createShell(root, actions) {
  const shell = element("section", "ct-root");
  shell.setAttribute("aria-label", "对话树");
  const toolbar = buildToolbar(actions);
  const filters = buildFilters(actions);
  const notice = element("div", "ct-notice");
  notice.setAttribute("role", "status");
  const summary = element("div", "ct-summary");
  const empty = buildEmpty(actions);
  const canvas = buildCanvas(actions);
  const inspector = element("article", "ct-inspector");
  shell.append(toolbar.toolbar, filters.filters, filters.role, notice, summary, empty.empty, canvas.canvas, inspector);
  root.replaceChildren(shell);
  return { shell, notice, summary, inspector, ...toolbar, ...filters, ...empty, ...canvas };
}
