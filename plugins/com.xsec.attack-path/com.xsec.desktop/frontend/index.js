const TREE_METHOD = "xsec.attack-path.tree.list";
const SUBAGENTS_METHOD = "xsec.attack-path.subagents.list";
const OPEN_TOOL_METHOD = "xsec.workspace.tool.open";
const NODE_WIDTH = 130;
const NODE_HEIGHT = 58;
const X_GAP = 150;
const Y_GAP = 120;
const ROOT_GAP = 80;
const PADDING = 80;
const MIN_SCALE = 0.45;
const MAX_SCALE = 1.8;
const POLL_INTERVAL_MS = 2000;
const SVG_NS = "http://www.w3.org/2000/svg";

export function layoutTreeNodes(nodes, rootId) {
  const positions = new Map();
  if (!nodes.length) return { positions, width: 0, height: 0 };
  const nodeIds = new Set(nodes.map((node) => node.id));
  const children = new Map();
  for (const node of nodes) {
    if (!node.parent_id || !nodeIds.has(node.parent_id)) continue;
    children.set(node.parent_id, [...(children.get(node.parent_id) ?? []), node]);
  }
  const roots = nodes.filter((node) => !node.parent_id || !nodeIds.has(node.parent_id));
  const preferredRoot = nodes.find((node) => node.id === rootId);
  if (preferredRoot) {
    const index = roots.findIndex((node) => node.id === preferredRoot.id);
    if (index > 0) roots.unshift(...roots.splice(index, 1));
  }
  let leaf = 0;
  const visited = new Set();
  const place = (node, depth) => {
    if (visited.has(node.id)) return PADDING + NODE_WIDTH / 2;
    visited.add(node.id);
    const kids = children.get(node.id) ?? [];
    const center = kids.length
      ? kids.reduce((sum, child) => sum + place(child, depth + 1), 0) / kids.length
      : PADDING + NODE_WIDTH / 2 + leaf++ * X_GAP;
    positions.set(node.id, { x: center - NODE_WIDTH / 2, y: PADDING + depth * Y_GAP });
    return center;
  };
  const placeRoot = (root) => {
    if (visited.has(root.id)) return;
    place(root, 0);
    leaf += ROOT_GAP / X_GAP;
  };
  roots.forEach(placeRoot);
  nodes.forEach(placeRoot);
  let maxX = 0;
  let maxY = 0;
  positions.forEach((position) => {
    maxX = Math.max(maxX, position.x + NODE_WIDTH);
    maxY = Math.max(maxY, position.y + NODE_HEIGHT);
  });
  return { positions, width: maxX + PADDING, height: maxY + PADDING };
}

export function nodeKind(node, rootId) {
  if (!node.parent_id || node.parent_id === rootId) return "task";
  if (node.status === "vuln" || node.kind === "vuln") return "finding";
  return "action";
}

export function graphModel(nodes, subagents) {
  const rootId = nodes.find((node) => !node.parent_id)?.id;
  const layout = layoutTreeNodes(nodes, rootId);
  const positioned = nodes.map((node) => ({
    node,
    ...(layout.positions.get(node.id) ?? { x: PADDING, y: PADDING }),
  }));
  const positions = new Map(positioned.map((position) => [position.node.id, position]));
  const subagentsByNode = new Map();
  for (const subagent of subagents) {
    if (subagent.node_id) subagentsByNode.set(subagent.node_id, subagent);
  }
  for (const node of nodes) {
    if (!node.subagent_id || subagentsByNode.has(node.id)) continue;
    const subagent = subagents.find((candidate) => candidate.id === node.subagent_id);
    if (subagent) subagentsByNode.set(node.id, subagent);
  }
  const counts = { task: 0, action: 0, finding: 0 };
  for (const node of nodes) {
    if (node.parent_id) counts[nodeKind(node, rootId)] += 1;
  }
  return {
    rootId,
    layout,
    positioned,
    positions,
    subagentsByNode,
    counts,
    stage: { width: Math.max(layout.width, 900), height: Math.max(layout.height, 520) },
  };
}

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function clampScale(scale) {
  return Math.min(MAX_SCALE, Math.max(MIN_SCALE, scale));
}

function displayIds(nodes, rootId) {
  const sequence = { task: 0, action: 0, finding: 0 };
  const ids = new Map();
  for (const node of nodes) {
    if (!node.parent_id) {
      ids.set(node.id, "Root");
      continue;
    }
    const kind = nodeKind(node, rootId);
    ids.set(node.id, `${kind[0].toUpperCase()}${kind.slice(1)}_${String(++sequence[kind]).padStart(3, "0")}`);
  }
  return ids;
}

function contextAssignmentId(context) {
  return context?.workspace?.binding?.assignmentId ?? null;
}

function contextVisible(context) {
  return context?.visible !== false;
}

function installStyles() {
  if (document.getElementById("xsec-attack-path-styles")) return;
  const style = document.createElement("style");
  style.id = "xsec-attack-path-styles";
  style.textContent = `
    :root{color-scheme:dark;font-family:var(--xsec-font-family,Inter,"Segoe UI",sans-serif)}
    :root[data-xsec-theme="light"]{color-scheme:light}*{box-sizing:border-box}
    html,body,[data-xsec-plugin-root]{width:100%;height:100%;margin:0;overflow:hidden}button{font:inherit}
    .ap-root{display:flex;width:100%;height:100%;min-width:0;min-height:280px;flex-direction:column;background:#080b10;color:#d6deeb}
    .ap-head{display:flex;min-height:42px;align-items:center;gap:14px;padding:8px 12px;border-bottom:1px solid #232936;background:#0c1018}
    .ap-title{font-size:13px;font-weight:650;white-space:nowrap}.ap-legend{display:flex;min-width:0;align-items:center;gap:6px;margin-left:auto;color:#8b94a7;font-size:11px;white-space:nowrap}.ap-legend b{margin-right:6px;color:#e6e9ef}
    .ap-dot{width:8px;height:8px;border-radius:50%}.ap-dot.task{background:#5b74ff}.ap-dot.action{background:#2ecc9b}.ap-dot.finding{background:#f0a935}
    .ap-controls{display:flex;flex:0 0 auto;gap:4px}.ap-controls button{height:26px;min-width:28px;padding:0 7px;border:1px solid #293144;border-radius:6px;background:#101522;color:#d6deeb;cursor:pointer}.ap-controls button:hover{border-color:#536382;background:#171e2e}
    .ap-status{display:none;max-width:46%;overflow:hidden;padding:4px 8px;border:1px solid rgba(245,163,163,.35);border-radius:6px;background:#2b1118;color:#f5a3a3;font-size:11px;text-overflow:ellipsis;white-space:nowrap}.ap-status.show{display:block}
    .ap-canvas{position:relative;min-height:0;flex:1;overflow:hidden;cursor:grab;touch-action:none;background:radial-gradient(circle at 50% 8%,rgba(91,116,255,.07),transparent 34%),#080b10}.ap-canvas.dragging{cursor:grabbing}
    .ap-stage{position:absolute;top:0;left:0;transform-origin:0 0}.ap-links{position:absolute;top:0;left:0;overflow:visible;pointer-events:none}.ap-link{fill:none;stroke:#344057;stroke-width:1.25;stroke-linecap:round;stroke-dasharray:7 8;animation:ap-flow 1.2s linear infinite}.ap-link.task{stroke:#5b74ff}.ap-link.action{stroke:#2ecc9b}.ap-link.finding{stroke:#f0a935}
    .ap-node{position:absolute;top:0;left:0;width:130px;min-height:58px;padding:13px 10px 8px;border:1px solid #232936;border-radius:8px;background:#12151c;color:#d6deeb;cursor:pointer;text-align:center;user-select:none;transition:border-color .12s,background .12s,outline-color .12s}.ap-node:hover{border-color:#52617d}.ap-node.no-agent{cursor:default;opacity:.78}
    .ap-node .ap-chip{position:absolute;top:-9px;left:10px;padding:1px 7px;border-radius:5px;color:#fff;font-size:10px;font-weight:700}.ap-node .ap-node-title{display:-webkit-box;overflow:hidden;font-size:12.5px;font-weight:600;line-height:1.35;-webkit-box-orient:vertical;-webkit-line-clamp:2}.ap-node .ap-id{display:block;margin-top:2px;color:#8b94a7;font-size:10.5px}.ap-node .ap-reason{display:block;overflow:hidden;margin-top:2px;color:#ffb86b;font-size:9.5px;text-overflow:ellipsis;white-space:nowrap}
    .ap-node.task{border-color:rgba(91,116,255,.5);background:rgba(91,116,255,.12)}.ap-node.task .ap-chip{background:#3f51c7}.ap-node.action{border-color:rgba(46,204,155,.45);background:rgba(46,204,155,.1)}.ap-node.action .ap-chip{background:#16765f}.ap-node.finding{border-color:rgba(240,169,53,.45);background:rgba(240,169,53,.1)}.ap-node.finding .ap-chip{background:#9a5d00}.ap-node.selected{outline:2px solid #5b74ff;outline-offset:2px}
    .ap-empty{display:grid;height:100%;place-content:center;justify-items:center;gap:10px;padding:28px;color:#8b94a7;text-align:center}.ap-empty strong{color:#d6deeb;font-size:14px}.ap-empty span{max-width:320px;font-size:12px;line-height:1.6}.ap-loading{width:28px;height:28px;border:2px solid #293144;border-top-color:#5b74ff;border-radius:50%;animation:ap-spin .8s linear infinite}
    @keyframes ap-flow{to{stroke-dashoffset:-15}}@keyframes ap-spin{to{transform:rotate(360deg)}}@media (prefers-reduced-motion:reduce){.ap-link,.ap-loading{animation:none}}@media (max-width:520px){.ap-head{align-items:flex-start;flex-wrap:wrap}.ap-legend{order:3;width:100%;margin-left:0}.ap-status{max-width:100%}}
    :root[data-xsec-theme="light"] .ap-root{background:#f7f8fb;color:#202737}:root[data-xsec-theme="light"] .ap-head{border-color:#dde2ea;background:#fff}:root[data-xsec-theme="light"] .ap-canvas{background:radial-gradient(circle at 50% 8%,rgba(74,103,255,.08),transparent 34%),#f7f8fb}:root[data-xsec-theme="light"] .ap-title,:root[data-xsec-theme="light"] .ap-legend b,:root[data-xsec-theme="light"] .ap-empty strong{color:#202737}:root[data-xsec-theme="light"] .ap-controls button{border-color:#d7dce5;background:#fff;color:#35405a}:root[data-xsec-theme="light"] .ap-node{color:#202737}:root[data-xsec-theme="light"] .ap-node .ap-id{color:#667085}
  `;
  document.head.append(style);
}

function createController(host) {
  let root = null;
  let assignmentId = null;
  let visible = true;
  let disposed = false;
  let loading = false;
  let requestGeneration = 0;
  let pollTimer = null;
  let resizeObserver = null;
  let nodes = [];
  let subagents = [];
  let model = graphModel([], []);
  let resetKey = "";
  let selectedSubagentId = null;
  let view = { x: 32, y: 40, scale: 1 };
  let drag = null;
  let legend = null;
  let status = null;
  let canvas = null;
  let zoomLabel = null;

  const applyTheme = (theme) => {
    document.documentElement.dataset.xsecTheme = theme?.["color-mode"] === "light" ? "light" : "dark";
  };
  applyTheme({ "color-mode": getComputedStyle(document.documentElement).getPropertyValue("--xsec-color-mode").trim() });
  const themeSubscription = host.onTheme(applyTheme);

  const showStatus = (message) => {
    if (!status) return;
    status.textContent = message ?? "";
    status.classList.toggle("show", Boolean(message));
    status.title = message ?? "";
  };
  const applyTransform = () => {
    const stage = canvas?.querySelector(".ap-stage");
    if (stage) stage.style.transform = `translate(${view.x}px,${view.y}px) scale(${view.scale})`;
    if (zoomLabel) zoomLabel.textContent = `${Math.round(view.scale * 100)}%`;
  };
  const resetView = () => {
    if (!canvas || !model.rootId) return;
    const rootPosition = model.positions.get(model.rootId);
    if (!rootPosition) return;
    const rect = canvas.getBoundingClientRect();
    view = { x: rect.width / 2 - rootPosition.x - NODE_WIDTH / 2, y: 36 - rootPosition.y, scale: 1 };
    applyTransform();
  };
  const zoomTo = (nextScale, origin) => {
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const focus = origin ?? { x: rect.width / 2, y: rect.height / 2 };
    const scale = clampScale(nextScale);
    const worldX = (focus.x - view.x) / view.scale;
    const worldY = (focus.y - view.y) / view.scale;
    view = { scale, x: focus.x - worldX * scale, y: focus.y - worldY * scale };
    applyTransform();
  };
  const renderEmpty = (title, description, spinner = false) => {
    if (!canvas) return;
    const empty = element("div", "ap-empty");
    if (spinner) empty.append(element("span", "ap-loading"));
    empty.append(element("strong", "", title), element("span", "", description));
    canvas.replaceChildren(empty);
    legend?.replaceChildren();
  };
  const openSubagent = async (subagent, title, button) => {
    if (!subagent?.id) return;
    selectedSubagentId = subagent.id;
    canvas?.querySelectorAll(".ap-node").forEach((node) => {
      node.classList.remove("selected");
      node.setAttribute("aria-pressed", "false");
    });
    button.classList.add("selected");
    button.setAttribute("aria-pressed", "true");
    try {
      await host.request(OPEN_TOOL_METHOD, {
        pluginId: "com.xsec.workspace.sub-agent",
        toolId: "subagent-detail",
        entityId: subagent.id,
        title: title || subagent.role || "子 Agent 详情",
      });
      showStatus(null);
    } catch (error) {
      showStatus(`无法打开子 Agent：${error instanceof Error ? error.message : String(error)}`);
    }
  };

  const renderGraph = () => {
    if (!canvas) return;
    if (!assignmentId) {
      renderEmpty("攻击路径尚未绑定任务", "Agent 派发子任务后，这里会显示路径、节点和子 Agent 状态。");
      return;
    }
    if (!nodes.length) {
      renderEmpty("暂无攻击路径节点", "主 Agent 创建测试节点并派发子任务后会自动更新。");
      return;
    }
    model = graphModel(nodes, subagents);
    const ids = displayIds(nodes, model.rootId);
    legend.replaceChildren();
    for (const kind of ["task", "action", "finding"]) {
      legend.append(element("i", `ap-dot ${kind}`), document.createTextNode(`${kind[0].toUpperCase()}${kind.slice(1)} `), element("b", "", String(model.counts[kind])));
    }
    const stage = element("div", "ap-stage");
    stage.style.width = `${model.stage.width}px`;
    stage.style.height = `${model.stage.height}px`;
    const svg = document.createElementNS(SVG_NS, "svg");
    svg.setAttribute("class", "ap-links");
    svg.setAttribute("width", String(model.stage.width));
    svg.setAttribute("height", String(model.stage.height));
    for (const node of nodes) {
      if (!node.parent_id) continue;
      const parent = model.positions.get(node.parent_id);
      const child = model.positions.get(node.id);
      if (!parent || !child) continue;
      const sx = parent.x + NODE_WIDTH / 2;
      const sy = parent.y + NODE_HEIGHT;
      const ex = child.x + NODE_WIDTH / 2;
      const ey = child.y;
      const mid = sy + Math.max(32, (ey - sy) / 2);
      const path = document.createElementNS(SVG_NS, "path");
      path.setAttribute("class", `ap-link ${nodeKind(node, model.rootId)}`);
      path.setAttribute("d", `M ${sx} ${sy} C ${sx} ${mid}, ${ex} ${mid}, ${ex} ${ey}`);
      svg.append(path);
    }
    stage.append(svg);
    for (const position of model.positioned) {
      const node = position.node;
      const kind = nodeKind(node, model.rootId);
      const subagent = model.subagentsByNode.get(node.id);
      const selected = selectedSubagentId === subagent?.id;
      const button = element("button", `ap-node ${kind}${subagent ? "" : " no-agent"}${selected ? " selected" : ""}`);
      button.type = "button";
      button.style.transform = `translate(${position.x}px,${position.y}px)`;
      button.setAttribute("aria-label", `${kind} 节点：${node.title}`);
      button.setAttribute("aria-pressed", String(selected));
      if (!subagent) button.setAttribute("aria-disabled", "true");
      const reason = subagent?.status_reason ? `\n原因: ${subagent.status_reason}` : "";
      button.title = subagent ? `状态: ${subagent.status}${reason}` : "尚未派发子 Agent";
      button.append(element("span", "ap-chip", `${kind[0].toUpperCase()}${kind.slice(1)}`), element("span", "ap-node-title", node.title), element("span", "ap-id", ids.get(node.id) ?? node.id));
      if (subagent?.status_reason) button.append(element("span", "ap-reason", subagent.status_reason));
      if (subagent) button.addEventListener("click", () => void openSubagent(subagent, node.title, button));
      stage.append(button);
    }
    canvas.replaceChildren(stage);
    const nextResetKey = `${assignmentId}:${model.rootId ?? ""}:${nodes.length}`;
    if (nextResetKey !== resetKey) {
      resetKey = nextResetKey;
      requestAnimationFrame(resetView);
    } else applyTransform();
  };

  const load = async () => {
    if (disposed || loading || !visible || !assignmentId) return;
    loading = true;
    const generation = ++requestGeneration;
    if (!nodes.length) renderEmpty("正在读取攻击路径", "正在同步节点与子 Agent 状态…", true);
    try {
      const [treeResult, subagentResult] = await Promise.all([host.request(TREE_METHOD, {}), host.request(SUBAGENTS_METHOD, {})]);
      if (disposed || generation !== requestGeneration) return;
      nodes = Array.isArray(treeResult?.nodes) ? treeResult.nodes : [];
      subagents = Array.isArray(subagentResult?.subagents) ? subagentResult.subagents : [];
      showStatus(null);
      renderGraph();
    } catch (error) {
      if (disposed || generation !== requestGeneration) return;
      showStatus(error instanceof Error ? error.message : String(error));
      if (!nodes.length) renderEmpty("攻击路径暂时不可用", "读取插件数据失败，稍后会自动重试。");
    } finally {
      if (generation === requestGeneration) loading = false;
    }
  };

  const buildShell = () => {
    installStyles();
    const shell = element("section", "ap-root");
    shell.setAttribute("aria-label", "攻击路径");
    const head = element("header", "ap-head");
    head.append(element("span", "ap-title", "攻击路径"));
    status = element("span", "ap-status");
    status.setAttribute("role", "status");
    legend = element("span", "ap-legend");
    const controls = element("span", "ap-controls");
    const zoomOut = element("button", "", "−");
    zoomOut.type = "button";
    zoomOut.title = "缩小";
    zoomOut.setAttribute("aria-label", "缩小攻击路径");
    zoomOut.addEventListener("click", () => zoomTo(view.scale - 0.1));
    zoomLabel = element("button", "", "100%");
    zoomLabel.type = "button";
    zoomLabel.title = "重置视图";
    zoomLabel.setAttribute("aria-label", "重置攻击路径视图");
    zoomLabel.addEventListener("click", resetView);
    const zoomIn = element("button", "", "+");
    zoomIn.type = "button";
    zoomIn.title = "放大";
    zoomIn.setAttribute("aria-label", "放大攻击路径");
    zoomIn.addEventListener("click", () => zoomTo(view.scale + 0.1));
    controls.append(zoomOut, zoomLabel, zoomIn);
    head.append(status, legend, controls);
    canvas = element("div", "ap-canvas");
    canvas.addEventListener("wheel", (event) => {
      event.preventDefault();
      const rect = canvas.getBoundingClientRect();
      zoomTo(view.scale + (event.deltaY > 0 ? -0.1 : 0.1), { x: event.clientX - rect.left, y: event.clientY - rect.top });
    }, { passive: false });
    canvas.addEventListener("pointerdown", (event) => {
      if (event.button !== 0 || event.target.closest(".ap-node")) return;
      canvas.setPointerCapture(event.pointerId);
      canvas.classList.add("dragging");
      drag = { pointerId: event.pointerId, startX: event.clientX, startY: event.clientY, view: { ...view } };
    });
    canvas.addEventListener("pointermove", (event) => {
      if (!drag || drag.pointerId !== event.pointerId) return;
      view = { ...drag.view, x: drag.view.x + event.clientX - drag.startX, y: drag.view.y + event.clientY - drag.startY };
      applyTransform();
    });
    const stopDrag = (event) => {
      if (!drag || drag.pointerId !== event.pointerId) return;
      if (canvas.hasPointerCapture(event.pointerId)) canvas.releasePointerCapture(event.pointerId);
      canvas.classList.remove("dragging");
      drag = null;
    };
    canvas.addEventListener("pointerup", stopDrag);
    canvas.addEventListener("pointercancel", stopDrag);
    shell.append(head, canvas);
    root.replaceChildren(shell);
    resizeObserver = typeof ResizeObserver === "function" ? new ResizeObserver(() => applyTransform()) : null;
    resizeObserver?.observe(canvas);
  };

  const updateContext = (context) => {
    const nextAssignmentId = contextAssignmentId(context);
    const assignmentChanged = nextAssignmentId !== assignmentId;
    visible = contextVisible(context);
    assignmentId = nextAssignmentId;
    if (assignmentChanged) {
      requestGeneration += 1;
      loading = false;
      nodes = [];
      subagents = [];
      selectedSubagentId = null;
      resetKey = "";
    }
    renderGraph();
    if (visible) void load();
  };

  return {
    async mount(nextRoot, initialContext) {
      root = nextRoot;
      buildShell();
      updateContext(initialContext);
      pollTimer = window.setInterval(() => void load(), POLL_INTERVAL_MS);
    },
    async update(nextContext) {
      updateContext(nextContext);
    },
    async dispose() {
      disposed = true;
      requestGeneration += 1;
      if (pollTimer !== null) window.clearInterval(pollTimer);
      resizeObserver?.disconnect();
      themeSubscription.dispose();
      root?.replaceChildren();
    },
  };
}

export function activate(host) {
  return createController(host);
}
