const LIST_METHOD = "xsec.subagents.list";
const GET_METHOD = "xsec.subagents.get";
const OPEN_TOOL_METHOD = "xsec.workspace.tool.open";
const POLL_INTERVAL_MS = 2000;

const STATUS = {
  running: ["运行中", "running", 0],
  starting: ["启动中", "running", 0],
  cancelling: ["取消收口中", "warning", 0],
  dispatched: ["排队中", "default", 1],
  vuln: ["发现漏洞", "vuln", 2],
  failed: ["运行失败", "failed", 2],
  done: ["已完成", "done", 3],
  completed: ["已完成", "done", 3],
  cancelled: ["已取消", "default", 3],
};

export function statusMeta(status) {
  return STATUS[status] ?? [status || "未知", "default", 4];
}

export function sortObservers(rows) {
  return [...rows].sort((left, right) => {
    const rank = statusMeta(left.status)[2] - statusMeta(right.status)[2];
    return rank || right.updated_at - left.updated_at || right.id.localeCompare(left.id);
  });
}

export function formatDuration(startedAt, completedAt, now = Date.now()) {
  if (!startedAt) return "—";
  const start = startedAt < 10_000_000_000 ? startedAt * 1000 : startedAt;
  const rawEnd = completedAt ?? now;
  const end = rawEnd < 10_000_000_000 ? rawEnd * 1000 : rawEnd;
  const seconds = Math.max(0, Math.floor((end - start) / 1000));
  if (seconds < 60) return `${seconds} 秒`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} 分 ${seconds % 60} 秒`;
  return `${Math.floor(minutes / 60)} 小时 ${minutes % 60} 分`;
}

export function formatTime(value) {
  if (!value) return "—";
  return new Date(value < 10_000_000_000 ? value * 1000 : value).toLocaleString("zh-CN", { hour12: false });
}

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function installStyles() {
  if (document.getElementById("xsec-subagent-styles")) return;
  const style = document.createElement("style");
  style.id = "xsec-subagent-styles";
  style.textContent = `
    :root{color-scheme:dark;font-family:var(--xsec-font-family,Inter,"Segoe UI",sans-serif)}:root[data-xsec-theme="light"]{color-scheme:light}*{box-sizing:border-box}html,body,[data-xsec-plugin-root]{width:100%;height:100%;margin:0}body{overflow:hidden}button{font:inherit}
    .sa-root{display:flex;width:100%;height:100%;min-width:0;flex-direction:column;overflow:hidden;background:#0c1018;color:#d6deeb}.sa-head{display:flex;min-height:52px;align-items:center;gap:10px;padding:9px 12px;border-bottom:1px solid #232936;background:#101522}.sa-head-copy{display:grid;min-width:0;gap:2px}.sa-head strong{overflow:hidden;font-size:14px;text-overflow:ellipsis;white-space:nowrap}.sa-head small{color:#8b94a7;font-size:11px}.sa-back{display:grid;width:30px;height:30px;flex:0 0 auto;place-items:center;border:1px solid #293144;border-radius:7px;background:#151b29;color:#d6deeb;cursor:pointer}.sa-back:hover{border-color:#52617d}.sa-body{min-height:0;flex:1;overflow:auto;padding:14px}.sa-summary{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px;margin-bottom:12px}.sa-summary div{display:grid;justify-items:center;gap:3px;padding:10px;border:1px solid #232936;border-radius:8px;background:#121722}.sa-summary strong{font-size:18px}.sa-summary span{color:#8b94a7;font-size:10px}.sa-notice{margin-bottom:12px;padding:8px 10px;border:1px solid rgba(91,116,255,.22);border-radius:7px;background:rgba(91,116,255,.09);color:#9eacff;font-size:11px;line-height:1.5}.sa-list{display:grid;gap:7px}.sa-row{display:grid;width:100%;min-width:0;grid-template-columns:minmax(0,1fr) auto;align-items:center;gap:10px;padding:10px;border:1px solid #232936;border-radius:8px;background:#111620;color:inherit;cursor:pointer;text-align:left}.sa-row:hover{border-color:#52617d;background:#151c2a}.sa-row-copy{display:grid;min-width:0;gap:3px}.sa-row strong,.sa-row small{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.sa-row strong{font-size:12.5px}.sa-row small{color:#8b94a7;font-size:10.5px}.sa-tag{display:inline-flex;min-height:22px;align-items:center;padding:2px 7px;border-radius:999px;background:#252b37;color:#aeb7c7;font-size:10px;white-space:nowrap}.sa-tag.running{background:rgba(91,116,255,.16);color:#9eacff}.sa-tag.warning{background:rgba(240,169,53,.14);color:#f0b959}.sa-tag.vuln,.sa-tag.failed{background:rgba(240,87,87,.14);color:#ff8f8f}.sa-tag.done{background:rgba(46,204,155,.14);color:#69ddb7}.sa-detail-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;margin:0 0 12px}.sa-detail-grid div{min-width:0;padding:10px;border:1px solid #232936;border-radius:8px;background:#111620}.sa-detail-grid dt{margin-bottom:5px;color:#8b94a7;font-size:10px}.sa-detail-grid dd{min-width:0;margin:0;overflow:hidden;font-size:12px;text-overflow:ellipsis;white-space:nowrap}.sa-reason{padding:10px;border:1px solid rgba(240,169,53,.3);border-radius:8px;background:rgba(240,169,53,.09);color:#f0c477;font-size:11px;line-height:1.55}.sa-empty{display:grid;height:100%;place-content:center;justify-items:center;gap:9px;padding:28px;color:#8b94a7;text-align:center}.sa-empty strong{color:#d6deeb;font-size:14px}.sa-empty span{max-width:320px;font-size:12px;line-height:1.6}.sa-spinner{width:28px;height:28px;border:2px solid #293144;border-top-color:#5b74ff;border-radius:50%;animation:sa-spin .8s linear infinite}.sa-error{margin-bottom:10px;padding:8px;border-radius:7px;background:#2b1118;color:#f5a3a3;font-size:11px}@keyframes sa-spin{to{transform:rotate(360deg)}}@media(max-width:480px){.sa-detail-grid{grid-template-columns:1fr}.sa-body{padding:10px}}
    :root[data-xsec-theme="light"] .sa-root{background:#f7f8fb;color:#202737}:root[data-xsec-theme="light"] .sa-head{border-color:#dde2ea;background:#fff}:root[data-xsec-theme="light"] .sa-row,:root[data-xsec-theme="light"] .sa-summary div,:root[data-xsec-theme="light"] .sa-detail-grid div{border-color:#dde2ea;background:#fff}:root[data-xsec-theme="light"] .sa-empty strong{color:#202737}
  `;
  document.head.append(style);
}

function contextValues(context) {
  return {
    visible: context?.visible !== false,
    kind: context?.tool?.kind ?? "sub-agent",
    entityId: context?.tool?.entityId ?? null,
    assignmentId: context?.workspace?.binding?.assignmentId ?? null,
  };
}

function createController(host) {
  let root = null;
  let context = contextValues(null);
  let rows = [];
  let detail = null;
  let error = null;
  let loading = false;
  let generation = 0;
  let timer = null;
  let disposed = false;
  const applyTheme = (theme) => {
    document.documentElement.dataset.xsecTheme = theme?.["color-mode"] === "light" ? "light" : "dark";
  };
  applyTheme({ "color-mode": getComputedStyle(document.documentElement).getPropertyValue("--xsec-color-mode").trim() });
  const themeSubscription = host.onTheme(applyTheme);

  const empty = (title, description, spinner = false) => {
    const node = element("div", "sa-empty");
    if (spinner) node.append(element("span", "sa-spinner"));
    node.append(element("strong", "", title), element("span", "", description));
    return node;
  };

  const open = async (toolId, title, entityId) => {
    try {
      await host.request(OPEN_TOOL_METHOD, { toolId, title, entityId });
      error = null;
    } catch (value) {
      error = value instanceof Error ? value.message : String(value);
      render();
    }
  };

  const renderList = (body) => {
    if (!context.assignmentId) {
      body.append(empty("暂无子 Agent", "当前会话未绑定任务，或主 Agent 尚未派发子任务。"));
      return;
    }
    if (loading && !rows.length) {
      body.append(empty("正在读取子 Agent", "正在同步运行状态…", true));
      return;
    }
    if (!rows.length) {
      body.append(empty("暂无子 Agent", "主 Agent 派发子任务后会出现在这里。"));
      return;
    }
    const active = rows.filter((row) => statusMeta(row.status)[2] === 0).length;
    const summary = element("div", "sa-summary");
    for (const [value, label] of [[rows.length, "全部"], [active, "运行中"], [rows.length - active, "已结束"]]) {
      const item = element("div");
      item.append(element("strong", "", String(value)), element("span", "", label));
      summary.append(item);
    }
    body.append(summary, element("div", "sa-notice", "仅查看，无法人工干预。子 Agent 详情由当前插件独立渲染。"));
    const list = element("div", "sa-list");
    for (const row of rows) {
      const button = element("button", "sa-row");
      button.type = "button";
      button.setAttribute("aria-label", `查看子 Agent ${row.node_title || row.role || row.id}`);
      const copy = element("span", "sa-row-copy");
      copy.append(element("strong", "", row.node_title || row.role || row.id.slice(0, 10)), element("small", "", `${row.role || "sub"}${row.attempt > 1 ? ` · attempt ${row.attempt}` : ""}`), element("small", "", statusMeta(row.status)[2] === 0 ? `已运行 ${formatDuration(row.started_at, null)}` : `结束于 ${formatTime(row.completed_at)}`));
      const meta = statusMeta(row.status);
      button.append(copy, element("span", `sa-tag ${meta[1]}`, meta[0]));
      button.addEventListener("click", () => void open("subagent-detail", row.node_title || row.role || "子 Agent 详情", row.id));
      list.append(button);
    }
    body.append(list);
  };

  const renderDetail = (body) => {
    if (loading && !detail) {
      body.append(empty("正在读取子 Agent", "正在同步运行详情…", true));
      return;
    }
    if (!detail) {
      body.append(empty("子 Agent 不存在", "无法读取对应的子 Agent 记录。"));
      return;
    }
    body.append(element("div", "sa-notice", "此页面由子 Agent 插件只读渲染，不能发送消息、取消、审批或重试。"));
    const grid = element("dl", "sa-detail-grid");
    const fields = [
      ["状态", statusMeta(detail.status)[0]],
      ["运行耗时", formatDuration(detail.started_at, detail.completed_at)],
      ["开始时间", formatTime(detail.started_at)],
      ["最近活动", formatTime(detail.heartbeat_at ?? detail.updated_at)],
      ["运行 ID", detail.runner_run_id || "尚未创建"],
      ["ACP 会话", detail.acp_session_id || "尚未注册"],
    ];
    for (const [label, value] of fields) {
      const item = element("div");
      item.append(element("dt", "", label), element("dd", "", value));
      item.querySelector("dd").title = value;
      grid.append(item);
    }
    body.append(grid);
    if (detail.status_reason) body.append(element("div", "sa-reason", detail.status_reason));
  };

  const render = () => {
    if (!root) return;
    const shell = element("section", "sa-root");
    shell.setAttribute("aria-label", context.kind === "subagent-detail" ? "子 Agent 运行详情" : "子 Agent");
    const head = element("header", "sa-head");
    const copy = element("span", "sa-head-copy");
    const title = context.kind === "subagent-detail" ? detail?.node_title || detail?.role || "子 Agent 详情" : "子 Agent";
    const subtitle = context.kind === "subagent-detail" && detail ? `${detail.role || "sub"} · attempt ${detail.attempt}` : "攻击路径关联运行";
    copy.append(element("strong", "", title), element("small", "", subtitle));
    head.append(copy);
    const body = element("div", "sa-body");
    if (error) body.append(element("div", "sa-error", error));
    if (context.kind === "subagent-detail") renderDetail(body);
    else renderList(body);
    shell.append(head, body);
    root.replaceChildren(shell);
  };

  const load = async () => {
    if (disposed || loading || !context.visible) return;
    if (context.kind === "subagent-detail" && !context.entityId) {
      detail = null;
      render();
      return;
    }
    if (context.kind !== "subagent-detail" && !context.assignmentId) {
      rows = [];
      render();
      return;
    }
    loading = true;
    const request = ++generation;
    render();
    try {
      if (context.kind === "subagent-detail") {
        const nextDetail = await host.request(GET_METHOD, { subagentId: context.entityId });
        if (request !== generation || disposed) return;
        detail = nextDetail;
      } else {
        const result = await host.request(LIST_METHOD, {});
        if (request !== generation || disposed) return;
        rows = sortObservers(Array.isArray(result?.subagents) ? result.subagents : []);
      }
      error = null;
    } catch (value) {
      if (request !== generation || disposed) return;
      error = value instanceof Error ? value.message : String(value);
    } finally {
      if (request === generation) {
        loading = false;
        render();
      }
    }
  };

  const update = (nextContext) => {
    const next = contextValues(nextContext);
    const bindingChanged = next.kind !== context.kind || next.entityId !== context.entityId || next.assignmentId !== context.assignmentId;
    context = next;
    if (bindingChanged) {
      generation += 1;
      loading = false;
      rows = [];
      detail = null;
      error = null;
    }
    render();
    if (context.visible) void load();
  };

  return {
    async mount(nextRoot, initialContext) {
      root = nextRoot;
      installStyles();
      update(initialContext);
      timer = window.setInterval(() => void load(), POLL_INTERVAL_MS);
    },
    async update(nextContext) {
      update(nextContext);
    },
    async dispose() {
      disposed = true;
      generation += 1;
      if (timer !== null) window.clearInterval(timer);
      themeSubscription.dispose();
      root?.replaceChildren();
    },
  };
}

export function activate(host) {
  return createController(host);
}
