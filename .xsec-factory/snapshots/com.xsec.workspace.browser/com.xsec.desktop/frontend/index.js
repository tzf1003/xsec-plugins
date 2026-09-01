const FRAME_HEADER = "XSBF", EVENT_HEADER = "XSBE"; const PAGE_POLL_MS = 1000, LIVE_SESSION_POLL_MS = 2000, CLOSED_SESSION_POLL_MS = 5000;
const NEW_PAGE_GRACE_MS = 5000, POINTER_MOVE_MS = 33, FRAME_ACK_INTERVAL_MS = 40, VIEWPORT_WIDTH = 1280, VIEWPORT_HEIGHT = 800, NO_MOUSE_BUTTONS = 0, MOUSE_BUTTON_MASKS = [1, 4, 2, 8, 16];
const element = (tag, className, value) => { const node = document.createElement(tag); if (className) node.className = className; if (value !== undefined) node.textContent = value; return node; };
function errorText(value) { return value instanceof Error ? value.message : String(value); }
function items(value, label) { if (Array.isArray(value)) return value; if (Array.isArray(value?.items)) return value.items; throw new Error(`${label}响应格式无效`); }
function displayUrl(url) { if (!url || url === "about:blank") return "新标签页"; try { return new URL(url).hostname || url; } catch { return url; } }
function pageLabel(page) { return page.title?.trim() || displayUrl(page.url); }
function normalizeUrl(value) {
  const source = value.trim(); if (!source) throw new Error("请输入地址");
  const hostPort = /^[^/:?#]+:\d+(?:[/?#]|$)/.test(source);
  const url = new URL(hostPort || !/^[a-z][a-z\d+.-]*:/i.test(source) ? `https://${source}` : source);
  if (!/^https?:$/.test(url.protocol)) throw new Error("只允许 HTTP 或 HTTPS 地址"); return url.toString();
}
function packetHeader(raw) { const bytes = new Uint8Array(raw); return String.fromCharCode(...bytes.subarray(0, 4)); }
function parseEvent(raw) {
  if (packetHeader(raw) !== EVENT_HEADER) return undefined;
  const bytes = new Uint8Array(raw);
  if (bytes.byteLength <= 4) throw new Error("浏览器画面事件无效");
  const event = JSON.parse(new TextDecoder().decode(bytes.subarray(4)));
  if (!event || !["started", "closed", "error"].includes(event.kind)) throw new Error("浏览器画面事件无效");
  return event;
}
function parseFrame(raw) {
  if (packetHeader(raw) !== FRAME_HEADER) return undefined;
  const bytes = new Uint8Array(raw);
  if (bytes.byteLength <= 16) throw new Error("浏览器画面帧无效");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const width = view.getUint32(8, true);
  const height = view.getUint32(12, true);
  if (!width || !height) throw new Error("浏览器画面尺寸无效");
  return { width, height, jpeg: bytes.slice(16).buffer };
}
function eventModifiers(event) { return (event.altKey ? 1 : 0) | (event.ctrlKey ? 2 : 0) | (event.metaKey ? 4 : 0) | (event.shiftKey ? 8 : 0); }
function mouseButton(button) { return ["left", "middle", "right", "back", "forward"][button] || "none"; } function mouseButtonMask(button) { return MOUSE_BUTTON_MASKS[button] || NO_MOUSE_BUTTONS; }
function mouseButtonReleases(buttons, point, modifiers) { let remaining = buttons; return MOUSE_BUTTON_MASKS.flatMap((mask, index) => { if (!(buttons & mask)) return []; remaining &= ~mask; return [{ kind: "mouse", event_type: "up", ...point, button: mouseButton(index), buttons: remaining, modifiers }]; }); }
function pageAfterClose(pages, id) { const index = pages.findIndex((page) => page.id === id); return index < 0 ? null : pages[index + 1]?.id || pages[index - 1]?.id || null; }
function selectSession(sessions, currentId, runId, userSelected) {
  const current = sessions.find((session) => session.id === currentId);
  if (current && (userSelected || current.live)) return current.id;
  return sessions.find((session) => session.live && (!runId || session.run_id === runId))?.id
    || sessions.find((session) => session.live)?.id || current?.id || sessions[0]?.id || null;
}
function selectPage(pages, groups, activeId, follow, pendingId) {
  if (pendingId) return pendingId;
  const ids = new Set(pages.map((page) => page.id));
  const parent = groups.filter((group) => group.owner === "parent" && ids.has(group.current_page_id))
    .sort((left, right) => right.updated_at - left.updated_at)[0]?.current_page_id;
  if (follow && parent) return parent;
  return ids.has(activeId) ? activeId : parent || pages[0]?.id || null;
}
function surfaceStatus(value) { if (value === "connecting") return "正在连接真实浏览器…"; if (value === "closed") return "页面连接已关闭"; if (value === "error") return "浏览器画面不可用"; return ""; }
function workspaceKey(context) { const binding = context?.workspace?.binding || {}; return [binding.projectId, binding.assignmentId || binding.runId, binding.sessionId].map((value) => value || "").join(":"); }
const css = `:root{color:var(--xsec-text-primary,#1d2733);background:var(--xsec-surface-container,#fff);font:12px/1.45 var(--xsec-font-family,system-ui)}*{box-sizing:border-box}body{margin:0}.app{display:flex;height:100vh;min-height:0;flex-direction:column;background:var(--xsec-surface-container,#fff)}button,input,select{font:inherit}.toolbar{display:flex;min-width:0;align-items:stretch;overflow-x:auto;scrollbar-width:thin;border-bottom:1px solid var(--xsec-border-subtle,#d9e0e7);background:var(--xsec-surface-subtle,#f6f8fa)}.session,.nav{display:flex;align-items:center;gap:6px;padding:6px 8px;background:transparent}.session{flex:0 0 244px;min-width:0;border-right:1px solid var(--xsec-border-subtle,#d9e0e7)}.session select{min-width:120px;max-width:54%}.session-state{display:inline-flex;min-width:0;flex:1;align-items:center;gap:6px;overflow:hidden;color:var(--xsec-text-tertiary,#7b8794);font-size:11px;text-overflow:ellipsis;white-space:nowrap}.session-state i{width:7px;height:7px;flex:0 0 auto;border-radius:50%;background:var(--xsec-text-tertiary,#7b8794)}.session-state i.live{background:var(--xsec-status-success,#12a594);box-shadow:0 0 0 3px color-mix(in srgb,var(--xsec-status-success,#12a594) 18%,transparent)}.icon,.new{display:grid;width:28px;height:26px;place-items:center;border:0;border-radius:6px;background:transparent;color:inherit;cursor:pointer}.icon:hover,.new:hover{background:var(--xsec-surface-hover,#e9eef3)}.icon.active{background:var(--xsec-accent,#4f7cff);color:#fff}.tabs{display:flex;flex:0 1 clamp(136px,18vw,260px);height:auto;min-width:136px;overflow-x:auto;border-right:1px solid var(--xsec-border-subtle,#d9e0e7);background:transparent}.tab{display:flex;min-width:108px;max-width:200px;align-items:stretch;border-right:1px solid var(--xsec-border-subtle,#d9e0e7);border-bottom:2px solid transparent}.tab.active{border-bottom-color:var(--xsec-accent,#4f7cff);background:var(--xsec-surface-container,#fff)}.tab-open{display:flex;min-width:0;flex:1;align-items:center;gap:6px;border:0;background:transparent;color:var(--xsec-text-secondary,#586575);cursor:pointer}.tab-open:hover{background:var(--xsec-surface-hover,#e9eef3)}.tab.active .tab-open{color:var(--xsec-text-primary,#1d2733)}.label{overflow:hidden;flex:1;text-align:left;text-overflow:ellipsis;white-space:nowrap}.owner{display:grid;width:17px;height:17px;place-items:center;border-radius:50%;background:var(--xsec-accent-soft,#e2ebff);color:var(--xsec-accent-strong,#315ee8);font-size:9px;font-style:normal}.close{border:0;background:transparent;color:var(--xsec-text-tertiary,#7b8794);cursor:pointer}.nav{flex:1 0 272px;min-width:0}.nav input{min-width:120px;flex:1;padding:5px 8px;border:1px solid var(--xsec-border,#b7c2cc);border-radius:7px;background:var(--xsec-surface-container,#fff);color:inherit}.error{padding:5px 10px;border-bottom:1px solid color-mix(in srgb,var(--xsec-status-error,#b42318) 35%,transparent);background:color-mix(in srgb,var(--xsec-status-error,#b42318) 9%,transparent);color:var(--xsec-status-error,#b42318);font-size:11px}.stage{position:relative;display:flex;min-width:0;min-height:0;flex:1;align-items:center;justify-content:center;overflow:hidden;background:#11151b;outline:2px solid transparent;outline-offset:-2px}.stage:focus-within{outline-color:var(--xsec-accent,#4f7cff)}canvas{display:block;max-width:100%;max-height:100%;touch-action:none}.keyboard{position:absolute;width:1px;height:1px;opacity:0;pointer-events:none}.surface-status{position:absolute;z-index:2;display:flex;align-items:center;gap:7px;padding:8px 12px;border:1px solid rgb(255 255 255 / 12%);border-radius:8px;background:rgb(10 13 18 / 82%);color:#dbe4f0;font-size:12px;backdrop-filter:blur(8px)}.surface-retry{position:absolute;z-index:3;top:calc(50% + 30px);border:1px solid rgb(255 255 255 / 22%);border-radius:6px;background:rgb(10 13 18 / 88%);color:#fff;cursor:pointer;padding:6px 10px}.empty[hidden],.surface-status[hidden],.surface-retry[hidden]{display:none}.empty{display:grid;place-items:center;min-height:240px;padding:24px;color:var(--xsec-text-tertiary,#7b8794);text-align:center}.footer{display:grid;min-height:26px;grid-template-columns:minmax(0,1fr) auto auto;gap:8px;align-items:center;padding:3px 8px;border-top:1px solid var(--xsec-border-subtle,#d9e0e7);background:var(--xsec-surface-subtle,#f6f8fa);color:var(--xsec-text-tertiary,#7b8794);font-size:10px}.settings{display:grid;max-width:720px;gap:12px;padding:22px}.settings h1,.settings p{margin:0}.settings h1{font-size:16px}.settings p,.settings-status{color:var(--xsec-text-secondary,#586575)}.settings-form{display:flex;gap:8px}.settings input{min-width:0;flex:1;padding:7px 9px;border:1px solid var(--xsec-border,#b7c2cc);border-radius:7px;background:var(--xsec-surface-container,#fff);color:inherit}.settings button{padding:7px 12px;border:0;border-radius:7px;background:var(--xsec-accent,#4f7cff);color:#fff;cursor:pointer}.settings-status{min-height:18px}.settings-status.error{color:var(--xsec-status-error,#b42318)}@media(max-width:720px){.session-state{display:none}}@media(max-width:560px){.tab{min-width:88px}.settings-form{flex-direction:column}}`;
function browserRpc(host) {
  return { sessionsList: () => host.request("xsec.browser.sessions.list", {}), pagesList: (browserSessionId) => host.request("xsec.browser.pages.list", { browserSessionId }), createPage: (browserSessionId) => host.request("xsec.browser.page.create", { browserSessionId }), navigatePage: (browserSessionId, pageId, url) => host.request("xsec.browser.page.navigate", { browserSessionId, pageId, url }), pageAction: (browserSessionId, pageId, action) => host.request("xsec.browser.page.action", { browserSessionId, pageId, action }), closePage: (browserSessionId, pageId) => host.request("xsec.browser.page.close", { browserSessionId, pageId }), openSurface: (browserSessionId, pageId) => host.request("xsec.browser.surface.open", { browserSessionId, pageId, viewportWidth: VIEWPORT_WIDTH, viewportHeight: VIEWPORT_HEIGHT }), readySurface: (surfaceId) => host.request("xsec.browser.surface.ready", { surfaceId }), sendSurfaceInput: (surfaceId, input) => host.request("xsec.browser.surface.input", { surfaceId, input }), closeSurface: (surfaceId) => host.request("xsec.browser.surface.close", { surfaceId }), acknowledgeSurface: (surfaceId) => host.request("xsec.browser.surface.acknowledge", { surfaceId }), setPresentationFocus: (focus) => host.request("xsec.browser.presentation.set", { focus }), readSettings: () => host.request("xsec.browser.settings.get", {}), writeSettings: (chromePath) => host.request("xsec.browser.settings.set", { chromePath }), onData: (stream, callback) => host.onData(stream, callback) };
}
class BrowserController {
  constructor(rpc, context) {
    this.rpc = rpc; this.context = context || {}; this.key = workspaceKey(this.context);
    this.state = { sessions: [], sessionId: null, userSelected: false, pages: [], groups: [], pageId: null, pageUrl: null, follow: true, focus: false, address: "", error: "", surfaceError: "", busy: "", loading: true, pending: null, observed: null, surfaceState: "" };
    this.timer = 0; this.revision = 0; this.refreshing = false; this.refreshQueued = false; this.refreshChain = Promise.resolve(); this.refreshLoopPromise = Promise.resolve(); this.disposed = false; this.surface = undefined; this.subscription = undefined; this.surfaceGeneration = 0; this.surfaceErrorKey = "";
    this.moveTimer = 0; this.pendingMove = undefined; this.inputTail = Promise.resolve(); this.surfaceCloseTail = Promise.resolve(); this.surfaceClosePromises = new Map(); this.surfaceTransitionTail = Promise.resolve(); this.surfaceTeardownPromise = undefined; this.closingSurfaceId = ""; this.addressEditPageId = null; this.presentationTails = new Map(); this.canvasContext = undefined; this.composing = false; this.compositionSurfaceId = ""; this.compositionCancelled = false; this.ignoredText = undefined; this.pressedKeys = new Map(); this.mouseButtons = 0; this.mouseSurfaceId = ""; this.lastPoint = { x: 0, y: 0 }; this.frameSurfaceId = ""; this.nextFrameAckAt = 0; this.focusTail = Promise.resolve(); this.focusTarget = false; this.focusRevision = 0; this.visibilityRevision = 0; this.settingsReady = false; this.settingsRevision = 0;
    this.onEscape = (event) => { if (this.focusTarget && event.key === "Escape") void this.setFocus(false).catch((error) => this.fail(error, "presentation")); };
    this.onVisibilityChange = () => void this.handleVisibilityChange(); this.onWindowBlur = () => { const modifiers = this.activeModifierMask(); this.releaseMouseButtons({ modifiers }); this.releasePressedKeys(); };
  }
  mount(root, context) {
    this.root = root; this.context = context || this.context;
    if (this.settingsPage()) { this.buildSettings(); return; }
    this.buildWorkspace(); console.debug("browser.workspace.mounted", { workspace: this.key }); void this.refresh();
  }
  async update(context) {
    const visibilityRevision = ++this.visibilityRevision; const next = context || {}; const changed = workspaceKey(next) !== this.key;
    this.context = next; this.key = workspaceKey(next); if (this.settingsPage()) return this.loadSettings();
    if (changed) { this.invalidateRefresh(); this.state.userSelected = false; this.state.sessionId = null; this.state.follow = true; await this.resetPages(); }
    if (this.visible()) await this.manualRefresh();
    else await this.teardownWorkspace(visibilityRevision);
  }
  async dispose() {
    this.disposed = true; this.invalidateRefresh(); this.clearTimer(); this.releaseMouseButtons(); this.clearPendingMove(); window.removeEventListener("keydown", this.onEscape); window.removeEventListener("blur", this.onWindowBlur); document.removeEventListener("visibilitychange", this.onVisibilityChange); try { if (!this.settingsPage()) await this.teardownWorkspace(); } finally { this.root?.replaceChildren(); } console.debug("browser.frontend.disposed");
  }
  settingsPage() { return this.context.kind === "settings-page"; }
  binding() { return this.context.workspace?.binding || {}; }
  visible() { return !this.disposed && this.context.visible !== false && document.visibilityState !== "hidden"; }
  session() { return this.state.sessions.find((item) => item.id === this.state.sessionId) || null; }
  page() { return this.state.pages.find((item) => item.id === this.state.pageId) || null; }
  surfaceKey(sessionId, pageId) { return `${sessionId}:${pageId}`; }
  clearTimer() { if (this.timer) window.clearTimeout(this.timer); this.timer = 0; }
  clearPendingMove() { if (this.moveTimer) window.clearTimeout(this.moveTimer); this.moveTimer = 0; this.pendingMove = undefined; this.mouseButtons = 0; }
  clearSurfaceInput() { this.clearPendingMove(); this.mouseSurfaceId = ""; this.closingSurfaceId = ""; this.compositionCancelled ||= this.composing; this.composing = false; this.compositionSurfaceId = ""; if (this.controls?.keyboard) this.controls.keyboard.value = ""; this.pressedKeys.clear(); this.inputTail = Promise.resolve(); } activeModifierMask() { return [...this.pressedKeys.values()].reduce((mask, input) => mask | (input.modifiers || 0), 0); } releasePressedKeys() { const held = [...this.pressedKeys.values()]; this.pressedKeys.clear(); held.forEach((input) => void this.sendInput({ ...input, event_type: "up", auto_repeat: false })); }
  invalidateRefresh() { this.revision += 1; if (this.refreshing) this.refreshQueued = true; }
  schedule(delay) { this.clearTimer(); if (this.visible() && !this.state.error) this.timer = window.setTimeout(() => void this.refresh(), delay); }
  clearSurfaceError() { this.surfaceErrorKey = ""; this.state.surfaceError = ""; if (["error", "closed"].includes(this.state.surfaceState)) this.state.surfaceState = ""; }
  async teardownWorkspace(visibilityRevision) { try { await this.setFocus(false); } finally { if (visibilityRevision === undefined || visibilityRevision === this.visibilityRevision && !this.visible()) await this.closeSurface(); } }
  async resetPages() {
    this.clearSurfaceError(); Object.assign(this.state, { pages: [], groups: [], pageId: null, pageUrl: null, pending: null, observed: null, address: "" }); await this.closeSurface();
  }
  async handleVisibilityChange() {
    const visibilityRevision = ++this.visibilityRevision;
    if (!this.visible()) { this.clearTimer(); this.releaseMouseButtons(); this.clearPendingMove(); await this.teardownWorkspace(visibilityRevision); if (visibilityRevision === this.visibilityRevision && !this.visible()) { this.render(); console.debug("browser.workspace.hidden"); } return; }
    console.debug("browser.workspace.visible"); await this.manualRefresh();
  }
  async refresh() {
    if (this.refreshing) { this.refreshQueued = true; return this.refreshLoopPromise; }
    if (!this.visible() || this.state.error) return;
    this.refreshing = true; this.refreshQueued = false; this.refreshLoopPromise = this.runRefreshLoop(); await this.refreshLoopPromise;
  }
  async runRefreshLoop() {
    try { do { this.refreshChain = this.refreshOnce(); await this.refreshChain; if (this.refreshQueued && this.visible()) this.refreshQueued = false; else break; } while (true); } finally { this.refreshing = false; }
  }
  async refreshOnce() {
    const id = ++this.revision;
    try {
      const sessions = items(await this.rpc.sessionsList(), "浏览器会话"); if (id !== this.revision) return;
      this.state.sessions = sessions; this.state.loading = false;
      const next = selectSession(sessions, this.state.sessionId, this.binding().assignmentId || this.binding().runId, this.state.userSelected);
      if (next !== this.state.sessionId) { this.state.sessionId = next; await this.resetPages(); }
      const session = this.session();
      if (!session?.live) { await this.resetPages(); this.render(); this.schedule(sessions.some((item) => item.live) ? LIVE_SESSION_POLL_MS : CLOSED_SESSION_POLL_MS); return; }
      await this.refreshPages(session, id); if (id !== this.revision) return; this.state.error = ""; this.render(); this.schedule(PAGE_POLL_MS);
    } catch (error) { if (id === this.revision) { this.state.loading = false; this.fail(error, "sync"); } }
  }
  async refreshPages(session, revision) {
    const snapshot = await this.rpc.pagesList(session.id); if (revision !== this.revision) return;
    if (!Array.isArray(snapshot?.pages) || !Array.isArray(snapshot.groups)) throw new Error("浏览器页面响应格式无效");
    const opened = this.state.observed && this.state.pageId ? snapshot.pages.find((page) => !this.state.observed.has(page.id) && page.opener_id === this.state.pageId)?.id : null;
    this.state.observed = new Set(snapshot.pages.map((page) => page.id)); this.state.pages = snapshot.pages; this.state.groups = snapshot.groups;
    const pending = this.state.pending?.expiresAt > Date.now() ? this.state.pending.pageId : null; if (!pending || snapshot.pages.some((page) => page.id === pending)) this.state.pending = null;
    if (opened) this.state.follow = false; const next = selectPage(snapshot.pages, snapshot.groups, this.state.pageId, this.state.follow, opened || pending);
    if (next !== this.state.pageId) { this.state.pageId = next; this.clearSurfaceError(); } this.updateAddress(); await this.ensureSurface();
  }
  updateAddress(force = false) {
    const page = this.page(); const url = page?.url || null; if (url === this.state.pageUrl && !force && this.addressEditPageId === this.state.pageId) return;
    this.state.pageUrl = url; const editing = document.activeElement === this.controls?.address; const editingCurrentPage = editing && this.addressEditPageId === this.state.pageId;
    if (!editingCurrentPage) { this.state.address = url && url !== "about:blank" ? url : ""; if (editing) { this.controls.address.value = this.state.address; this.addressEditPageId = this.state.pageId; } }
  }
  async manualRefresh() {
    this.state.error = ""; this.clearTimer(); if (this.refreshing) { this.invalidateRefresh(); await this.refreshLoopPromise; return; } await this.refresh();
  }
  fail(error, stage) { console.error(`browser.${stage}.failed`, { message: errorText(error) }); this.state.error = errorText(error); this.render(); }
  async action(name, operation) {
    const startedAt = performance.now(); const scope = { key: this.key, sessionId: this.state.sessionId, pageId: this.state.pageId }; const current = () => this.key === scope.key && this.state.sessionId === scope.sessionId && this.state.pageId === scope.pageId; this.state.busy = name; this.render(); console.info("browser.action.started", { action: name });
    try { await operation(scope); if (current()) { this.state.error = ""; await this.manualRefresh(); console.info("browser.action.completed", { action: name, elapsedMs: Math.round(performance.now() - startedAt) }); } }
    catch (error) { if (current()) this.fail(error, "action"); else console.error("browser.action.stale_failed", { action: name, message: errorText(error) }); } finally { this.state.busy = ""; if (!this.disposed) this.render(); }
  }
  async chooseSession(id) {
    this.invalidateRefresh(); this.state.userSelected = true; this.state.sessionId = id; this.state.follow = true; await this.resetPages(); console.info("browser.session.selected", { source: "user" }); await this.manualRefresh();
  }
  async choosePage(id) {
    this.state.pending = null; this.state.follow = false; this.state.pageId = id; this.clearSurfaceError(); this.updateAddress(); console.info("browser.page.selected", { source: "user" }); await this.ensureSurface(); this.render();
  }
  async createPage() {
    const session = this.session(); const key = this.key; if (!session?.live) return;
    await this.action("new", async (scope) => { const result = await this.rpc.createPage(session.id); if (this.key !== key || this.session()?.id !== session.id || this.state.pageId !== scope.pageId) return; this.state.pending = { pageId: result.page_id, expiresAt: Date.now() + NEW_PAGE_GRACE_MS }; this.state.follow = false; this.state.pageId = result.page_id; scope.pageId = result.page_id; this.clearSurfaceError(); });
  }
  async navigate() {
    const session = this.session(); const page = this.page(); if (!session?.live || !page) return;
    if (this.addressEditPageId && this.addressEditPageId !== page.id) { this.addressEditPageId = null; this.updateAddress(true); return; }
    const address = this.state.address; await this.action("navigate", () => this.rpc.navigatePage(session.id, page.id, normalizeUrl(address)));
  }
  async pageAction(action) {
    const session = this.session(); const page = this.page(); if (!session?.live || !page) return;
    await this.action(action, () => this.rpc.pageAction(session.id, page.id, action));
  }
  async closePage(id) {
    const session = this.session(); const key = this.key; if (!session?.live) return; const next = this.state.pageId === id ? pageAfterClose(this.state.pages, id) : null;
    await this.action("close", async (scope) => { await this.rpc.closePage(session.id, id); if (next && this.key === key && this.session()?.id === session.id && this.state.pageId === id) { this.state.follow = false; this.state.pageId = next; scope.pageId = next; this.clearSurfaceError(); this.updateAddress(); } });
  }
  async closeSurface(clearState = true, invalidate = true) { if (this.surfaceTeardownPromise) return this.surfaceTeardownPromise; this.surfaceTeardownPromise = this.closeSurfaceNow(clearState, invalidate).finally(() => { this.surfaceTeardownPromise = undefined; }); return this.surfaceTeardownPromise;
  } async closeSurfaceNow(clearState = true, invalidate = true) {
    const surface = this.surface; const subscription = this.subscription; const heldKeys = [...this.pressedKeys.values()]; const heldModifiers = this.activeModifierMask(); this.pressedKeys.clear(); this.closingSurfaceId = this.mouseSurfaceId || surface?.id || ""; const release = this.releaseMouseButtons({ modifiers: heldModifiers, propagate: true }); this.surface = undefined; this.subscription = undefined; if (invalidate) this.surfaceGeneration += 1; this.frameSurfaceId = ""; this.controls?.canvas && (this.controls.canvas.hidden = true); const releaseKeys = async () => { for (const input of heldKeys) await this.rpc.sendSurfaceInput(surface.id, { ...input, event_type: "up", auto_repeat: false }); }; const keyRelease = surface ? this.inputTail.then(releaseKeys, releaseKeys) : Promise.resolve(); const results = await Promise.allSettled([keyRelease, release]); this.clearSurfaceInput(); subscription?.dispose?.(); if (clearState) this.state.surfaceState = ""; await this.closeNativeSurface(surface); const failure = results.find((result) => result.status === "rejected"); if (failure) throw failure.reason;
  } closeNativeSurface(surface) { if (!surface) return this.surfaceCloseTail; const existing = this.surfaceClosePromises.get(surface.id); if (existing) return existing; const close = async () => { console.debug("browser.surface.close.started", { pageId: surface.pageId }); await this.rpc.closeSurface(surface.id); }; const operation = this.surfaceCloseTail.then(close, close); this.surfaceClosePromises.set(surface.id, operation); this.surfaceCloseTail = operation.catch((error) => console.error("browser.surface.close.failed", { message: errorText(error) })); return operation; }
  surfaceRequestCurrent(generation, sessionId, pageId) { return generation === this.surfaceGeneration && this.visible() && this.session()?.id === sessionId && this.page()?.id === pageId; }
  async ensureSurface() { const run = () => this.ensureSurfaceNow(); this.surfaceTransitionTail = this.surfaceTransitionTail.then(run, run); return this.surfaceTransitionTail; } async ensureSurfaceNow() {
    const session = this.session(); const page = this.page(); if (!this.visible() || !session?.live || !page) { await this.closeSurface(); return; }
    const key = this.surfaceKey(session.id, page.id); if (this.surface?.pageId === page.id && this.surface.sessionId === session.id) return; if (this.surfaceErrorKey === key) return;
    const generation = ++this.surfaceGeneration; await this.closeSurface(true, false); if (generation !== this.surfaceGeneration) return; this.state.surfaceState = "connecting"; this.state.surfaceError = ""; this.render(); console.info("browser.surface.open.started", { pageId: page.id });
    try {
      const result = await this.rpc.openSurface(session.id, page.id);
      if (!this.surfaceRequestCurrent(generation, session.id, page.id)) { await this.closeNativeSurface({ id: result.surfaceId, pageId: page.id }); return; }
      this.surface = { id: result.surfaceId, stream: result.stream, pageId: page.id, sessionId: session.id }; this.nextFrameAckAt = 0;
      this.subscription = this.rpc.onData(result.stream, (raw) => { const tail = this.presentationTails.get(result.surfaceId) || Promise.resolve(); const next = tail.then(() => this.present(raw, result.surfaceId), () => this.present(raw, result.surfaceId)).catch((error) => this.failSurface(error, result.surfaceId)); this.presentationTails.set(result.surfaceId, next); });
      await this.rpc.readySurface(result.surfaceId);
      if (!this.surfaceRequestCurrent(generation, session.id, page.id) || this.surface?.id !== result.surfaceId) {
        const stale = this.surface?.id === result.surfaceId ? this.surface : undefined;
        if (stale) { this.surface = undefined; this.subscription?.dispose?.(); this.subscription = undefined; this.frameSurfaceId = ""; this.clearSurfaceInput(); }
        const teardown = this.surfaceTeardownPromise;
        if (teardown) await teardown;
        else await this.closeNativeSurface(stale || { id: result.surfaceId, pageId: page.id });
        return;
      }
      console.info("browser.surface.open.completed", { pageId: page.id });
    } catch (error) { if (generation !== this.surfaceGeneration || this.session()?.id !== session.id || this.page()?.id !== page.id) return; await this.failSurface(error, undefined, generation); }
  }
  async retrySurface() { this.clearSurfaceError(); await this.ensureSurface(); }
  async acknowledgeFrame(surfaceId) {
    const delay = Math.max(0, this.nextFrameAckAt - performance.now()); if (delay) await new Promise((resolve) => window.setTimeout(resolve, delay));
    if (this.surface?.id !== surfaceId) return; this.nextFrameAckAt = performance.now() + FRAME_ACK_INTERVAL_MS; await this.rpc.acknowledgeSurface(surfaceId);
  }
  async present(raw, surfaceId) {
    if (!this.controls || this.surface?.id !== surfaceId) return; const event = parseEvent(raw);
    if (event) { await this.presentEvent(event, surfaceId); return; }
    const frame = parseFrame(raw); if (!frame) throw new Error("未知的浏览器画面数据"); await this.presentFrame(frame, surfaceId);
  }
  async presentEvent(event, surfaceId) {
    if (event.kind === "error") throw new Error(event.message || "真实浏览器画面不可用");
    if (event.kind === "closed") { const surface = this.surface; if (!surface || surface.id !== surfaceId) return; this.subscription?.dispose?.(); this.subscription = undefined; this.surface = undefined; this.frameSurfaceId = ""; this.clearSurfaceInput(); this.surfaceErrorKey = this.surfaceKey(surface.sessionId, surface.pageId); this.state.surfaceState = "closed"; this.render(); return; }
    if (this.state.surfaceState !== "live") { this.state.surfaceState = "live"; this.render(); }
  }
  async presentFrame(frame, surfaceId) {
    try {
      const image = await createImageBitmap(new Blob([frame.jpeg], { type: "image/jpeg" })); if (this.surface?.id !== surfaceId) { image.close(); return; }
      const firstFrame = this.frameSurfaceId !== surfaceId; const canvas = this.controls.canvas; if (canvas.width !== frame.width) canvas.width = frame.width; if (canvas.height !== frame.height) canvas.height = frame.height; this.canvasContext ||= canvas.getContext("2d", { alpha: false }); this.canvasContext?.drawImage(image, 0, 0, frame.width, frame.height); image.close(); this.frameSurfaceId = surfaceId;
      if (firstFrame || this.state.surfaceState !== "live") { this.state.surfaceState = "live"; this.render(); }
    } finally { await this.acknowledgeFrame(surfaceId); }
  }
  async failSurface(error, surfaceId, generation) {
    if (generation !== undefined && generation !== this.surfaceGeneration) return; const surface = this.surface; if (surfaceId && surface?.id !== surfaceId) return;
    const key = surface ? this.surfaceKey(surface.sessionId, surface.pageId) : this.surfaceKey(this.state.sessionId, this.state.pageId); const current = !surface || surface.sessionId === this.state.sessionId && surface.pageId === this.state.pageId; this.surfaceErrorKey = key; console.error("browser.surface.failed", { message: errorText(error) });
    if (current) { this.state.surfaceState = "error"; this.state.surfaceError = errorText(error); this.frameSurfaceId = ""; this.render(); } if (surface) await this.closeSurface(false);
  }
  async setFocus(focus) {
    this.focusTarget = focus; const revision = ++this.focusRevision;
    const apply = async () => { try { await this.rpc.setPresentationFocus(focus); this.state.focus = focus; if (revision === this.focusRevision) this.render(); } catch (error) { if (revision !== this.focusRevision) return; this.focusTarget = this.state.focus; throw error; } };
    this.focusTail = this.focusTail.then(apply, apply); return this.focusTail;
  }
  releaseMouseButtons(options = {}) { const buttons = this.mouseButtons; const surfaceId = this.mouseSurfaceId || this.surface?.id; const move = this.takePendingMove(); const modifiers = options.modifiers ?? this.activeModifierMask(); this.mouseButtons = 0; this.mouseSurfaceId = ""; if (!buttons || !surfaceId) return Promise.resolve(); return this.queuePointer(surfaceId, [...(move ? [move] : []), ...mouseButtonReleases(buttons, this.lastPoint, modifiers)], options); }
  sendInput(input, surfaceId = this.surface?.id, options = {}) {
    if (!surfaceId || this.surface?.id !== surfaceId && this.closingSurfaceId !== surfaceId) return Promise.resolve(); const send = async () => { if (this.surface?.id !== surfaceId && this.closingSurfaceId !== surfaceId) return; try { await this.rpc.sendSurfaceInput(surfaceId, input); } catch (error) { if (options.propagate) throw error; void this.failSurface(error, surfaceId); } };
    this.inputTail = this.inputTail.then(send, send); return this.inputTail;
  }
  point(event) {
    const rect = this.controls.canvas.getBoundingClientRect(); const width = this.controls.canvas.width || VIEWPORT_WIDTH; const height = this.controls.canvas.height || VIEWPORT_HEIGHT;
    const point = { x: Math.max(0, Math.min(width, ((event.clientX - rect.left) / rect.width) * width)), y: Math.max(0, Math.min(height, ((event.clientY - rect.top) / rect.height) * height)) }; this.lastPoint = point; return point;
  }
  takePendingMove() { if (this.moveTimer) window.clearTimeout(this.moveTimer); this.moveTimer = 0; const input = this.pendingMove; this.pendingMove = undefined; return input; }
  queuePointer(surfaceId, inputs, options = {}) { let tail = Promise.resolve(); inputs.forEach((input) => { tail = this.sendInput(input, surfaceId, options); }); return tail; }
  queueMove(input) { this.pendingMove = input; if (this.moveTimer) return; this.moveTimer = window.setTimeout(() => void this.flushPendingMove(), POINTER_MOVE_MS); }
  async flushPendingMove() { const input = this.takePendingMove(); if (input) await this.queuePointer(this.surface?.id, [input]); }
  render() {
    if (!this.controls) return; const session = this.session(); const page = this.page(); const live = Boolean(session?.live);
    this.controls.app.classList.toggle("focus", this.state.focus); this.controls.select.replaceChildren(...this.state.sessions.map((item) => sessionOption(item, item.id === this.state.sessionId))); this.controls.tabs.replaceChildren(...this.state.pages.map((item) => pageTab(this, item)), this.controls.newTab);
    this.controls.sessionDot.classList.toggle("live", live); this.controls.sessionText.textContent = live ? "真实 Chrome 已连接" : "浏览器已离线"; if (document.activeElement !== this.controls.address) this.controls.address.value = this.state.address;
    this.controls.follow.classList.toggle("active", this.state.follow); this.controls.focus.classList.toggle("active", this.state.focus); this.controls.error.textContent = this.state.error; this.controls.error.hidden = !this.state.error; this.controls.address.disabled = Boolean(this.state.busy); this.controls.canvas.hidden = !live || !page || this.frameSurfaceId !== this.surface?.id;
    this.controls.empty.hidden = Boolean(live && page); this.controls.empty.textContent = this.state.loading ? "正在读取浏览器会话…" : !this.state.sessions.length ? "当前任务还没有浏览器会话。MCP 创建浏览器后，这里会自动映射真实页面。" : live ? "浏览器中没有页面" : "该浏览器会话已经结束";
    this.controls.surfaceStatus.textContent = this.state.surfaceError || surfaceStatus(this.state.surfaceState); this.controls.surfaceStatus.hidden = !this.controls.surfaceStatus.textContent; this.controls.surfaceRetry.hidden = !this.state.surfaceError && this.state.surfaceState !== "closed";
    this.controls.newTab.disabled = !live || Boolean(this.state.busy); this.controls.actions.forEach((button) => { button.disabled = !live || !page || Boolean(this.state.busy); });
    const owners = this.state.groups.filter((group) => group.current_page_id === this.state.pageId).map((group) => group.owner === "parent" ? "主 Agent" : "子 Agent").join(" · "); this.controls.footer.replaceChildren(element("span", "", page ? `${displayUrl(page.url)} · ${page.id.slice(0, 12)}` : "未选择页面"), element("span", "", owners), element("span", "", `${VIEWPORT_WIDTH} × ${VIEWPORT_HEIGHT}`));
  }
  buildWorkspace() {
    this.root.replaceChildren(element("style", "", css)); this.controls = workspaceControls(this); this.root.append(this.controls.app); window.addEventListener("keydown", this.onEscape); window.addEventListener("blur", this.onWindowBlur); document.addEventListener("visibilitychange", this.onVisibilityChange); this.render();
  }
  buildSettings() {
    this.root.replaceChildren(element("style", "", css)); this.controls = settingsControls(this); this.root.append(this.controls.app); void this.loadSettings();
  }
  async loadSettings() {
    const revision = ++this.settingsRevision; this.settingsReady = false; this.controls.settingsInput.disabled = true; this.controls.settingsSave.disabled = true; this.controls.settingsRetry.hidden = true; this.settingsMessage("正在读取浏览器路径…", false);
    try { const result = await this.rpc.readSettings(); if (revision !== this.settingsRevision) return; this.controls.settingsInput.value = result.chromePath || ""; this.settingsReady = true; this.controls.settingsInput.disabled = false; this.controls.settingsSave.disabled = false; this.settingsMessage("", false); console.info("browser.settings.read.completed"); }
    catch (error) { if (revision !== this.settingsRevision) return; this.settingsMessage(`读取浏览器路径失败：${errorText(error)}`, true); this.controls.settingsRetry.hidden = false; console.error("browser.settings.read.failed", { message: errorText(error) }); }
  }
  settingsMessage(message, failed) { this.controls.settingsStatus.textContent = message; this.controls.settingsStatus.classList.toggle("error", failed); }
  async saveSettings() {
    if (!this.settingsReady) return; const revision = this.settingsRevision; const button = this.controls.settingsSave; button.disabled = true; this.controls.settingsInput.disabled = true; this.settingsMessage("正在保存…", false); console.info("browser.settings.save.started");
    try { const result = await this.rpc.writeSettings(this.controls.settingsInput.value.trim()); if (revision !== this.settingsRevision) return; this.controls.settingsInput.value = result.chromePath || ""; this.settingsMessage("浏览器路径已保存；新建浏览器会话时生效", false); console.info("browser.settings.save.completed"); }
    catch (error) { if (revision !== this.settingsRevision) return; this.settingsMessage(`保存浏览器路径失败：${errorText(error)}`, true); console.error("browser.settings.save.failed", { message: errorText(error) }); } finally { if (revision === this.settingsRevision) { this.controls.settingsInput.disabled = false; button.disabled = false; } }
  }
}
function sessionOption(session, selected) {
  const option = element("option", "", `${session.live ? "运行中" : "已结束"} · ${session.id.slice(0, 10)}`);
  option.value = session.id; option.selected = selected; return option;
}
function pageTab(controller, page) {
  const tab = element("div", `tab${page.id === controller.state.pageId ? " active" : ""}`); const open = element("button", "tab-open"); const close = element("button", "close", "×");
  open.type = "button"; open.setAttribute("role", "tab"); open.setAttribute("aria-selected", String(page.id === controller.state.pageId)); open.append(element("span", "", "◉"), element("span", "label", pageLabel(page)));
  const groups = controller.state.groups.filter((group) => group.current_page_id === page.id); if (groups.length) open.append(element("em", "owner", groups.some((group) => group.owner === "parent") ? "主" : "子"));
  open.onclick = () => void controller.choosePage(page.id).catch((error) => controller.fail(error, "page-select")); close.type = "button"; close.setAttribute("aria-label", `关闭 ${pageLabel(page)}`); close.disabled = Boolean(controller.state.busy); close.onclick = () => void controller.closePage(page.id); tab.append(open, close); return tab;
}
function icon(text, label, handler) {
  const button = element("button", "icon", text); button.type = "button"; button.setAttribute("aria-label", label); button.onclick = handler; return button;
}
function workspaceControls(controller) {
  const app = element("main", "app"); const session = element("header", "session"); const select = element("select"); const sessionDot = element("i"); const sessionText = element("span"); const sessionState = element("span", "session-state");
  select.setAttribute("aria-label", "浏览器会话"); select.onchange = () => void controller.chooseSession(select.value).catch((error) => controller.fail(error, "session-select")); sessionState.append(sessionDot, sessionText);
  const follow = icon("◉", "跟随 Agent", () => { controller.state.follow = !controller.state.follow; if (controller.state.follow) controller.state.pending = null; void controller.manualRefresh(); });
  const focus = icon("⛶", "切换浏览器专注模式", () => void controller.setFocus(!controller.focusTarget).catch((error) => controller.fail(error, "presentation")));
  const refresh = icon("↻", "重新读取浏览器会话", () => void controller.manualRefresh()); session.append(select, sessionState, follow, focus, refresh);
  const tabs = element("div", "tabs"); tabs.setAttribute("role", "tablist"); const newTab = element("button", "new", "+"); newTab.type = "button"; newTab.setAttribute("aria-label", "新建浏览器标签页"); newTab.onclick = () => void controller.createPage();
  const nav = element("div", "nav"); const back = icon("←", "浏览器后退", () => void controller.pageAction("back")); const forward = icon("→", "浏览器前进", () => void controller.pageAction("forward")); const reload = icon("↻", "浏览器刷新", () => void controller.pageAction("reload")); const stop = icon("■", "停止加载", () => void controller.pageAction("stop"));
  const address = element("input"); address.placeholder = "输入授权范围内的 HTTP/HTTPS 地址"; address.setAttribute("aria-label", "浏览器地址"); address.onfocus = () => { controller.addressEditPageId = controller.state.pageId; }; address.oninput = () => { controller.state.address = address.value; }; address.onblur = () => { controller.addressEditPageId = null; controller.updateAddress(true); address.value = controller.state.address; }; address.onkeydown = (event) => { if (event.key === "Enter" && !controller.state.busy) void controller.navigate(); }; nav.append(back, forward, reload, stop, address);
  const error = element("div", "error"); const stage = element("div", "stage"); const canvas = element("canvas"); const keyboard = element("textarea", "keyboard"); const surfaceStatus = element("div", "surface-status"); const surfaceRetry = element("button", "surface-retry", "重新连接"); const empty = element("div", "empty");
  canvas.setAttribute("aria-label", "真实浏览器页面"); keyboard.setAttribute("aria-label", "浏览器键盘输入"); surfaceRetry.type = "button"; surfaceRetry.onclick = () => void controller.retrySurface().catch((error) => void controller.failSurface(error)); stage.append(canvas, keyboard, surfaceStatus, surfaceRetry, empty);
  const toolbar = element("div", "toolbar"); toolbar.setAttribute("role", "toolbar"); toolbar.setAttribute("aria-label", "浏览器工具栏"); toolbar.append(session, tabs, nav); const footer = element("footer", "footer"); app.append(toolbar, error, stage, footer); bindSurfaceInput(controller, canvas, keyboard);
  return { app, select, sessionDot, sessionText, follow, focus, tabs, newTab, address, error, canvas, keyboard, surfaceStatus, surfaceRetry, empty, footer, actions: [back, forward, reload, stop] };
}
function bindSurfaceInput(controller, canvas, keyboard) {
  canvas.oncontextmenu = (event) => event.preventDefault();
  const pressMouse = (event, capture, clickCount) => { const mask = mouseButtonMask(event.button); const surfaceId = controller.surface?.id; if (!mask || !surfaceId || controller.mouseButtons & mask) return; const move = controller.takePendingMove(); controller.mouseButtons = event.buttons; controller.mouseSurfaceId = surfaceId; if (capture) canvas.setPointerCapture(event.pointerId); keyboard.focus({ preventScroll: true }); const point = controller.point(event); void controller.queuePointer(surfaceId, [...(move ? [move] : []), { kind: "mouse", event_type: "down", ...point, button: mouseButton(event.button), buttons: event.buttons, click_count: clickCount, modifiers: eventModifiers(event) }]); };
  canvas.onpointerdown = (event) => { if (event.pointerType === "mouse") { canvas.setPointerCapture(event.pointerId); keyboard.focus({ preventScroll: true }); return; } pressMouse(event, true, event.detail || 1); }; canvas.onmousedown = (event) => pressMouse(event, false, event.detail || 1);
  const releaseMouse = async (event) => { const mask = mouseButtonMask(event.button); if (!mask || !(controller.mouseButtons & mask)) return; const move = controller.takePendingMove(); const surfaceId = controller.mouseSurfaceId; controller.mouseButtons = event.buttons; if (!event.buttons) controller.mouseSurfaceId = ""; const point = controller.point(event); await controller.queuePointer(surfaceId, [...(move ? [move] : []), { kind: "mouse", event_type: "up", ...point, button: mouseButton(event.button), buttons: event.buttons, click_count: event.detail || 1, modifiers: eventModifiers(event) }]); };
  canvas.onmouseup = (event) => void releaseMouse(event); canvas.onpointercancel = (event) => { const buttons = controller.mouseButtons; const move = controller.takePendingMove(); const surfaceId = controller.mouseSurfaceId; controller.mouseButtons = NO_MOUSE_BUTTONS; controller.mouseSurfaceId = ""; if (!buttons) return; const point = controller.point(event); void controller.queuePointer(surfaceId, [...(move ? [move] : []), ...mouseButtonReleases(buttons, point, eventModifiers(event))]); };
  canvas.onpointermove = (event) => { if (event.buttons && event.buttons !== controller.mouseButtons) return; const point = controller.point(event); controller.queueMove({ kind: "mouse", event_type: "move", ...point, button: "none", buttons: event.buttons, modifiers: eventModifiers(event) }); }; canvas.onlostpointercapture = () => controller.releaseMouseButtons();
  canvas.onwheel = (event) => { event.preventDefault(); const move = controller.takePendingMove(); const point = controller.point(event); void controller.queuePointer(controller.surface?.id, [...(move ? [move] : []), { kind: "mouse", event_type: "wheel", ...point, button: "none", buttons: event.buttons || controller.mouseButtons, modifiers: eventModifiers(event), delta_x: event.deltaX, delta_y: event.deltaY }]); };
  keyboard.onkeydown = (event) => { if (event.isComposing || controller.composing || event.key === "Process") return; if (!controller.surface) return; if (controller.focusTarget && event.key === "Escape") { event.preventDefault(); event.stopPropagation(); void controller.setFocus(false).catch((error) => controller.fail(error, "presentation")); return; } const paste = (event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "v" || event.shiftKey && event.key === "Insert"; if (paste) return; const altGraph = event.getModifierState?.("AltGraph"); const printable = event.key.length === 1 && !event.metaKey && (!event.ctrlKey && !event.altKey || altGraph || event.altKey && !event.ctrlKey); if (!printable) event.preventDefault(); const key = event.code || event.key; const input = { kind: "key", event_type: "down", key: event.key, code: event.code, modifiers: eventModifiers(event), windows_virtual_key_code: event.keyCode, auto_repeat: event.repeat }; controller.pressedKeys.set(key, input); void controller.sendInput(input); };
  keyboard.onkeyup = (event) => { const key = event.code || event.key; if (!controller.pressedKeys.delete(key)) return; void controller.sendInput({ kind: "key", event_type: "up", key: event.key, code: event.code, modifiers: eventModifiers(event), windows_virtual_key_code: event.keyCode, auto_repeat: event.repeat }); };
  keyboard.onblur = () => controller.releasePressedKeys();
  keyboard.oncompositionstart = () => { controller.composing = true; controller.compositionCancelled = false; controller.compositionSurfaceId = controller.surface?.id || ""; }; keyboard.oncompositionend = (event) => { const accepted = !controller.compositionCancelled && controller.surface?.id === controller.compositionSurfaceId; controller.composing = false; controller.compositionCancelled = false; controller.compositionSurfaceId = ""; controller.ignoredText = event.data; if (accepted && event.data) controller.sendInput({ kind: "insert_text", text: event.data }); event.target.value = ""; };
  keyboard.onpaste = (event) => { event.preventDefault(); const text = event.clipboardData.getData("text/plain"); if (text) controller.sendInput({ kind: "insert_text", text }); event.target.value = ""; };
  keyboard.oninput = (event) => { if (controller.composing) return; const text = event.target.value; event.target.value = ""; if (controller.ignoredText === text) { controller.ignoredText = undefined; return; } controller.ignoredText = undefined; if (text) controller.sendInput({ kind: "insert_text", text }); };
}
function settingsControls(controller) { const app = element("main", "settings"); const title = element("h1", "", "自定义浏览器路径"); const description = element("p", "", "仅在自动发现的浏览器不适用时填写可执行文件路径；留空会使用系统默认发现结果。"); const form = element("div", "settings-form"); const settingsInput = element("input"); const settingsSave = element("button", "", "保存"); const settingsRetry = element("button", "", "重新读取"); const settingsStatus = element("div", "settings-status");
  const agent = navigator.userAgent; settingsInput.setAttribute("aria-label", "自定义 Chrome 路径"); settingsInput.placeholder = agent.includes("Windows") ? "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" : agent.includes("Mac") ? "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" : "/usr/bin/google-chrome"; settingsSave.type = "button"; settingsSave.onclick = () => void controller.saveSettings(); settingsRetry.type = "button"; settingsRetry.hidden = true; settingsRetry.onclick = () => void controller.loadSettings(); form.append(settingsInput, settingsSave, settingsRetry); app.append(title, description, form, settingsStatus); return { app, settingsInput, settingsSave, settingsRetry, settingsStatus };
} export function activate(host) { console.debug("browser.frontend.activated", { apiVersion: host.apiVersion }); const controller = new BrowserController(browserRpc(host), host.context); return { mount(root, context) { return controller.mount(root, context); }, update(context) { return controller.update(context); }, dispose() { return controller.dispose(); } }; }
