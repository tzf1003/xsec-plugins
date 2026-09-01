const WINDOWS_PROFILE_IDS = new Set(["cmd", "windows-powershell", "powershell-7"]);
const ACTIVE_POLL_INTERVAL_MS = 100, IDLE_POLL_INTERVAL_MS = 500, RESIZE_DELAY_MS = 100;
const MIN_COLUMNS = 20, MIN_ROWS = 2, CELL_WIDTH = 8, CELL_HEIGHT = 16, MAX_SCROLLBACK_CHARACTERS = 200_000;
const e = (tag, className, text) => {
  const node = document.createElement(tag); if (className) node.className = className;
  if (text !== undefined) node.textContent = text; return node;
};
const errorText = (error) => error instanceof Error ? error.message : String(error);
const clean = (value) => String(value || "")
  .replace(/\x1b\][^\x07]*(?:\x07|\x1b\\)/g, "")
  .replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, "");
const css = `
:root{color-scheme:dark;--bg:#111;--surface:#17191d;--surface-hover:#202329;--text:#fcfcfc;--muted:#919191;--border:#303030;--accent:#76a5ff;--danger:#ff8b88;--danger-bg:#2b171b;--danger-border:#60343c}
:root[data-theme="light"]{color-scheme:light;--bg:#fff;--surface:#f6f7f9;--surface-hover:#eceff3;--text:#17191c;--muted:#606773;--border:#d7dbe1;--accent:#3977e8;--danger:#b42318;--danger-bg:#fdeaea;--danger-border:#f4b8b2}
*{box-sizing:border-box}html,body,[data-xsec-plugin-root]{width:100%;height:100%}body{margin:0;background:var(--bg);color:var(--text)}button,select{font:inherit}[hidden]{display:none!important}
.app{display:flex;height:100%;flex-direction:column;background:var(--bg)}.screen{min-height:0;flex:1;margin:0;padding:10px 12px;overflow:auto;outline:none;color:var(--text);background:var(--bg);font:12px/1.3 ui-monospace,"SFMono-Regular",Consolas,monospace;white-space:pre-wrap;overflow-wrap:anywhere}.screen:focus-visible{box-shadow:inset 0 0 0 1px var(--accent)}
.status{flex:0 0 auto;padding:8px 12px;border-bottom:1px solid var(--danger-border);background:var(--danger-bg);color:var(--danger);font:600 12px/1.4 ui-monospace,"SFMono-Regular",Consolas,monospace;overflow-wrap:anywhere}.status:empty{display:none}
.settings{min-height:100%;padding:24px;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}.settings-card{width:min(680px,100%);padding:20px;border:1px solid var(--border);border-radius:10px;background:var(--surface)}
.settings h1{margin:0 0 6px;font-size:20px;line-height:1.3}.settings p{margin:0;color:var(--muted)}.settings label{display:grid;gap:7px;margin:20px 0 12px;color:var(--text);font-weight:600}.settings select,.settings button{min-height:36px;padding:7px 10px;border:1px solid var(--border);border-radius:7px;background:var(--bg);color:var(--text)}
.settings select:focus-visible,.settings button:focus-visible{outline:2px solid var(--accent);outline-offset:1px}.settings button{cursor:pointer;font-weight:600}.settings button:hover{background:var(--surface-hover)}.settings button:disabled{cursor:default;opacity:.55}.settings .effective{margin-top:10px}.settings .actions{display:flex;gap:8px;margin-top:16px}.settings .primary{border-color:var(--accent);background:var(--accent);color:#fff}.settings .notice{min-height:21px;margin-top:12px}.settings .notice.error{color:var(--danger)}
`;
function followHostTheme(host) {
  const apply = (theme) => {
    const bridged = getComputedStyle(document.documentElement).getPropertyValue("--xsec-color-mode").trim();
    const mode = theme?.["color-mode"] || bridged;
    document.documentElement.dataset.theme = mode === "light" ? "light" : "dark";
  };
  apply(); return host.onTheme?.(apply);
}
function replaceDocument(root) { root.replaceChildren(); root.append(e("style", "", css)); }
function settingStatus(state, message, error = false) {
  state.controls.notice.textContent = message; state.controls.notice.className = `notice${error ? " error" : ""}`;
}
function renderSettingsView(state, view) {
  const profiles = Array.isArray(view?.profiles) ? view.profiles : [];
  const isWindows = view?.platform === "windows";
  state.controls.form.hidden = !isWindows; state.controls.systemDefault.hidden = isWindows;
  if (!isWindows) {
    state.controls.systemDefault.textContent = "新建终端使用当前帐户的登录 Shell。"; return;
  }
  const available = profiles.filter((item) => WINDOWS_PROFILE_IDS.has(item.id));
  if (!available.length) throw new Error("当前 Windows 系统没有可用的终端");
  state.controls.profile.replaceChildren();
  const automatic = e("option", "", "跟随系统默认终端"); automatic.value = "";
  state.controls.profile.append(automatic);
  for (const item of available) {
    const suffix = item.is_default ? "（系统默认）" : "";
    const option = e("option", "", `${item.label || item.id}${suffix}`); option.value = item.id;
    state.controls.profile.append(option);
  }
  state.controls.profile.value = view?.configuredProfileId || "";
  const effective = available.find((item) => item.id === view?.effectiveProfileId);
  state.controls.effective.textContent = effective ? `新建终端将使用：${effective.label || effective.id}` : "";
}
async function loadSettings(host, state, generation = state.generation) {
  state.ready = false; state.controls.save.disabled = true;
  settingStatus(state, "正在读取终端设置…");
  try {
    const view = await host.request("xsec.terminal.settings.get", {});
    if (generation !== state.generation) return;
    renderSettingsView(state, view);
    state.ready = true; state.controls.save.disabled = false;
    settingStatus(state, "");
  } catch (error) {
    if (generation === state.generation) settingStatus(state, `读取终端设置失败：${errorText(error)}`, true);
  }
}
async function saveSettings(host, state) {
  if (!state.ready) return;
  const generation = state.generation;
  state.controls.save.disabled = true;
  try {
    await host.request("xsec.terminal.settings.set", { profileId: state.controls.profile.value || null });
    if (generation !== state.generation) return;
    await loadSettings(host, state, generation);
    if (generation === state.generation && state.ready) {
      settingStatus(state, "默认终端已保存，仅影响之后新建的终端。");
    }
  } catch (error) {
    if (generation === state.generation) {
      settingStatus(state, `保存终端设置失败：${errorText(error)}`, true);
      state.controls.save.disabled = false;
    }
  }
}
function buildSettings(host, state) {
  replaceDocument(state.root);
  const page = e("main", "settings"), card = e("section", "settings-card"), form = e("div");
  const label = e("label", "", "Windows 默认终端"), profile = e("select");
  const effective = e("p", "effective"), systemDefault = e("p"), actions = e("div", "actions");
  const save = e("button", "primary", "保存"), notice = e("p", "notice");
  form.hidden = true; systemDefault.hidden = true;
  save.disabled = true;
  save.onclick = () => void saveSettings(host, state);
  label.append(profile);
  actions.append(save);
  form.append(label, effective, actions);
  card.append(e("h1", "", "系统终端"), e("p", "", "设置之后新建终端使用的 Shell。"), form, systemDefault, notice);
  page.append(card);
  state.root.append(page);
  state.controls = { form, profile, effective, systemDefault, save, notice };
  void loadSettings(host, state);
}
function terminalSettings(host) {
  const state = { root: undefined, controls: {}, ready: false, generation: 0, theme: undefined };
  return {
    mount(root) {
      state.root = root; state.generation += 1; console.info("system-terminal.settings.mount");
      state.theme = followHostTheme(host); buildSettings(host, state);
    },
    update() {},
    dispose() { console.debug("system-terminal.settings.dispose"); state.generation += 1; state.theme?.dispose(); state.theme = undefined; },
  };
}
function clearPoll(state) { if (state.pollTimer) clearTimeout(state.pollTimer); state.pollTimer = 0; }
function report(state, message) { state.controls.status.textContent = message; }
async function failTerminal(host, state, message) {
  if (state.failed) return;
  state.failed = true; state.reading = false; state.writing = false; state.inputBuffer = ""; clearPoll(state);
  const generation = state.generation, terminalId = state.terminalId; state.terminalId = "";
  let closeError;
  try { if (terminalId) await host.request("xsec.terminal.close", { terminalId }); }
  catch (error) { closeError = error; }
  if (generation !== state.generation) return;
  report(state, closeError ? `${message}；关闭终端失败：${errorText(closeError)}` : message);
}
function appendScreen(state, value) {
  const text = state.controls.screenText; text.appendData(clean(value));
  const overflow = text.length - MAX_SCROLLBACK_CHARACTERS;
  if (overflow > 0) text.deleteData(0, overflow);
  state.controls.screen.scrollTop = state.controls.screen.scrollHeight;
}
function isCurrentTerminal(state, generation, terminalId) { return generation === state.generation && terminalId === state.terminalId; }
function schedulePoll(host, state, delay = ACTIVE_POLL_INTERVAL_MS) {
  clearPoll(state);
  if (state.disposed || state.failed || !state.terminalId || document.hidden) return;
  state.pollTimer = setTimeout(() => void poll(host, state), delay);
}
async function poll(host, state) {
  if (state.disposed || state.failed || !state.terminalId || state.reading || document.hidden) return;
  const generation = state.generation, terminalId = state.terminalId;
  let nextDelay = 0;
  state.reading = true;
  try {
    const data = await host.request("xsec.terminal.read", { terminalId });
    if (!isCurrentTerminal(state, generation, terminalId)) return;
    if (data?.data) appendScreen(state, data.data);
    nextDelay = data?.data ? ACTIVE_POLL_INTERVAL_MS : IDLE_POLL_INTERVAL_MS;
  } catch (error) {
    if (isCurrentTerminal(state, generation, terminalId)) {
      await failTerminal(host, state, `读取终端失败：${errorText(error)}`);
    }
  } finally {
    if (isCurrentTerminal(state, generation, terminalId)) {
      state.reading = false;
      if (nextDelay) schedulePoll(host, state, nextDelay);
    }
  }
}
function terminalSize(state) { return {
  cols: Math.max(MIN_COLUMNS, Math.floor(state.controls.screen.clientWidth / CELL_WIDTH)),
  rows: Math.max(MIN_ROWS, Math.floor(state.controls.screen.clientHeight / CELL_HEIGHT)),
}; }
async function terminalOpenOptions(host, state) {
  if (!/Windows/i.test(navigator.userAgent)) return terminalSize(state);
  const settings = await host.request("xsec.terminal.settings.get", {});
  return { ...terminalSize(state), profileId: settings?.effectiveProfileId || undefined };
}
async function openTerminal(host, state, generation) {
  state.controls.status.textContent = "";
  state.controls.screenText.data = "";
  try {
    const options = await terminalOpenOptions(host, state);
    if (generation !== state.generation) return;
    const handle = await host.request("xsec.terminal.open", options);
    if (generation !== state.generation) {
      await host.request("xsec.terminal.close", { terminalId: handle.terminal_id });
      return;
    }
    state.terminalId = handle.terminal_id;
    state.controls.screen.focus();
    resizeTerminal(host, state);
    schedulePoll(host, state, 0);
  } catch (error) {
    if (generation !== state.generation) return;
    await failTerminal(host, state, `启动终端失败：${errorText(error)}`);
  }
}
function scheduleWrite(host, state) {
  if (state.inputFrame || state.writing || !state.inputBuffer) return;
  state.inputFrame = requestAnimationFrame(() => {
    state.inputFrame = 0;
    void flushWrite(host, state);
  });
}
async function flushWrite(host, state) {
  if (state.failed || state.writing || !state.inputBuffer || !state.terminalId) return;
  const generation = state.generation, terminalId = state.terminalId, data = state.inputBuffer;
  state.inputBuffer = "";
  state.writing = true;
  try {
    await host.request("xsec.terminal.write", { terminalId, data });
  } catch (error) {
    if (isCurrentTerminal(state, generation, terminalId)) {
      await failTerminal(host, state, `写入终端失败：${errorText(error)}`);
    }
  } finally {
    if (isCurrentTerminal(state, generation, terminalId)) {
      state.writing = false;
      scheduleWrite(host, state);
    }
  }
}
function keyInput(host, state, event) {
  if (state.failed || !state.terminalId) return;
  if (event.ctrlKey && event.key.toLowerCase() === "c") {
    event.preventDefault();
    state.inputBuffer += "\x03";
    scheduleWrite(host, state);
    return;
  }
  const map = { Enter: "\r", Backspace: "\x7f", Tab: "\t", ArrowUp: "\x1b[A", ArrowDown: "\x1b[B", ArrowRight: "\x1b[C", ArrowLeft: "\x1b[D", Escape: "\x1b" };
  const data = map[event.key] || (event.key.length === 1 && !event.ctrlKey && !event.metaKey ? event.key : "");
  if (!data) return;
  event.preventDefault();
  state.inputBuffer += data;
  scheduleWrite(host, state);
}
function resizeTerminal(host, state) {
  if (state.failed || !state.terminalId) return;
  const generation = state.generation, terminalId = state.terminalId;
  const resizeGeneration = ++state.resizeGeneration;
  void host.request("xsec.terminal.resize", {
    terminalId,
    ...terminalSize(state),
  }).catch(async (error) => {
    if (resizeGeneration === state.resizeGeneration && isCurrentTerminal(state, generation, terminalId)) {
      await failTerminal(host, state, `调整终端大小失败：${errorText(error)}`);
    }
  });
}
function buildTerminal(host, state) {
  replaceDocument(state.root);
  const app = e("main", "app"), status = e("div", "status"), screen = e("pre", "screen", "");
  screen.tabIndex = 0;
  screen.setAttribute("role", "application");
  screen.setAttribute("aria-label", "系统终端");
  screen.append(document.createTextNode(""));
  screen.onkeydown = (event) => keyInput(host, state, event);
  app.append(status, screen);
  state.root.append(app);
  state.controls = { status, screen, screenText: screen.firstChild };
  state.observer = new ResizeObserver(() => {
    clearTimeout(state.resizeTimer);
    state.resizeTimer = setTimeout(() => resizeTerminal(host, state), RESIZE_DELAY_MS);
  });
  state.observer.observe(screen);
  state.visibility = () => document.hidden ? clearPoll(state) : schedulePoll(host, state);
  document.addEventListener("visibilitychange", state.visibility);
  const generation = state.generation;
  state.opening = openTerminal(host, state, generation);
  void state.opening.catch(() => {});
}
async function disposeTerminal(host, state) {
  const terminalId = state.terminalId, opening = state.opening, theme = state.theme;
  state.generation += 1;
  state.disposed = true; state.failed = false; state.terminalId = "";
  state.reading = false; state.writing = false; state.inputBuffer = "";
  clearPoll(state);
  clearTimeout(state.resizeTimer);
  cancelAnimationFrame(state.inputFrame);
  state.inputFrame = 0;
  state.observer?.disconnect();
  theme?.dispose();
  state.theme = undefined;
  document.removeEventListener("visibilitychange", state.visibility);
  if (opening) await opening;
  if (terminalId) await host.request("xsec.terminal.close", { terminalId });
}
function terminalSurface(host) {
  const state = {
    root: undefined, controls: {}, terminalId: "", disposed: false, failed: false,
    reading: false, writing: false, inputBuffer: "", pollTimer: 0,
    resizeTimer: 0, resizeGeneration: 0, inputFrame: 0, observer: undefined, visibility: undefined,
    theme: undefined, opening: undefined, generation: 0,
  };
  return {
    mount(root) {
      state.root = root; state.generation += 1; console.info("system-terminal.surface.mount");
      state.disposed = false; state.failed = false;
      state.theme = followHostTheme(host); buildTerminal(host, state);
    },
    update() {},
    dispose() { console.debug("system-terminal.surface.dispose"); return disposeTerminal(host, state); },
  };
}
export function activate(host) {
  console.debug("system-terminal.activate", { kind: host.context?.kind }); if (host.context?.kind === "settings-page") return terminalSettings(host);
  return terminalSurface(host);
}
