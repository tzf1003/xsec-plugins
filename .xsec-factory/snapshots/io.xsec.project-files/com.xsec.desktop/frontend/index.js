const LIST = "xsec.files.list";
const READ = "xsec.files.read";
const ADD = "xsec.workspace.composer.path.add";

const styles = `
:host,body{margin:0;background:#f7f8fb;color:#172033;font:13px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
*{box-sizing:border-box}.pf{height:100%;min-height:320px;display:grid;grid-template-rows:auto 1fr;container-type:inline-size}
.pf-head{padding:14px 16px 12px;background:#fff;border-bottom:1px solid #e4e8f0;display:flex;gap:10px;align-items:center}.pf-title{font-size:15px;font-weight:700;white-space:nowrap}.pf-count{color:#8a93a5;font-size:11px}
.pf-input{min-width:80px;flex:1;border:1px solid #dbe1eb;border-radius:8px;padding:7px 10px;background:#fbfcfe;color:inherit;outline:none}.pf-input:focus{border-color:#6b8afd;box-shadow:0 0 0 3px #6b8afd22}
.pf-main{min-height:0;display:grid;grid-template-columns:minmax(190px,42%) 1fr}.pf-list{min-width:0;overflow:auto;border-right:1px solid #e4e8f0;background:#fff;padding:8px}.pf-preview{min-width:0;overflow:auto;padding:16px}.pf-toolbar{display:flex;gap:6px;margin-bottom:10px}.pf-btn{border:1px solid #dbe1eb;background:#fff;border-radius:7px;padding:6px 9px;color:#43506a;cursor:pointer}.pf-btn:hover{border-color:#6b8afd;color:#355de5}.pf-btn.primary{background:#3567f4;border-color:#3567f4;color:#fff}.pf-row{display:flex;align-items:center;gap:7px;width:100%;padding:7px 8px;border:0;border-radius:7px;background:transparent;color:inherit;text-align:left;cursor:pointer}.pf-row:hover{background:#f0f3fa}.pf-row.selected{background:#e9efff;color:#2457dc}.pf-indent{width:var(--indent);flex:0 0 var(--indent)}.pf-chevron{width:13px;color:#8490a6}.pf-icon{width:17px;text-align:center}.pf-name{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.pf-size{margin-left:auto;color:#9aa3b4;font-size:11px}.pf-empty{height:100%;display:grid;place-items:center;color:#8b95a8;text-align:center}.pf-card{max-width:960px;margin:0 auto;background:#fff;border:1px solid #e4e8f0;border-radius:12px;overflow:hidden;box-shadow:0 8px 24px #18233d0a}.pf-card-head{display:flex;align-items:center;gap:8px;padding:12px 15px;border-bottom:1px solid #edf0f5}.pf-card-title{font-weight:700;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.pf-meta{margin-left:auto;color:#8d97aa;font-size:11px}.pf-code{margin:0;padding:14px 16px;overflow:auto;background:#111827;color:#d7e0ef;font:12px/1.7 ui-monospace,SFMono-Regular,Menlo,monospace;counter-reset:line}.pf-line{display:block;white-space:pre;min-height:1.7em}.pf-line:before{content:counter(line);counter-increment:line;display:inline-block;width:36px;margin-right:16px;color:#66738b;text-align:right;user-select:none}.tok-key{color:#93c5fd}.tok-str{color:#86efac}.tok-com{color:#94a3b8}.tok-num{color:#fbbf24}.pf-bubble{position:fixed;right:14px;bottom:14px;padding:8px 12px;border-radius:9px;background:#153d2b;color:#b9f7ce;box-shadow:0 8px 22px #153d2b33;opacity:0;transform:translateY(6px);transition:.2s;pointer-events:none}.pf-bubble.show{opacity:1;transform:none}
@container (max-width:620px){.pf-main{grid-template-columns:1fr;grid-template-rows:minmax(150px,42%) 1fr}.pf-list{border-right:0;border-bottom:1px solid #e4e8f0}.pf-preview{padding:10px}}
`;

const esc = (value) => String(value).replace(/[&<>"']/g, (char) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[char]));
const size = (bytes) => bytes < 1024 ? `${bytes} B` : bytes < 1_048_576 ? `${(bytes / 1024).toFixed(1)} KB` : `${(bytes / 1_048_576).toFixed(1)} MB`;
const lang = (path) => path.split(".").pop()?.toLowerCase() || "text";
function highlight(line, extension) {
  const source = String(line);
  const supported = ["js","ts","jsx","tsx","py","java","go","rs","json","css","html"];
  if (!supported.includes(extension)) return esc(source) || " ";
  const comment = extension === "py" ? "#.*$" : extension === "html" ? "<!--.*?-->" : "\\/\\/.*$";
  const token = new RegExp(`${comment}|\"(?:\\\\.|[^\"\\\\])*\"|'(?:\\\\.|[^'\\\\])*'|\`(?:\\\\.|[^\`\\\\])*\`|\\b\\d+(?:\\.\\d+)?\\b|\\b(?:const|let|var|function|return|if|else|for|while|class|import|from|export|async|await|def|true|false|null|new|public|private)\\b`, "g");
  let cursor = 0, html = "";
  for (const match of source.matchAll(token)) {
    html += esc(source.slice(cursor, match.index));
    const value = match[0];
    const style = /^(?:\/\/|#|<!--)/.test(value) ? "tok-com" : /^[\"'`]/.test(value) ? "tok-str" : /^\d/.test(value) ? "tok-num" : "tok-key";
    html += `<span class="${style}">${esc(value)}</span>`;
    cursor = match.index + value.length;
  }
  return html + esc(source.slice(cursor)) || " ";
}

function projectId(host) { return host.context?.workspace?.binding?.projectId ?? host.context?.project?.id; }
function createController(host) {
  let root, current, selected, query = "", loading = false;
  const directories = new Map(), children = new Map();
  const bubble = (message, error = false) => {
    const node = root?.querySelector(".pf-bubble"); if (!node) return;
    node.textContent = message; node.style.background = error ? "#5c2028" : "#153d2b"; node.classList.add("show");
    clearTimeout(bubble.timer); bubble.timer = setTimeout(() => node.classList.remove("show"), 2400);
  };
  const request = (method, params = {}) => host.request(method, params);
  const load = async (directory = "") => {
    if (loading) return; loading = true; render();
    try {
      const result = await request(LIST, directory ? { directory } : {});
      if (!Array.isArray(result?.files)) throw new Error("项目文件列表返回格式无效");
      directories.set(directory, true); children.set(directory, result.files);
      console.info("project-files.list", { directory, count: result.files.length });
    } catch (error) { console.error("project-files.list.failed", error); bubble(error.message || "读取目录失败", true); }
    finally { loading = false; render(); }
  };
  const visible = () => [...children.values()].flat().filter((file) => !query || file.path.toLowerCase().includes(query.toLowerCase()));
  const row = (file, depth) => {
    const active = selected?.path === file.path;
    return `<button class="pf-row${active ? " selected" : ""}" data-path="${esc(file.path)}" data-dir="${file.is_dir}" style="--indent:${depth * 15}px"><span class="pf-indent"></span><span class="pf-chevron">${file.is_dir ? (directories.has(file.path) ? "⌄" : "›") : ""}</span><span class="pf-icon">${file.is_dir ? "▰" : "▤"}</span><span class="pf-name">${esc(file.name)}</span><span class="pf-size">${file.is_dir ? "" : size(file.size)}</span></button>`;
  };
  const tree = (directory = "", depth = 0) => (children.get(directory) || []).filter((file) => !query || file.path.toLowerCase().includes(query.toLowerCase())).sort((a, b) => Number(b.is_dir) - Number(a.is_dir) || a.name.localeCompare(b.name)).map((file) => row(file, depth) + (file.is_dir && directories.has(file.path) ? tree(file.path, depth + 1) : "")).join("");
  const preview = () => {
    if (!selected) return `<div class="pf-empty"><div><strong>选择一个文件开始预览</strong><br><span>宽度足够时在右侧展示，窄屏自动移到底部</span></div></div>`;
    if (selected.is_dir) return `<div class="pf-empty"><div><strong>${esc(selected.name)}</strong><br><span>目录已展开，文件内容保持只读</span></div></div>`;
    if (!("content" in selected)) return `<div class="pf-empty"><div>正在读取 ${esc(selected.name)}…</div></div>`;
    const lines = selected.content.split("\n").map((line) => `<span class="pf-line">${highlight(line, lang(selected.path))}</span>`).join("");
    return `<article class="pf-card"><header class="pf-card-head"><span>▤</span><span class="pf-card-title">${esc(selected.name)}</span><span class="pf-meta">${esc(selected.path)} · ${size(selected.size)}</span><button class="pf-btn primary" data-add="1">添加到会话</button></header><pre class="pf-code">${lines}</pre></article>`;
  };
  const render = () => { if (!root) return; root.querySelector(".pf-count").textContent = `${visible().length} 项`; root.querySelector(".pf-list").innerHTML = loading ? `<div class="pf-empty">读取中…</div>` : tree(); root.querySelector(".pf-preview").innerHTML = preview(); };
  const bind = () => {
    root.querySelector(".pf-input").addEventListener("input", (event) => { query = event.target.value; render(); });
    root.addEventListener("click", async (event) => {
      const button = event.target.closest("[data-path]");
      if (button) {
        const path = button.dataset.path; const file = [...children.values()].flat().find((item) => item.path === path); if (!file) return;
        selected = file; if (file.is_dir && !directories.has(path)) await load(path);
        if (!file.is_dir) { try { selected = { ...file, ...(await request(READ, { path })) }; console.info("project-files.read", { path }); } catch (error) { console.error("project-files.read.failed", error); bubble(error.message || "读取文件失败", true); } }
        render(); return;
      }
      if (event.target.closest("[data-add]") && selected) { try { await request(ADD, { path: selected.path, expectedIsDirectory: false }); bubble(`已将“${selected.name}”添加到会话`); } catch (error) { console.error("project-files.composer.failed", error); bubble(error.message || "添加失败", true); } }
    });
  };
  return { mount(element) { root = element; root.innerHTML = `<style>${styles}</style><section class="pf"><header class="pf-head"><span class="pf-title">项目文件</span><span class="pf-count">0 项</span><input class="pf-input" placeholder="搜索文件…" aria-label="搜索文件" /></header><main class="pf-main"><nav class="pf-list" aria-label="项目文件树"></nav><section class="pf-preview" aria-live="polite"></section></main><div class="pf-bubble" role="status"></div></section>`; bind(); console.debug("project-files.mount"); void load(); }, update() { render(); }, dispose() { console.debug("project-files.dispose"); root?.replaceChildren(); } };
}

export function activate(host) { console.debug("project-files.activate", { projectId: projectId(host) }); return createController(host); }
