import { formatFileSize } from "./model.js";
import { icon } from "./icons.js";
import { actionButton, element, emptyPanel, errorPanel, loadingPanel, noticePanel } from "./view-utils.js";

function entryAction(controller, entry) {
  return entry.isDirectory ? () => { void controller.toggleDirectory(entry); } : () => { void controller.openFile(entry); };
}

function addButton(controller, entry) {
  const label = `添加 ${entry.name} 到会话`;
  const button = actionButton("file-tree-add-action", label, () => { void controller.addPath(entry); });
  const busy = controller.state.addingPaths.has(entry.path);
  button.disabled = !controller.composerWritable || busy;
  button.title = controller.composerWritable ? "添加到会话" : "当前会话不可编辑";
  if (busy) button.setAttribute("aria-busy", "true");
  button.append(icon("at"));
  return button;
}

function row(controller, entry, depth) {
  const branch = element("div", "file-tree-branch");
  const item = element("div", "file-tree-row");
  item.style.setProperty("--file-tree-depth", String(depth));
  const main = actionButton("file-tree-main-action", entry.isDirectory ? `展开 ${entry.name}` : `打开 ${entry.name}`, entryAction(controller, entry));
  main.setAttribute("role", "treeitem");
  const expanded = controller.state.expanded.has(entry.path);
  if (entry.isDirectory) main.setAttribute("aria-expanded", String(expanded));
  const chevron = element("span", "file-tree-chevron");
  if (entry.isDirectory) chevron.append(icon(expanded ? "chevronDown" : "chevronRight"));
  const name = element("span", "file-tree-name", entry.name);
  const metadata = element("small", "file-tree-metadata", entry.isDirectory && controller.state.loadingDirectories.has(entry.path) ? "加载中…" : entry.isDirectory ? "" : formatFileSize(entry.size));
  main.append(chevron, icon(entry.isDirectory ? "folder" : "file"), name, metadata);
  item.append(main, addButton(controller, entry));
  branch.append(item);
  if (entry.isDirectory && expanded) appendDirectory(branch, controller, entry.path, depth + 1);
  return branch;
}

function appendDirectory(parent, controller, directory, depth) {
  const files = controller.state.filesByDirectory.get(directory);
  const error = controller.state.directoryErrors.get(directory);
  if (error) {
    parent.append(errorPanel(error, () => { void controller.loadDirectory(directory); }));
    return;
  }
  if (!files) {
    parent.append(loadingPanel(3));
    return;
  }
  for (const entry of files) parent.append(row(controller, entry, depth));
}

function toolbar(controller) {
  const header = element("header", "project-files-toolbar");
  header.append(element("strong", "", "项目文件"));
  const refresh = actionButton("project-files-refresh", "刷新项目文件", () => controller.refresh());
  refresh.disabled = controller.state.loadingDirectories.has("");
  refresh.textContent = "刷新";
  header.append(refresh);
  return header;
}

export function renderTree(controller) {
  const rootFiles = controller.state.filesByDirectory.get("");
  const rootError = controller.state.directoryErrors.get("");
  const view = element("section", "project-files-view");
  if (controller.state.actionError) view.append(errorPanel(controller.state.actionError));
  if (controller.state.actionNotice) view.append(noticePanel(controller.state.actionNotice));
  view.append(toolbar(controller));
  if (rootError && !rootFiles) {
    view.append(errorPanel(rootError, () => { void controller.loadDirectory(""); }));
    return view;
  }
  if (!rootFiles && controller.state.loadingDirectories.has("")) {
    view.append(loadingPanel());
    return view;
  }
  if (!rootFiles?.length) {
    view.append(emptyPanel(controller.contextKey ? "项目目录为空" : "尚未绑定工作区"));
    return view;
  }
  const tree = element("div", "file-tree");
  tree.setAttribute("aria-label", "项目文件");
  tree.setAttribute("role", "tree");
  for (const entry of rootFiles) tree.append(row(controller, entry, 0));
  view.append(tree);
  return view;
}
