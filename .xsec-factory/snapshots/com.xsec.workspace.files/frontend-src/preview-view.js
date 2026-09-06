import { icon } from "./icons.js";
import { MAX_PREVIEW_LINES, previewLines } from "./model.js";
import { actionButton, element, errorPanel, focusLater, loadingPanel, noticePanel } from "./view-utils.js";

function composerButton(controller, file) {
  const button = actionButton("project-file-header-action", `添加 ${file.name} 到会话`, () => { void controller.addPath(file); });
  const busy = controller.state.addingPaths.has(file.path);
  button.disabled = !controller.composerWritable || busy;
  button.title = controller.composerWritable ? "添加到会话" : "当前会话不可编辑";
  if (busy) button.setAttribute("aria-busy", "true");
  button.append(icon("at"));
  return button;
}

function commentEditor(controller, lineNumber, code) {
  const editor = element("form", "file-line-comment-editor");
  const heading = element("div", "file-line-comment-heading");
  heading.append(icon("message"), element("strong", "", "本地评论"), element("small", "", `对第 ${lineNumber} 行发表评论`));
  const input = document.createElement("textarea");
  input.dataset.commentInput = "";
  input.placeholder = "输入给 Agent 的评论…";
  input.value = controller.state.comment;
  let submit;
  input.addEventListener("input", () => {
    controller.state.comment = input.value;
    if (submit) submit.disabled = !controller.composerWritable || !input.value.trim();
  });
  input.addEventListener("keydown", (event) => {
    if ((event.metaKey || event.ctrlKey) && event.key === "Enter") {
      event.preventDefault();
      void controller.submitComment(lineNumber, code);
    }
  });
  const footer = element("footer", "file-line-comment-footer");
  const cancel = actionButton("", "取消评论", () => controller.cancelComment());
  cancel.textContent = "取消";
  submit = actionButton("project-files-primary", "添加到对话框", () => { void controller.submitComment(lineNumber, code); });
  submit.disabled = !controller.composerWritable || controller.state.submittingComment || !input.value.trim();
  if (controller.state.submittingComment) submit.setAttribute("aria-busy", "true");
  submit.textContent = "添加到对话框";
  editor.addEventListener("submit", (event) => { event.preventDefault(); void controller.submitComment(lineNumber, code); });
  footer.append(cancel, submit);
  editor.append(heading, input, footer);
  focusLater("[data-comment-input]");
  return editor;
}

function codeRows(controller) {
  const table = element("div", "project-file-code");
  table.setAttribute("aria-label", `${controller.state.selected.name} 文件内容`);
  table.setAttribute("role", "table");
  const preview = previewLines(controller.state.content);
  preview.lines.forEach((code, index) => {
    const lineNumber = index + 1;
    const line = element("div", `project-file-line${controller.state.commentLine === lineNumber ? " is-commenting" : ""}`);
    line.setAttribute("role", "row");
    const trigger = actionButton("file-line-comment-trigger", `评论第 ${lineNumber} 行`, () => controller.startComment(lineNumber));
    trigger.disabled = !controller.composerWritable;
    trigger.append(icon("message"));
    line.append(trigger, element("span", "file-line-number", String(lineNumber)), element("code", "", code || " "));
    if (controller.state.commentLine === lineNumber) line.append(commentEditor(controller, lineNumber, code));
    table.append(line);
  });
  return { table, truncated: preview.truncated };
}

export function renderPreview(controller) {
  const file = controller.state.selected;
  const view = element("section", "project-files-view has-preview");
  const preview = element("section", "project-file-preview");
  const header = element("header", "");
  const back = actionButton("project-file-header-action", "返回项目文件树", () => controller.closeFile());
  back.append(icon("folder"));
  header.append(back, element("strong", "", file.name), element("small", "", file.path), composerButton(controller, file));
  preview.append(header);
  if (controller.state.actionError) preview.append(errorPanel(controller.state.actionError));
  if (controller.state.actionNotice) preview.append(noticePanel(controller.state.actionNotice));
  if (controller.state.previewError) preview.append(errorPanel(controller.state.previewError, () => { void controller.openFile(file); }));
  else if (controller.state.fileLoading) preview.append(loadingPanel());
  else {
    const code = codeRows(controller);
    preview.append(code.table);
    if (code.truncated) preview.append(noticePanel(`文件行数较多，仅显示前 ${MAX_PREVIEW_LINES.toLocaleString()} 行`));
  }
  view.append(preview);
  return view;
}
