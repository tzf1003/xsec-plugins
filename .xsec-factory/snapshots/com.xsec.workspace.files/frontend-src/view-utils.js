export function element(name, className, content) {
  const node = document.createElement(name);
  if (className) node.className = className;
  if (content !== undefined) node.textContent = content;
  return node;
}

export function actionButton(className, label, onClick) {
  const button = element("button", className);
  button.type = "button";
  button.setAttribute("aria-label", label);
  button.addEventListener("click", onClick);
  return button;
}

export function errorPanel(message, retry) {
  const panel = element("section", "project-files-error", message);
  if (retry) {
    const button = actionButton("project-files-retry", "重试", retry);
    button.textContent = "重试";
    panel.append(button);
  }
  return panel;
}

export function emptyPanel(message) {
  return element("section", "project-files-empty", message);
}

export function noticePanel(message) {
  const notice = element("div", "project-files-notice", message);
  notice.setAttribute("aria-live", "polite");
  notice.setAttribute("role", "status");
  return notice;
}

export function loadingPanel(rows = 8) {
  const panel = element("section", "project-files-loading");
  for (let index = 0; index < rows; index += 1) panel.append(element("span", "project-files-loading-row"));
  return panel;
}

export function focusLater(selector) {
  queueMicrotask(() => document.querySelector(selector)?.focus());
}
