export function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

export function button(className, text, label) {
  const node = element("button", className, text);
  node.type = "button";
  if (label) node.setAttribute("aria-label", label);
  return node;
}

export function svgElement(tag, attributes = {}) {
  const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [name, value] of Object.entries(attributes)) node.setAttribute(name, String(value));
  return node;
}

export function shortText(value, length = 52) {
  const normalized = String(value ?? "").replace(/\s+/g, " ").trim();
  if (!normalized) return "（空消息）";
  return normalized.length <= length ? normalized : `${normalized.slice(0, length)}…`;
}

export function formatTime(value, full = false) {
  if (!Number.isFinite(value)) throw new Error("conversation_tree_invalid_timestamp");
  const options = full
    ? { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }
    : { hour: "2-digit", minute: "2-digit", hour12: false };
  return new Date(value).toLocaleString("zh-CN", options);
}

export function displayValue(value) {
  if (value === null || value === undefined || value === "") return "未记录";
  if (typeof value === "string") return value;
  return JSON.stringify(value);
}

export function factList(className, fields) {
  const list = element("dl", className);
  for (const [label, value, title] of fields) {
    const description = element("dd", "", String(value));
    if (title) description.title = title;
    list.append(element("dt", "", label), description);
  }
  return list;
}
