const SVG_NAMESPACE = "http://www.w3.org/2000/svg";
const ICON_SIZE = "16";

const iconPaths = {
  at: ["circle:12:12:4", "path:M16 8v1a4 4 0 0 1-8 0v-1a4 4 0 0 1 8 0Z", "path:M16 8v4a2 2 0 0 0 4 0v-1a8 8 0 1 0-3 6"],
  chevronDown: ["path:M6 9l6 6 6-6"],
  chevronRight: ["path:M9 6l6 6-6 6"],
  file: ["path:M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z", "path:M14 2v6h6", "path:M8 13h8", "path:M8 17h8"],
  folder: ["path:M3 7a2 2 0 0 1 2-2h5l2 2h7a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z", "path:M3 9h18"],
  message: ["path:M21 11.5a8.4 8.4 0 0 1-9 8.4 8.6 8.6 0 0 1-3.7-.9L3 21l1.8-4.6a8.4 8.4 0 0 1-.9-3.9 8.4 8.4 0 0 1 8.4-8.4 8.5 8.5 0 0 1 8.7 7.5Z"],
};

function svgElement(name) {
  return document.createElementNS(SVG_NAMESPACE, name);
}

function appendShape(svg, descriptor) {
  const [kind, ...values] = descriptor.split(":");
  const node = svgElement(kind);
  if (kind === "circle") ["cx", "cy", "r"].forEach((name, index) => node.setAttribute(name, values[index]));
  if (kind === "path") node.setAttribute("d", values.join(":"));
  svg.append(node);
}

export function icon(name) {
  const svg = svgElement("svg");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("fill", "none");
  svg.setAttribute("height", ICON_SIZE);
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("stroke-width", "2");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("width", ICON_SIZE);
  for (const descriptor of iconPaths[name] ?? []) appendShape(svg, descriptor);
  return svg;
}
