import type { TrafficSummary } from "./types";

const BYTES_PER_KIBIBYTE = 1024;
const ONE_DECIMAL_KIBIBYTE_LIMIT = 10 * BYTES_PER_KIBIBYTE;

/** Format bytes for display. */
export function formatBytes(value: number): string {
  if (value < BYTES_PER_KIBIBYTE) return `${value} B`;
  const decimals = value < ONE_DECIMAL_KIBIBYTE_LIMIT ? 1 : 0;
  return `${(value / BYTES_PER_KIBIBYTE).toFixed(decimals)} KiB`;
}

/** Format time for display. */
export function formatTime(value: number): string {
  return new Date(value).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

/** Format the request path and query string for the traffic table. */
export function requestTarget(row: TrafficSummary): string {
  const query = row.query?.replace(/^\?/, "");
  if (query && !row.path.includes("?")) return `${row.path}?${query}`;
  try {
    const url = new URL(row.url);
    return `${url.pathname}${url.search}`;
  } catch {
    return row.path || row.url;
  }
}

/** Format a host and optional port for display. */
export function hostLabel(row: TrafficSummary): string {
  const normalized = row.host.includes(":") && !row.host.startsWith("[") ? `[${row.host}]` : row.host;
  return row.port ? `${normalized}:${row.port}` : normalized;
}

/** Map a MIME category to its accepted table label. */
export function mimeLabel(value: TrafficSummary["mime_category"]): string {
  return ({ html: "HTML", script: "脚本", xml: "XML", otherText: "文本 / JSON", css: "CSS", images: "图片", otherBinary: "二进制", unknown: "未知" } as Record<string, string>)[value ?? "unknown"] ?? "未知";
}

/** Map a traffic source to its accepted table label. */
export function sourceLabel(value: string): string {
  return value === "replay" ? "重放" : value === "proxy" ? "代理" : value || "未知";
}

/** Format an optional extension with the accepted empty placeholder. */
export function extensionLabel(value: string | null | undefined): string {
  if (!value) return "—";
  return `.${value.replace(/^\.+/, "")}`;
}

/** Format parameter presence for the compact request column. */
export function compactParameterLabel(value: boolean | undefined): string {
  if (value === undefined) return "未知";
  return value ? "有参" : "无参";
}

/** Format parameter presence for the full parameters column. */
export function parameterLabel(value: boolean | undefined): string {
  if (value === undefined) return "—";
  return value ? "有" : "无";
}

/** Select the semantic CSS class for an HTTP method. */
export function methodClass(method: string): string {
  const value = method.toLowerCase();
  return ["get", "post", "delete"].includes(value) ? `method-${value}` : "method-other";
}

/** Select the semantic CSS class for an HTTP response status. */
export function statusClass(status: number | null | undefined): string {
  if (status == null) return "status-empty";
  if (status < 200) return "status-informational";
  if (status < 300) return "status-success";
  if (status < 400) return "status-redirection";
  if (status < 500) return "status-client";
  return "status-server";
}
