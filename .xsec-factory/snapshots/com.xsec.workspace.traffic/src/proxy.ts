import type { FlowSection, FlowSnapshot, TrafficDetail } from "./types";

/** Normalize an optional stored flow payload into a readable snapshot. */
export function flowSnapshot(value: unknown): FlowSnapshot {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  return value as FlowSnapshot;
}

/** Normalize object or tuple headers into ordered name-value pairs. */
export function headerPairs(headers?: FlowSection["headers"]): [string, string][] {
  if (Array.isArray(headers)) return headers;
  return headers ? Object.entries(headers) : [];
}

/** Render a message start line, headers, and body as raw HTTP text. */
export function renderSection(section?: FlowSection): string {
  if (!section) return "";
  const lines = section.line ? [section.line] : [];
  for (const [name, value] of headerPairs(section.headers)) lines.push(`${name}: ${value}`);
  const head = lines.join("\r\n");
  return section.body === undefined ? head : `${head}\r\n\r\n${section.body}`;
}

/** Resolve raw request text from a traffic-detail payload. */
export function requestRaw(detail: TrafficDetail): string {
  const snapshot = flowSnapshot(detail.payload);
  return snapshot.raw_request ?? renderSection(snapshot.request);
}

/** Resolve raw response text from a traffic-detail payload. */
export function responseRaw(detail: TrafficDetail): string {
  const snapshot = flowSnapshot(detail.payload);
  return snapshot.raw_response ?? renderSection(snapshot.response);
}

/** Format body for readable display. */
export function prettyBody(body?: string): string {
  if (!body) return "";
  try {
    return JSON.stringify(JSON.parse(body), null, 2);
  } catch {
    return body;
  }
}

/** Determine whether sensitive host confirmation is required. */
export function requiresSensitiveHostConfirmation(options: {
  sourceHost: string;
  sourcePort: number | null | undefined;
  sourceScheme: string;
  targetHost: string;
  targetPort: number;
  targetScheme: "http" | "https";
  rawRequest: string;
}): boolean {
  if (!hasSensitiveHeaders(options.rawRequest)) return false;
  const sourceOrigin = endpointOrigin(options.sourceHost, options.sourcePort, options.sourceScheme);
  const targetOrigin = endpointOrigin(options.targetHost, options.targetPort, options.targetScheme);
  if (!sourceOrigin || !targetOrigin || !sameOrigin(sourceOrigin, targetOrigin)) return true;
  return !requestAuthoritiesMatchSource(options.rawRequest, sourceOrigin);
}

type ReplayOrigin = { scheme: "http" | "https"; host: string; port: number };

/** Detect authorization or cookie headers in the request head. */
function hasSensitiveHeaders(rawRequest: string): boolean {
  const normalized = rawRequest.replace(/\r\n/gu, "\n");
  const head = normalized.split("\n\n", 1)[0] ?? normalized;
  return head.split("\n").slice(1).some((line) => {
    if (line.startsWith(" ") || line.startsWith("\t")) return false;
    const separator = line.indexOf(":");
    if (separator < 0) return false;
    const name = line.slice(0, separator).trim().toLowerCase();
    return name === "authorization" || name === "cookie";
  });
}

/** Verify Host and absolute-form authorities remain on the captured origin. */
function requestAuthoritiesMatchSource(rawRequest: string, sourceOrigin: ReplayOrigin): boolean {
  const normalized = rawRequest.replace(/\r\n/gu, "\n");
  const head = normalized.split("\n\n", 1)[0] ?? normalized;
  const lines = head.split("\n");
  const hostHeader = lines.slice(1).find((line) => /^host\s*:/iu.test(line));
  const requestHost = hostHeader?.replace(/^host\s*:/iu, "").trim();
  const requestOrigin = requestHost === undefined ? undefined : authorityOrigin(requestHost, sourceOrigin.scheme);
  const absoluteOrigin = parseAbsoluteFormOrigin(lines[0] ?? "");
  return (requestHost === undefined || Boolean(requestOrigin && sameOrigin(sourceOrigin, requestOrigin)))
    && absoluteOrigin !== null
    && (!absoluteOrigin || sameOrigin(sourceOrigin, absoluteOrigin));
}

/** Parse an absolute-form request target into a replay origin. */
function parseAbsoluteFormOrigin(startLine: string): ReplayOrigin | null | undefined {
  const requestTarget = startLine.trim().split(/\s+/u)[1];
  if (!requestTarget || !/^https?:\/\//iu.test(requestTarget)) return undefined;
  if (requestTarget.includes("\\")) return null;
  try {
    return urlOrigin(new URL(requestTarget)) ?? null;
  } catch {
    return null;
  }
}

/** Normalize host, port, and scheme fields into a replay origin. */
function endpointOrigin(host: string, port: number | null | undefined, scheme: string): ReplayOrigin | undefined {
  const normalizedScheme = scheme === "http" ? "http" : scheme === "https" ? "https" : undefined;
  const effectivePort = port ?? (normalizedScheme ? defaultPort(normalizedScheme) : undefined);
  if (!normalizedScheme || !validPort(effectivePort)) return undefined;
  const hostValue = host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
  return authorityOrigin(`${hostValue}:${effectivePort}`, normalizedScheme);
}

/** Parse an HTTP authority under the supplied transport scheme. */
function authorityOrigin(authority: string, scheme: "http" | "https"): ReplayOrigin | undefined {
  if (!authority.trim() || /[\\/?#@\s]/u.test(authority)) return undefined;
  try {
    return urlOrigin(new URL(`${scheme}://${authority}`));
  } catch {
    return undefined;
  }
}

/** Normalize a URL into an HTTP replay origin. */
function urlOrigin(url: URL): ReplayOrigin | undefined {
  const scheme = url.protocol === "http:" ? "http" : url.protocol === "https:" ? "https" : undefined;
  if (!scheme || !url.hostname) return undefined;
  const port = Number(url.port || defaultPort(scheme));
  if (!validPort(port)) return undefined;
  return { scheme, host: url.hostname.toLowerCase(), port };
}

/** Return the default TCP port for an HTTP transport scheme. */
function defaultPort(scheme: "http" | "https"): number {
  return scheme === "https" ? 443 : 80;
}

/** Compare scheme, normalized host, and effective port as one origin. */
function sameOrigin(left: ReplayOrigin, right: ReplayOrigin): boolean {
  return left.scheme === right.scheme && left.host === right.host && left.port === right.port;
}

/** Validate a TCP port as an integer in the accepted range. */
function validPort(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value > 0 && value <= 65_535;
}

/** Add a Host header when an editable raw request does not contain one. */
export function ensureHost(raw: string, options: {
  host: string;
  port: number | null | undefined;
  scheme: string;
}): string {
  const separator = raw.includes("\r\n") ? "\r\n" : "\n";
  const boundaryIndex = raw.indexOf(`${separator}${separator}`);
  const head = boundaryIndex < 0 ? raw : raw.slice(0, boundaryIndex);
  if (/^host\s*:/im.test(head)) return raw;
  const firstBreak = raw.indexOf(separator);
  if (firstBreak < 0) return raw;
  const normalized = options.host.includes(":") && !options.host.startsWith("[")
    ? `[${options.host}]`
    : options.host;
  const defaultPort = options.scheme === "https" ? 443 : 80;
  const authority = options.port && options.port !== defaultPort
    ? `${normalized}:${options.port}`
    : normalized;
  return `${raw.slice(0, firstBreak + separator.length)}Host: ${authority}${separator}${raw.slice(firstBreak + separator.length)}`;
}
