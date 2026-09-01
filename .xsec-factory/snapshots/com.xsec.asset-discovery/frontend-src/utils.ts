import type { CollectionRun, CollectionStatusFilter, CollectorProvider, ToolCall } from "./types";

const ACTIVE_STATUSES = new Set(["running", "active", "starting"]);
const COMPLETED_STATUSES = new Set(["done", "completed", "final"]);
const FAILED_STATUSES = new Set(["failed", "error"]);
const CANCELLED_STATUSES = new Set(["cancelled", "canceled", "stopped"]);
const HOST_LABEL = "[a-z0-9](?:[a-z0-9-]*[a-z0-9])?";
const HOST_PATTERN = new RegExp(`^(?:${HOST_LABEL})(?:\\.(?:${HOST_LABEL}))*$`, "i");
const WILDCARD_PATTERN = new RegExp(`^\\*\\.(?:${HOST_LABEL})(?:\\.(?:${HOST_LABEL}))+$`, "i");
const IPV4_SCOPE_PATTERN = /^(\d{1,3}(?:\.\d{1,3}){3})(?::(\d+))?$/;
const IPV6_SCOPE_PATTERN = /^\[([0-9a-f:.]+)](?::(\d+))?$/i;
const IPV4_OCTET_COUNT = 4;
const MIN_IPV4_OCTET = 0;
const MAX_IPV4_OCTET = 255;
const MIN_PORT = 1;
const MAX_PORT = 65_535;

export function collectionBucket(status: string): Exclude<CollectionStatusFilter, "all"> | "other" {
  const value = status.trim().toLowerCase();
  if (ACTIVE_STATUSES.has(value)) return "running";
  if (COMPLETED_STATUSES.has(value)) return "completed";
  if (FAILED_STATUSES.has(value)) return "failed";
  if (CANCELLED_STATUSES.has(value)) return "cancelled";
  return "other";
}

export function providerLabel(provider: string): string {
  if (provider === "hunter") return "鹰图 Hunter";
  if (provider === "fofa") return "FOFA + 天眼查";
  return provider || "未标明数据源";
}

export function statusLabel(status: string): string {
  const labels: Record<string, string> = {
    running: "进行中",
    completed: "已完成",
    failed: "失败",
    cancelled: "已停止",
  };
  return labels[collectionBucket(status)] ?? (status || "未知");
}

export function approvalModeLabel(mode?: "auto" | "full"): string {
  if (mode === "full") return "完全访问";
  if (mode === "auto") return "LLM 自动审批";
  return "未记录";
}

export function formatTime(value: number | null | undefined): string {
  if (!value || value <= 0) return "—";
  return new Date(value).toLocaleString("zh-CN", { hour12: false });
}

export function formatDuration(start: number, end: number | null): string {
  const total = Math.max(0, Math.floor(((end ?? Date.now()) - start) / 1000));
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const seconds = total % 60;
  if (hours) return `${hours}h ${minutes}m`;
  if (minutes) return `${minutes}m ${seconds}s`;
  return `${seconds}s`;
}

export function runTitle(run: CollectionRun): string {
  return run.name.trim() || `收集任务 ${run.id.slice(0, 8)}`;
}

export function runSubtitle(run: CollectionRun): string {
  const line = run.scope_prompt.split(/\r?\n/).map((item) => item.trim()).find(Boolean) ?? "未填写范围";
  return line.length > 96 ? `${line.slice(0, 96)}…` : line;
}

export function filterRuns(runs: CollectionRun[], filter: CollectionStatusFilter, query: string): CollectionRun[] {
  const needle = query.trim().toLowerCase();
  return runs.filter((run) => {
    if (filter !== "all" && collectionBucket(run.status) !== filter) return false;
    if (!needle) return true;
    return [run.id, run.name, run.provider, run.scope_prompt, providerLabel(run.provider)]
      .some((value) => value.toLowerCase().includes(needle));
  });
}

export function collectionMetrics(runs: CollectionRun[]) {
  return runs.reduce((metrics, run) => {
    metrics.assets += run.total || 0;
    metrics[collectionBucket(run.status)] = (metrics[collectionBucket(run.status)] ?? 0) + 1;
    return metrics;
  }, { assets: 0, running: 0, completed: 0, failed: 0, cancelled: 0, other: 0 } as Record<string, number>);
}

const COLLECTION_FAILURE_COPY: Record<string, string> = {
  missing_configuration: "未配置数据源凭据",
  provider_auth: "数据源认证失败",
  skill_mismatch: "收集范围与所选 Skill 不匹配",
  provider_error: "数据源服务异常",
  import_failed: "资产入库失败",
  agent_error: "收集 Agent 异常结束",
  incomplete_finalization: "收集未提交完成回执",
  watchdog_timeout: "收集执行超时",
  startup_timeout: "收集任务启动超时",
  unexpected_exit: "收集进程异常结束",
  interrupted: "收集任务被中断",
};

export function collectionResultDescription(run: CollectionRun): string | undefined {
  const bucket = collectionBucket(run.status);
  const reason = run.failure_message?.trim()
    || (run.failure_code ? COLLECTION_FAILURE_COPY[run.failure_code] : undefined);
  if (bucket === "failed") return run.total ? `已入库 ${run.total} 条，任务未完整完成：${reason ?? "收集失败"}` : (reason ?? "收集任务未能完整完成");
  if (bucket === "cancelled") return run.total ? `已入库 ${run.total} 条，任务已中断` : (reason ?? "任务被手动停止或应用退出中断");
  return undefined;
}

function isHackerOneUrl(value: string): boolean {
  try {
    const url = new URL(value.startsWith("//") ? `https:${value}` : value);
    return /^https?:$/i.test(url.protocol) && /^(www\.)?hackerone\.com$/i.test(url.hostname) && url.pathname !== "/";
  } catch {
    return false;
  }
}

function hasValidPort(value: string | undefined): boolean {
  if (value === undefined) return true;
  const port = Number(value);
  return /^\d+$/.test(value) && Number.isSafeInteger(port) && port >= MIN_PORT && port <= MAX_PORT;
}

function isIpv4Address(value: string): boolean {
  const octets = value.split(".");
  return octets.length === IPV4_OCTET_COUNT && octets.every((octet) => {
    const number = Number(octet);
    return /^\d{1,3}$/.test(octet) && Number.isInteger(number) && number >= MIN_IPV4_OCTET && number <= MAX_IPV4_OCTET;
  });
}

function isIpv6Address(value: string): boolean {
  try {
    new URL(`http://[${value}]/`);
    return true;
  } catch {
    return false;
  }
}

function resemblesIpScope(value: string): boolean {
  return value.startsWith("[")
    || /^\d+(?:\.\d+)+(?:[:].*)?$/.test(value)
    || (value.includes(":") && /^[0-9a-f:.]+$/i.test(value));
}

function isIpScope(value: string): boolean {
  const ipv4 = IPV4_SCOPE_PATTERN.exec(value);
  if (ipv4) return isIpv4Address(ipv4[1]) && hasValidPort(ipv4[2]);
  const ipv6 = IPV6_SCOPE_PATTERN.exec(value);
  return Boolean(ipv6 && isIpv6Address(ipv6[1]) && hasValidPort(ipv6[2]));
}

function networkScope(value: string): boolean {
  if (value.startsWith("*.")) return WILDCARD_PATTERN.test(value);
  if (value.includes("*") || value.startsWith(".")) return false;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(value) || value.startsWith("//")) return isHackerOneUrl(value);
  if (resemblesIpScope(value)) return isIpScope(value);
  return HOST_PATTERN.test(value);
}

function companyScope(value: string): boolean {
  return !resemblesIpScope(value)
    && !value.includes("*")
    && !value.includes("://")
    && !value.startsWith("//")
    && /[\p{L}\p{N}]/u.test(value)
    && !/[\p{Cc}]/u.test(value);
}

function stripScopeComment(line: string): string {
  const trimmed = line.trim();
  if (trimmed.startsWith("#")) return "";
  return line.split(/\s+#/, 1)[0].trim();
}

function scopeLines(prompt: string): string[] {
  return prompt.split(/\r?\n/).map(stripScopeComment).filter(Boolean);
}

export function normalizeCollectorScope(prompt: string): string {
  return scopeLines(prompt).join("\n");
}

function fofaNetworkScope(value: string): boolean {
  if (!networkScope(value)) return false;
  if (value.startsWith("*.") || resemblesIpScope(value)) return true;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(value) || value.startsWith("//")) return true;
  return value.includes(".");
}

export function fofaScopeRequiresTianyan(prompt: string): boolean {
  return scopeLines(prompt).some((line) => companyScope(line) && !fofaNetworkScope(line));
}

export function validateCollectorScope(provider: CollectorProvider, prompt: string): string | undefined {
  const lines = scopeLines(prompt);
  const error = provider === "fofa"
    ? "FOFA 的收集范围必须是企业名称、通配符域名或固定主机（请按行输入）"
    : "鹰图 Hunter 的收集范围必须是 HackerOne 链接、handle、通配符域名或固定主机（请按行输入）";
  if (!lines.length) return error;
  const valid = provider === "hunter"
    ? lines.every(networkScope)
    : lines.every((line) => networkScope(line) || companyScope(line));
  return valid ? undefined : error;
}

export function printableToolValue(value: unknown): string {
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

export function toolLabel(tool: ToolCall): string {
  return tool.name?.trim() || "工具调用";
}
