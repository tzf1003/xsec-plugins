import type { ReplayAttempt, ReplayResult, TrafficDetail, TrafficPage, TrafficSummary } from "../types";
import { array, boolean, number, object, optionalNumber, optionalString, string } from "./value";

const MIMES = new Set(["html", "script", "xml", "otherText", "css", "images", "otherBinary", "unknown"]);

/** Parse and validate one traffic-list row from the host response. */
export function trafficSummary(value: unknown): TrafficSummary {
  const row = object(value, "流量记录");
  const mime = optionalString(row.mime_category, "MIME 分类");
  if (mime != null && !MIMES.has(mime)) throw new Error("MIME 分类格式无效");
  return {
    flow_id: string(row.flow_id, "流量 ID"),
    timestamp: number(row.timestamp, "流量时间"),
    scheme: string(row.scheme, "协议"),
    host: string(row.host, "主机"),
    port: optionalNumber(row.port, "端口"),
    method: string(row.method, "方法"),
    url: string(row.url, "URL"),
    path: string(row.path, "路径"),
    query: optionalString(row.query, "查询参数"),
    request_body_size: number(row.request_body_size, "请求大小"),
    status: optionalNumber(row.status, "状态码"),
    response_body_size: number(row.response_body_size, "响应大小"),
    content_type: optionalString(row.content_type, "内容类型"),
    mime_category: mime as TrafficSummary["mime_category"],
    file_extension: optionalString(row.file_extension, "扩展名"),
    has_parameters: row.has_parameters === undefined ? undefined : boolean(row.has_parameters, "参数标记"),
    duration_ms: optionalNumber(row.duration_ms, "耗时"),
    in_scope: boolean(row.in_scope, "范围标记"),
    capture_source: string(row.capture_source, "流量来源"),
    truncated: boolean(row.truncated, "截断标记"),
  };
}

/** Parse and validate a cursor-paginated traffic-list response. */
export function trafficPage(value: unknown): TrafficPage {
  const page = object(value, "流量分页");
  return {
    items: array(page.items, "流量列表").map(trafficSummary),
    next_cursor: optionalString(page.next_cursor, "下一页游标"),
  };
}

/** Parse and validate one traffic-detail response. */
export function trafficDetail(value: unknown): TrafficDetail {
  const row = object(value, "流量详情");
  return { ...trafficSummary(row), ...(row.payload === undefined ? {} : { payload: row.payload }) };
}

/** Parse and validate one recorded replay attempt. */
export function replayAttempt(value: unknown): ReplayAttempt {
  const row = object(value, "重放记录");
  return {
    id: string(row.id, "重放 ID"),
    source_flow_id: string(row.source_flow_id, "源流量 ID"),
    result_flow_id: optionalString(row.result_flow_id, "结果流量 ID"),
    scheme: string(row.scheme, "重放协议"),
    target_host: string(row.target_host, "重放主机"),
    target_port: number(row.target_port, "重放端口"),
    host_header: string(row.host_header, "Host Header"),
    sni: string(row.sni, "SNI"),
    status: string(row.status, "重放状态"),
    response_status: optionalNumber(row.response_status, "响应状态"),
    duration_ms: optionalNumber(row.duration_ms, "重放耗时"),
    error: optionalString(row.error, "重放错误"),
    created_at: number(row.created_at, "重放时间"),
    request_raw: string(row.request_raw, "重放请求"),
  };
}

/** Parse and validate a replay-history response. */
export function replayAttempts(value: unknown): ReplayAttempt[] {
  const page = object(value, "重放历史");
  return array(page.items, "重放历史列表").map(replayAttempt);
}

/** Parse and validate a replay-submission result. */
export function replayResult(value: unknown): ReplayResult {
  const result = object(value, "重放结果");
  return {
    attempt: result.attempt == null ? result.attempt as null | undefined : replayAttempt(result.attempt),
    result: result.result == null ? result.result as null | undefined : trafficSummary(result.result),
    response_status: optionalNumber(result.response_status, "重放状态码"),
    capture_pending: result.capture_pending === undefined ? undefined : boolean(result.capture_pending, "流量入库状态"),
  };
}
