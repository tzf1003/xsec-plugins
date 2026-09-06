import { compactParameterLabel, extensionLabel, formatBytes, formatTime, hostLabel, methodClass, mimeLabel, parameterLabel, requestTarget, sourceLabel, statusClass } from "../format";
import type { TrafficSummary } from "../types";

/** Render the flow table component. */
export function FlowTable({ rows, page, selectedId, onSelect, onOpen }: {
  rows: TrafficSummary[];
  page: number;
  selectedId: string | null;
  onSelect: (id: string) => void;
  onOpen: (row: TrafficSummary) => void;
}) {
  return <table className="traffic-table"><thead><tr>
    <th className="col-index">#</th><th className="col-method">方法</th><th className="col-request-compact">请求</th><th className="col-host">主机</th><th className="col-path">URL</th><th className="col-parameters">参数</th><th className="col-status">状态码</th><th className="col-type-compact">类型</th><th className="col-mime">响应类型</th><th className="col-extension">扩展名</th><th className="col-source">来源</th><th className="col-scope">范围</th><th className="col-duration">耗时</th><th className="col-size">大小</th><th className="col-time">时间</th>
  </tr></thead><tbody>{rows.map((row, index) => {
    const target = requestTarget(row);
    const hostName = hostLabel(row);
    return <tr key={row.flow_id} tabIndex={0} aria-selected={selectedId === row.flow_id} className={selectedId === row.flow_id ? "is-selected" : ""} onClick={() => onSelect(row.flow_id)} onDblClick={() => onOpen(row)} onKeyDown={(event) => {
      if (event.key === "Enter" || event.key === " ") onSelect(row.flow_id);
    }}>
      <td className="col-index">{(page - 1) * 100 + index + 1}</td><td className="col-method"><span className={`traffic-method ${methodClass(row.method)}`}>{row.method}</span></td>
      <td className="col-request-compact"><div className="compact-primary"><span className={`traffic-method ${methodClass(row.method)}`}>{row.method}</span><strong title={hostName}>{hostName}</strong></div><span className="compact-secondary" title={target}>{target}</span><div className="compact-meta"><span>{compactParameterLabel(row.has_parameters)}</span><span>{row.in_scope ? "范围内" : "范围外"}</span></div></td>
      <td className="col-host" title={hostName}>{hostName}</td><td className="col-path" title={target}>{target}</td><td className="col-parameters">{parameterLabel(row.has_parameters)}</td><td className="col-status"><span className={`traffic-status ${statusClass(row.status)}`}>{row.status ?? "无响应"}</span></td>
      <td className="col-type-compact"><div className="compact-primary"><span>{mimeLabel(row.mime_category)}</span><span>{extensionLabel(row.file_extension)}</span></div><span className="compact-meta">来源：{sourceLabel(row.capture_source)}</span></td>
      <td className="col-mime">{mimeLabel(row.mime_category)}</td><td className="col-extension">{extensionLabel(row.file_extension)}</td><td className="col-source">{sourceLabel(row.capture_source)}</td><td className="col-scope">{row.in_scope ? "范围内" : "范围外"}</td><td className="col-duration">{row.duration_ms == null ? "—" : `${row.duration_ms} ms`}</td><td className="col-size">{formatBytes(row.response_body_size)}</td><td className="col-time">{formatTime(row.timestamp)}</td>
    </tr>;
  })}</tbody></table>;
}
