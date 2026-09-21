import { useEffect, useState } from "preact/hooks";
import { getTraffic, openTrafficTool } from "../api/traffic";
import { flowSnapshot, requestRaw, responseRaw } from "../proxy";
import type { PluginHost, TrafficDetail } from "../types";
import { Button, EmptyState, Notice, Spinner } from "../ui/primitives";
import { MessagePane } from "./message-pane";

/** Render the detail page component. */
export function DetailPage({ host, flowId }: { host: PluginHost; flowId: string }) {
  const [detail, setDetail] = useState<TrafficDetail>();
  const [error, setError] = useState<string>();
  const [actionError, setActionError] = useState<string>();
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    let active = true; setError(undefined); setActionError(undefined); setDetail(undefined);
    void getTraffic(host, flowId).then((value) => { if (active) setDetail(value); }).catch((reason) => { if (active) setError(String(reason)); });
    return () => { active = false; };
  }, [flowId, host, revision]);
  if (error) return <Notice action={<Button onClick={() => { setError(undefined); setRevision((value) => value + 1); }}>重新加载</Button>}>{`读取流量详情失败：${error}`}</Notice>;
  if (!detail) return <Spinner label="正在加载流量详情…" />;
  const snapshot = flowSnapshot(detail.payload);
  const rawRequest = requestRaw(detail); const rawResponse = responseRaw(detail);
  const hasMessages = Boolean(rawRequest || rawResponse);
  const openReplay = async () => {
    setActionError(undefined);
    try { await openTrafficTool(host, { toolId: "traffic-replay", flowId, title: `重放 ${detail.method} ${detail.host}` }); }
    catch (reason) { setActionError(`打开重放器失败：${String(reason)}`); }
  };
  const rows = actionError ? "auto auto minmax(0, 1fr)" : "auto minmax(0, 1fr)";
  return <section className="traffic-workbench traffic-detail-page" style={{ "--traffic-list-height": "0px", "grid-template-rows": rows }}>
    <div className="traffic-detail-toolbar"><div><strong>{detail.method} {detail.url}</strong><span>{detail.status ?? "无响应"}</span></div><Button icon="play" onClick={() => void openReplay()}>发送到重放器</Button></div>
    {actionError ? <div className="traffic-alert-slot"><Notice onClose={() => setActionError(undefined)}>{actionError}</Notice></div> : null}
    <div className="traffic-message-grid">{hasMessages ? <><MessagePane title="Request" section={snapshot.request} raw={rawRequest} /><MessagePane title="Response" section={snapshot.response} raw={rawResponse} /></> : <EmptyState>该流量没有可显示的报文内容</EmptyState>}</div>
  </section>;
}
