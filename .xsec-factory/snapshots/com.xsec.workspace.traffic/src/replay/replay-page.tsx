import { flowSnapshot, responseRaw } from "../proxy";
import type { PluginHost, WorkspaceToolContext } from "../types";
import { Button, Dialog, EmptyState, Field, IconButton, Notice, Spinner } from "../ui/primitives";
import { MessagePane } from "../traffic/message-pane";
import { MAX_REPLAY_PORT, MIN_REPLAY_PORT } from "./target";
import { useReplay } from "./use-replay";

type ReplayModel = ReturnType<typeof useReplay>;

/** Format the replay response status with an optional duration. */
function replayResponseMeta(model: ReplayModel): string {
  if (!model.selected) return "尚未发送";
  if (model.selected.status === "failed") return "发送失败";
  if (model.selected.status === "sending") return "等待响应入库";
  const status = model.selected.response_status ?? model.result?.status ?? "—";
  const duration = model.selected.duration_ms == null ? "" : ` · ${model.selected.duration_ms} ms`;
  return `HTTP ${status}${duration}`;
}

/** Render the replay toolbar component. */
function ReplayToolbar({ model }: { model: ReplayModel }) {
  const sendDisabled = [!model.source, !model.rawRequest.trim(), !model.targetValid, model.sending].some(Boolean);
  const nextDisabled = [model.selectedIndex < 0, model.selectedIndex >= model.attempts.length - 1].some(Boolean);
  const historyIndex = model.selectedIndex < 0 ? 0 : model.selectedIndex + 1;
  return <header className="replay-toolbar">
    <div className="replay-actions"><Button tone="primary" icon="play" disabled={sendDisabled} onClick={() => void model.send(false)}>{model.sending ? "发送中…" : "发送"}</Button>
      <div className="replay-history"><IconButton label="上一次重放" icon="arrow-left" disabled={model.selectedIndex <= 0} onClick={() => model.selectAttempt(model.selectedIndex - 1)} /><strong>{historyIndex}/{model.attempts.length}</strong><IconButton label="下一次重放" icon="arrow-right" disabled={nextDisabled} onClick={() => model.selectAttempt(model.selectedIndex + 1)} /><IconButton label="刷新重放历史" icon="refresh" onClick={() => void model.refreshHistory(false).catch((reason) => model.setHistoryError(`刷新重放历史失败：${String(reason)}`))} /></div>
    </div>
    <div className="replay-target-summary"><span>{model.scheme.toUpperCase()}</span><code>{model.targetHost || "未设置"}:{model.targetPort}</code><Button icon="settings" tone="ghost" onClick={() => model.setConnectionOpen(!model.connectionOpen)}>连接设置</Button></div>
  </header>;
}

/** Render the replay connection component. */
function ReplayConnection({ model }: { model: ReplayModel }) {
  if (!model.connectionOpen) return null;
  const changeScheme = (value: string) => {
    const next = value === "http" ? "http" : "https";
    model.setScheme(next);
    model.setTargetPort((current) => {
      if (current !== 80 && current !== 443) return current;
      return next === "https" ? 443 : 80;
    });
  };
  return <div className="replay-targets"><Field label="协议"><select disabled={model.sending} value={model.scheme} onChange={(event) => changeScheme(event.currentTarget.value)}><option value="https">HTTPS</option><option value="http">HTTP</option></select></Field><Field label="连接目标 / SNI"><input disabled={model.sending} value={model.targetHost} onInput={(event) => model.setTargetHost(event.currentTarget.value)} /></Field><Field label="端口"><input disabled={model.sending} type="number" min={MIN_REPLAY_PORT} max={MAX_REPLAY_PORT} value={model.targetPort} onInput={(event) => model.setTargetPort(Number(event.currentTarget.value))} /></Field><p>HTTP Host 直接编辑下方请求报文中的 Host Header。</p></div>;
}

/** Render the replay notices component. */
function ReplayNotices({ model }: { model: ReplayModel }) {
  return <div className="replay-notice">
    {model.error ? <Notice onClose={() => model.setError(undefined)}>{model.error}</Notice> : null}
    {model.historyError ? <Notice onClose={() => model.setHistoryError(undefined)}>{model.historyError}</Notice> : null}
    {model.resultError ? <Notice action={<Button onClick={() => { model.setResultError(undefined); model.setResultRevision((value) => value + 1); }}>重新加载结果</Button>} onClose={() => model.setResultError(undefined)}>{model.resultError}</Notice> : null}
    {model.notice ? <Notice tone="success" onClose={() => model.setNotice(undefined)}>{model.notice}</Notice> : null}
  </div>;
}

/** Render the replay request component. */
function ReplayRequest({ model }: { model: ReplayModel }) {
  return <article className="traffic-message-pane replay-request"><header><div><strong>Request</strong><span>Raw · 可编辑</span></div></header><textarea value={model.rawRequest} disabled={model.sending} spellcheck={false} aria-label="可编辑的重放原始请求" onInput={(event) => {
    model.setRawRequest(event.currentTarget.value);
    model.drafts.current.set(model.selectedId ?? "draft", event.currentTarget.value);
  }} /></article>;
}

/** Render the replay response component. */
function ReplayResponse({ model, meta }: { model: ReplayModel; meta: string }) {
  if (model.resultLoading) return <Spinner label="加载响应…" />;
  if (model.result) return <MessagePane title="Response" meta={meta} section={flowSnapshot(model.result.payload).response} raw={responseRaw(model.result)} />;
  if (model.selected?.status === "failed") return <article className="traffic-message-pane"><header><div><strong>Response</strong><span>{meta}</span></div></header><Notice>{model.selected.error || "重放失败"}</Notice></article>;
  const message = model.selected?.status === "sending" ? "等待响应流量入库…" : "发送请求后，响应将在这里显示";
  return <article className="traffic-message-pane"><header><div><strong>Response</strong><span>{meta}</span></div></header><EmptyState>{message}</EmptyState></article>;
}

/** Render the replay exchange component. */
function ReplayExchange({ model, meta }: { model: ReplayModel; meta: string }) {
  const orientation = model.stacked ? "horizontal" : "vertical";
  return <div ref={model.exchangeRef} className={`replay-exchange ${model.stacked ? "is-stacked" : ""}`} style={{ "--replay-request-size": `${model.panePercent}%` }}>
    <ReplayRequest model={model} />
    <div className="replay-resizer" role="separator" aria-label="调整请求与响应大小" aria-orientation={orientation} aria-valuemin={25} aria-valuemax={75} aria-valuenow={Math.round(model.panePercent)} onPointerDown={model.resize} />
    <ReplayResponse model={model} meta={meta} />
  </div>;
}

/** Render the replay footer component. */
function ReplayFooter({ model, meta }: { model: ReplayModel; meta: string }) {
  if (!model.result) return null;
  return <footer className="replay-footer"><span>{meta}</span><Button tone="ghost" onClick={() => void model.openResult()}>独立打开结果流量</Button></footer>;
}

/** Render the replay confirmation component. */
function ReplayConfirmation({ model }: { model: ReplayModel }) {
  if (!model.confirmOpen) return null;
  const cancel = () => { model.confirmation.current = undefined; model.setConfirmOpen(false); };
  const confirm = () => { model.setConfirmOpen(false); void model.send(true); };
  return <Dialog title="确认向新连接目标发送敏感 Header？" width={520} onClose={cancel} footer={<><Button onClick={cancel}>取消</Button><Button tone="danger" onClick={confirm}>确认并重放</Button></>}><p>连接协议、端口或目标与原始流量不同，请求仍包含 Cookie 或 Authorization。请确认目标属于当前授权范围。</p></Dialog>;
}

/** Render the replay page component. */
export function ReplayPage({ host, context, flowId }: { host: PluginHost; context: WorkspaceToolContext; flowId: string }) {
  const model = useReplay(host, flowId, context.visible);
  if (model.loading && !model.source) return <Spinner label="加载重放请求…" />;
  if (!model.source && model.error) return <Notice action={<Button onClick={() => model.setSourceRevision((value) => value + 1)}>重新加载</Button>}>{model.error}</Notice>;
  const meta = replayResponseMeta(model);
  const navigateHistory = (event: KeyboardEvent) => {
    if (!event.altKey) return;
    if (event.key === "ArrowLeft") model.selectAttempt(model.selectedIndex - 1);
    if (event.key === "ArrowRight") model.selectAttempt(model.selectedIndex + 1);
  };
  const replayClass = `traffic-replay${model.connectionOpen ? " has-connection" : ""}`;
  return <section className={replayClass} aria-label="请求重放器" onKeyDown={(event) => {
    if (model.confirmOpen) { event.stopPropagation(); return; }
    navigateHistory(event);
  }}>
    <ReplayToolbar model={model} />
    <ReplayConnection model={model} />
    <ReplayNotices model={model} />
    <ReplayExchange model={model} meta={meta} />
    <ReplayFooter model={model} meta={meta} />
    <ReplayConfirmation model={model} />
  </section>;
}
