import { flowSnapshot, requestRaw, responseRaw } from "../proxy";
import type { PluginHost, TrafficDetail, WorkspaceToolContext } from "../types";
import { Icon } from "../ui/icon";
import { Button, EmptyState, IconButton, Notice, Spinner } from "../ui/primitives";
import { FilterDialog } from "./filter-dialog";
import { FlowTable } from "./flow-table";
import { MessagePane } from "./message-pane";
import { showTrafficEmpty, workbenchNotice } from "./workbench-state";
import { useWorkbench } from "./use-workbench";

type WorkbenchModel = ReturnType<typeof useWorkbench>;

/** Render the filter count component. */
function FilterCount({ count }: { count: number }) {
  if (!count) return null;
  return <span className="traffic-filter-count">{count}</span>;
}

/** Format the current cursor page and visible-row count. */
function pageSummary(model: WorkbenchModel): string {
  if (model.nextCursor) return `本页 ${model.rows.length} 条 · 还有更多`;
  return `本页 ${model.rows.length} 条`;
}

/** Render the traffic toolbar component. */
function TrafficToolbar({ model }: { model: WorkbenchModel }) {
  return <header className="traffic-toolbar">
    <label className="traffic-search"><span className="sr-only">搜索当前会话流量</span><Icon name="search" /><input className="x-input" disabled={!model.defaults} value={model.filter.searchTerm} placeholder="搜索方法、主机、URL、状态码或 MIME" onInput={(event) => model.applyFilter({ ...model.filter, searchTerm: event.currentTarget.value })} /></label>
    <div className="traffic-filter-button"><Button icon="filter" disabled={!model.defaults} onClick={() => model.setFilterOpen(true)}>筛选</Button><FilterCount count={model.activeFilters} /></div>
    <div className="traffic-scope"><span>仅当前会话</span><code>宿主已绑定</code><em>{pageSummary(model)}</em></div>
    <div className="traffic-pages"><IconButton label="上一页流量" icon="arrow-left" disabled={!model.previous.length || model.loading} onClick={model.previousPage} /><strong>第 {model.page} 页</strong><IconButton label="下一页流量" icon="arrow-right" disabled={!model.nextCursor || model.loading} onClick={model.nextPage} /></div>
    <IconButton label="刷新当前会话流量" icon="refresh" disabled={model.loading} onClick={() => model.setRevision((value) => value + 1)} />
  </header>;
}

/** Render the traffic error component. */
function TrafficError({ model }: { model: WorkbenchModel }) {
  const message = workbenchNotice(model.error, model.listError);
  if (!message) return null;
  const retry = model.listError
    ? <Button onClick={() => model.setRevision((value) => value + 1)}>重新读取</Button>
    : model.defaults ? null : <Button onClick={() => model.setSettingsRevision((value) => value + 1)}>重新读取</Button>;
  const dismiss = model.listError
    ? () => model.setListError(null)
    : model.defaults ? () => model.setError(null) : undefined;
  return <Notice onClose={dismiss} action={retry}>{message}</Notice>;
}

/** Render the new traffic notice component. */
function NewTrafficNotice({ model }: { model: WorkbenchModel }) {
  if (!model.hasNewTraffic) return null;
  return <Notice tone="warning" action={<Button onClick={model.latestPage}>查看最新</Button>}>发现新流量</Notice>;
}

/** Render the traffic alerts component. */
function TrafficAlerts({ model }: { model: WorkbenchModel }) {
  return <div className="traffic-alert-slot"><TrafficError model={model} />{model.detailError ? <Notice action={<Button onClick={() => { model.setDetailError(null); model.setDetailRevision((value) => value + 1); }}>重新加载详情</Button>} onClose={() => model.setDetailError(null)}>{model.detailError}</Notice> : null}<NewTrafficNotice model={model} /></div>;
}

/** Render the traffic table area component. */
function TrafficTableArea({ model }: { model: WorkbenchModel }) {
  if (model.loading && !model.rows.length) return <div className="traffic-table-wrap"><Spinner label="正在读取当前会话流量…" /></div>;
  if (showTrafficEmpty(model.error, model.listError, model.rows.length)) {
    const empty = model.activeFilters ? "没有符合筛选条件的流量" : "当前会话暂无抓包流量";
    return <div className="traffic-table-wrap"><EmptyState>{empty}</EmptyState></div>;
  }
  return <div className="traffic-table-wrap"><FlowTable rows={model.rows} page={model.page} selectedId={model.selectedId} onSelect={model.setSelectedId} onOpen={model.openDetail} /></div>;
}

/** Render the selected traffic component. */
function SelectedTraffic({ selected }: { selected: TrafficDetail | null | undefined }) {
  if (!selected) return <span>选择一条流量查看报文</span>;
  const source = selected.capture_source === "replay" ? "重放结果" : "代理捕获";
  return <><strong>{selected.method} {selected.host}</strong><span>{source}</span></>;
}

/** Render the reference button component. */
function ReferenceButton({ model }: { model: WorkbenchModel }) {
  if (!model.canAddReference) return null;
  return <Button tone="primary" icon="message" disabled={!model.selectedDetail} onClick={() => void model.addReference()}>引用到会话</Button>;
}

/** Render the detail toolbar component. */
function DetailToolbar({ model }: { model: WorkbenchModel }) {
  const selected = model.selectedDetail;
  const openDetail = () => { if (selected) model.openDetail(selected); };
  const openReplay = () => { if (selected) model.openReplay(selected); };
  return <div className="traffic-detail-toolbar"><div><SelectedTraffic selected={selected} /></div><div><Button icon="external" disabled={!selected} onClick={openDetail}>独立打开</Button><Button icon="play" disabled={!selected} onClick={openReplay}>发送到重放器</Button><ReferenceButton model={model} /></div></div>;
}

/** Render the detail loading component. */
function DetailLoading({ loading }: { loading: boolean }) {
  if (!loading) return null;
  return <Spinner label="加载报文…" />;
}

/** Render the detail messages component. */
function DetailMessages({ selected }: { selected: TrafficDetail | null | undefined }) {
  if (!selected) return null;
  const snapshot = flowSnapshot(selected.payload);
  return <><MessagePane title="Request" section={snapshot.request} raw={requestRaw(selected)} /><MessagePane title="Response" section={snapshot.response} raw={responseRaw(selected)} /></>;
}

/** Render the detail empty component. */
function DetailEmpty({ model }: { model: WorkbenchModel }) {
  if (model.detailLoading) return null;
  if (model.selectedDetail) return null;
  return <EmptyState>选择上方流量后，请求与响应将在此同屏显示</EmptyState>;
}

/** Render the detail area component. */
function DetailArea({ model }: { model: WorkbenchModel }) {
  return <div className="traffic-message-grid"><DetailLoading loading={model.detailLoading} /><DetailMessages selected={model.selectedDetail} /><DetailEmpty model={model} /></div>;
}

/** Render the filter overlay component. */
function FilterOverlay({ model }: { model: WorkbenchModel }) {
  if (!model.filterOpen) return null;
  if (!model.defaults) return null;
  const apply = (value: typeof model.filter, close: boolean) => {
    model.applyFilter(value);
    if (close) model.setFilterOpen(false);
  };
  return <FilterDialog value={model.filter} defaults={model.defaults} onClose={() => model.setFilterOpen(false)} onApply={apply} />;
}

/** Render the workbench component. */
export function Workbench({ host, context }: { host: PluginHost; context: WorkspaceToolContext }) {
  const model = useWorkbench(host, context);
  return <section ref={model.workbenchRef} className="traffic-workbench" aria-label="当前会话抓包流量" style={{ "--traffic-list-height": `${model.listHeight}px` }}>
    <TrafficToolbar model={model} />
    <TrafficAlerts model={model} />
    <TrafficTableArea model={model} />
    <div className="traffic-resizer" role="separator" aria-label="调整流量列表与报文详情高度" aria-orientation="horizontal" aria-valuemin={160} aria-valuenow={Math.round(model.listHeight)} onPointerDown={model.resizeList} />
    <DetailToolbar model={model} />
    <DetailArea model={model} />
    <FilterOverlay model={model} />
  </section>;
}
