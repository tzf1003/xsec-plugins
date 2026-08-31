import { useEffect, useMemo, useRef } from "react";
import type { AssetDiscoveryApi } from "./host";
import type { CollectionRun, CollectionStatusFilter } from "./types";
import { collectionMetrics, collectionResultDescription, filterRuns, formatTime, providerLabel, runSubtitle, runTitle } from "./utils";
import { Button, EmptyState, ErrorState, StatusBadge } from "./ui";
import { CollectionConsole } from "./collection-console";

const STATUS_FILTERS: Array<{ key: CollectionStatusFilter; label: string }> = [
  { key: "all", label: "全部" }, { key: "running", label: "运行" }, { key: "completed", label: "完成" }, { key: "failed", label: "失败" }, { key: "cancelled", label: "已停止" },
];

type RunsPanelProps = {
  api: AssetDiscoveryApi;
  runs: CollectionRun[];
  loading: boolean;
  error?: string;
  selectedRunId?: string;
  filter: CollectionStatusFilter;
  query: string;
  onSelect: (id?: string) => void;
  onFilter: (filter: CollectionStatusFilter) => void;
  onQuery: (query: string) => void;
  onRefresh: () => Promise<void>;
  onStart: () => void;
  onOpenAssets: (runId: string) => void;
  onOpenSettings: () => Promise<void>;
};

function moveIndex(index: number, length: number, key: string): number {
  if (!length) return 0;
  if (key === "Home") return 0;
  if (key === "End") return length - 1;
  if (key === "ArrowUp") return Math.max(0, index - 1);
  return Math.min(length - 1, index + 1);
}

export function RunsPanel({
  api, runs, loading, error, selectedRunId, filter, query, onSelect, onFilter, onQuery,
  onRefresh, onStart, onOpenAssets, onOpenSettings,
}: RunsPanelProps) {
  const runRefs = useRef<Record<string, HTMLButtonElement | null>>({});
  const metrics = useMemo(() => collectionMetrics(runs), [runs]);
  const visible = useMemo(() => filterRuns(runs, filter, query), [filter, query, runs]);
  const selected = visible.find((run) => run.id === selectedRunId) ?? visible[0];
  useEffect(() => {
    if (selectedRunId && !visible.some((run) => run.id === selectedRunId)) onSelect(visible[0]?.id);
  }, [onSelect, selectedRunId, visible]);
  const activateRun = (run: CollectionRun, index: number, event: React.KeyboardEvent<HTMLButtonElement>) => {
    if (!["ArrowUp", "ArrowDown", "Home", "End"].includes(event.key)) return;
    event.preventDefault();
    const next = visible[moveIndex(index, visible.length, event.key)];
    if (!next) return;
    onSelect(next.id);
    runRefs.current[next.id]?.focus();
  };
  const activateFilter = (current: CollectionStatusFilter, event: React.KeyboardEvent<HTMLButtonElement>) => {
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
    event.preventDefault();
    const index = STATUS_FILTERS.findIndex((item) => item.key === current);
    const direction = event.key === "ArrowLeft" ? -1 : event.key === "ArrowRight" ? 1 : 0;
    const nextIndex = event.key === "Home" ? 0 : event.key === "End" ? STATUS_FILTERS.length - 1 : (index + direction + STATUS_FILTERS.length) % STATUS_FILTERS.length;
    onFilter(STATUS_FILTERS[nextIndex].key);
  };

  return <section className="ad-runs">
    <div className="ad-toolbar"><div className="ad-status-tabs" role="tablist" aria-label="收集任务状态筛选">{STATUS_FILTERS.map((item) => <button className={`ad-status-tab ${filter === item.key ? "active" : ""}`} type="button" role="tab" aria-selected={filter === item.key} key={item.key} onClick={() => onFilter(item.key)} onKeyDown={(event) => activateFilter(item.key, event)}><span>{item.label}</span><strong>{item.key === "all" ? runs.length : metrics[item.key]}</strong></button>)}</div><input className="ad-input search" value={query} placeholder="搜索任务名 / 范围 / 数据源 / ID" onChange={(event) => onQuery(event.target.value)} /><Button onClick={() => void onRefresh()}>刷新</Button></div>
    <div className="ad-master-detail"><aside className="ad-run-list" aria-busy={loading}>{error ? <ErrorState error={error} onRetry={() => void onRefresh()} /> : null}{!error && !visible.length ? <EmptyState>{runs.length ? "没有匹配的收集任务" : <><p>还没有收集任务</p><Button className="primary" onClick={onStart}>启动资产收集</Button></>}</EmptyState> : null}<div role="listbox" aria-label="资产收集任务">{visible.map((run, index) => <button className={`ad-run-card ${run.id === selected?.id ? "active" : ""}`} type="button" role="option" aria-selected={run.id === selected?.id} ref={(node) => { runRefs.current[run.id] = node; }} key={run.id} onClick={() => onSelect(run.id)} onFocus={() => onSelect(run.id)} onKeyDown={(event) => activateRun(run, index, event)}><span className="ad-run-card-title"><strong>{runTitle(run)}</strong><StatusBadge status={run.status} /></span><p>{runSubtitle(run)}</p>{collectionResultDescription(run) ? <span className="ad-run-outcome">{collectionResultDescription(run)}</span> : null}<span className="ad-metadata"><span>{providerLabel(run.provider)}</span><span>{run.total} 项 · {formatTime(run.updated_at)}</span></span></button>)}</div></aside>
      <CollectionConsole api={api} run={selected} onChanged={onRefresh} onDeleted={() => onSelect(undefined)} onOpenAssets={onOpenAssets} onOpenSettings={onOpenSettings} />
    </div>
  </section>;
}
