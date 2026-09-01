import { useCallback, useEffect, useRef, useState } from "react";
import type { AssetDiscoveryApi } from "./host";
import type { AssetFilters, AssetPage, CollectionRun, Project } from "./types";
import { formatTime, providerLabel, runTitle } from "./utils";
import { Button, ConfirmModal, EmptyState, ErrorState, Modal, Notice, StatusBadge } from "./ui";

const INITIAL_FILTERS: AssetFilters = { importedOnly: false, page: 1, pageSize: 50 };

type AssetPoolProps = {
  api: AssetDiscoveryApi;
  runs: CollectionRun[];
  selectedRunId?: string;
  onSelectedRunId: (value?: string) => void;
};

type AssetFilterToolbarProps = {
  filters: AssetFilters;
  queryDraft: string;
  runs: CollectionRun[];
  selectedCount: number;
  mutating: boolean;
  onSubmit: () => void;
  onQuery: (value: string) => void;
  onUpdate: (next: Partial<AssetFilters>) => void;
  onRun: (value?: string) => void;
  onImport: () => void;
  onDelete: () => void;
};

type AssetTableProps = {
  page: AssetPage;
  filters: AssetFilters;
  selected: string[];
  mutating: boolean;
  onSelected: (value: string[]) => void;
  onUpdate: (next: Partial<AssetFilters>) => void;
};

export function AssetPool({ api, runs, selectedRunId, onSelectedRunId }: AssetPoolProps) {
  const [filters, setFilters] = useState<AssetFilters>({ ...INITIAL_FILTERS, runId: selectedRunId });
  const [queryDraft, setQueryDraft] = useState("");
  const [page, setPage] = useState<AssetPage>();
  const [selected, setSelected] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string>();
  const [notice, setNotice] = useState<string>();
  const [importOpen, setImportOpen] = useState(false);
  const [projects, setProjects] = useState<Project[]>();
  const [projectsError, setProjectsError] = useState<string>();
  const [projectId, setProjectId] = useState("");
  const [mutating, setMutating] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const latestFilters = useRef(filters);
  const projectRequestGeneration = useRef(0);
  latestFilters.current = filters;

  const load = useCallback(async () => {
    if (latestFilters.current !== filters) return;
    setLoading(true); setError(undefined); setPage(undefined); setSelected([]);
    try {
      const next = await api.assets(filters);
      if (latestFilters.current !== filters) return;
      const lastPage = Math.max(1, Math.ceil(next.total / filters.pageSize));
      if (!next.items.length && filters.page > lastPage) {
        setFilters((current) => ({ ...current, page: lastPage }));
        return;
      }
      setPage(next);
      setSelected([]);
    } catch (reason) {
      if (latestFilters.current === filters) setError(`读取资产池失败：${String(reason)}`);
    } finally {
      if (latestFilters.current === filters) setLoading(false);
    }
  }, [api, filters]);

  useEffect(() => { void load(); }, [load]);
  useEffect(() => { if (selectedRunId !== filters.runId) setFilters((current) => ({ ...current, runId: selectedRunId, page: 1 })); }, [filters.runId, selectedRunId]);

  const update = (next: Partial<AssetFilters>) => setFilters((current) => ({ ...current, ...next, page: next.page ?? 1 }));
  const openImport = async () => {
    const generation = ++projectRequestGeneration.current;
    setImportOpen(true); setProjectId(""); setProjects(undefined); setProjectsError(undefined);
    try {
      const next = await api.projects();
      if (generation === projectRequestGeneration.current) setProjects(next);
    } catch (reason) {
      if (generation === projectRequestGeneration.current) setProjectsError(`读取项目列表失败：${String(reason)}`);
    }
  };
  const confirmImport = async () => {
    if (!projectId) { setProjectsError("请选择目标项目。"); return; }
    setMutating(true);
    try { const result = await api.importAssets(selected, projectId); setImportOpen(false); setProjectId(""); await load(); setNotice(`导入完成：新增 ${result.created}，跳过 ${result.skipped}，失败 ${result.failed}`); } catch (reason) { setProjectsError(`导入失败：${String(reason)}`); } finally { setMutating(false); }
  };
  const remove = async () => {
    const selectedCount = selected.length;
    setMutating(true);
    console.info("asset-discovery.assets.delete.started", { selectedCount });
    try {
      const result = await api.deleteAssets(selected);
      setDeleteOpen(false);
      await load();
      console.info("asset-discovery.assets.delete.completed", { selectedCount, deleted: result.deleted });
      setNotice(`已删除 ${result.deleted} 条资产。`);
    } catch (reason) {
      console.error("asset-discovery.assets.delete.failed", { selectedCount, message: String(reason) });
      setError(`删除资产失败：${String(reason)}`);
    } finally {
      setMutating(false);
    }
  };
  return <section className="ad-assets">
    <AssetFilterToolbar filters={filters} queryDraft={queryDraft} runs={runs} selectedCount={selected.length} mutating={mutating} onSubmit={() => update({ query: queryDraft.trim() || undefined })} onQuery={(value) => { setQueryDraft(value); if (!value) update({ query: undefined }); }} onUpdate={update} onRun={onSelectedRunId} onImport={() => void openImport()} onDelete={() => setDeleteOpen(true)} />
    {notice ? <Notice>{notice}</Notice> : null}
    {error ? <ErrorState error={error} onRetry={() => void load()} /> : null}
    {!error && !loading && !page?.items.length ? <EmptyState>资产池为空</EmptyState> : null}
    {page?.items.length ? <AssetTable page={page} filters={filters} selected={selected} mutating={mutating} onSelected={setSelected} onUpdate={update} /> : null}
    {importOpen ? <ImportModal projects={projects} error={projectsError} projectId={projectId} count={selected.length} saving={mutating} onProject={setProjectId} onClose={() => setImportOpen(false)} onConfirm={() => void confirmImport()} /> : null}
    {deleteOpen ? <ConfirmModal title="删除发现资产" detail={`确认删除选中的 ${selected.length} 条资产？此操作不可恢复。`} confirmLabel="删除" danger busy={mutating} onClose={() => setDeleteOpen(false)} onConfirm={() => void remove()} /> : null}
  </section>;
}

function AssetFilterToolbar({ filters, queryDraft, runs, selectedCount, mutating, onSubmit, onQuery, onUpdate, onRun, onImport, onDelete }: AssetFilterToolbarProps) {
  const selectRun = (value: string) => {
    const runId = value || undefined;
    onRun(runId);
    onUpdate({ runId });
  };
  return <form className="ad-filter-row" onSubmit={(event) => { event.preventDefault(); onSubmit(); }}>
    <select className="ad-select" value={filters.runId ?? ""} onChange={(event) => selectRun(event.target.value)}><option value="">全部收集任务</option>{runs.map((run) => <option value={run.id} key={run.id}>{runTitle(run)}</option>)}</select>
    <select className="ad-select" value={filters.provider ?? ""} onChange={(event) => onUpdate({ provider: event.target.value || undefined })}><option value="">全部数据源</option><option value="hunter">鹰图 Hunter</option><option value="fofa">FOFA + 天眼查</option></select>
    <input className="ad-input" value={queryDraft} placeholder="按 Host 模糊搜索" onChange={(event) => onQuery(event.target.value)} />
    <Button type="submit">搜索</Button>
    <select className="ad-select" value={filters.importedOnly ? "imported" : "all"} onChange={(event) => onUpdate({ importedOnly: event.target.value === "imported" })}><option value="all">全部资产</option><option value="imported">仅已导入</option></select>
    <Button disabled={!selectedCount || mutating} onClick={onImport}>导入到项目{selectedCount ? `（${selectedCount}）` : ""}</Button><Button className="danger" disabled={!selectedCount || mutating} onClick={onDelete}>删除选中</Button>
  </form>;
}

function AssetTable({ page, filters, selected, mutating, onSelected, onUpdate }: AssetTableProps) {
  const allSelected = Boolean(page.items.length) && page.items.every((asset) => selected.includes(asset.id));
  const lastPage = Math.max(1, Math.ceil(page.total / filters.pageSize));
  const toggleAsset = (id: string, checked: boolean) => onSelected(checked ? [...selected, id] : selected.filter((item) => item !== id));
  return <>
    <div className="ad-table-wrap"><table className="ad-table"><thead><tr><th><input aria-label="选择当前页资产" type="checkbox" checked={allSelected} onChange={(event) => onSelected(event.target.checked ? page.items.map((asset) => asset.id) : [])} /></th><th>类型</th><th>资产</th><th>Host</th><th>来源</th><th>导入状态</th><th>发现时间</th></tr></thead><tbody>{page.items.map((asset) => <tr key={asset.id}><td><input aria-label={`选择 ${asset.raw_value}`} type="checkbox" checked={selected.includes(asset.id)} onChange={(event) => toggleAsset(asset.id, event.target.checked)} /></td><td>{asset.type}</td><td className="ellipsis" title={asset.raw_value}><strong>{asset.raw_value}</strong></td><td className="ellipsis" title={asset.host ?? ""}>{asset.host || "—"}</td><td>{asset.source_provider ? providerLabel(asset.source_provider) : "—"}</td><td><span className={`ad-status ${asset.imported ? "completed" : "other"}`}>{asset.imported ? "已导入" : "未导入"}</span></td><td>{formatTime(asset.created_at)}</td></tr>)}</tbody></table></div>
    <div className="ad-pagination"><span>共 {page.total} 条</span><select className="ad-select" value={filters.pageSize} disabled={mutating} onChange={(event) => onUpdate({ pageSize: Number(event.target.value) })}><option value="25">25 / 页</option><option value="50">50 / 页</option><option value="100">100 / 页</option></select><Button className="compact" disabled={filters.page <= 1 || mutating} onClick={() => onUpdate({ page: filters.page - 1 })}>上一页</Button><span>{filters.page} / {lastPage}</span><Button className="compact" disabled={filters.page >= lastPage || mutating} onClick={() => onUpdate({ page: filters.page + 1 })}>下一页</Button></div>
  </>;
}

function ImportModal({ projects, error, projectId, count, saving, onProject, onClose, onConfirm }: {
  projects?: Project[]; error?: string; projectId: string; count: number; saving: boolean; onProject: (value: string) => void; onClose: () => void; onConfirm: () => void;
}) {
  const close = () => { if (!saving) onClose(); };
  return <Modal title="导入到项目" onClose={close} footer={<><Button disabled={saving} onClick={close}>取消</Button><Button className="primary" disabled={saving || !projectId} onClick={onConfirm}>导入</Button></>}><p className="ad-description">将把选中的 {count} 条资产导入到目标项目；已存在的资产会自动跳过。</p><label className="ad-field">目标项目<select className="ad-select" value={projectId} disabled={saving} onChange={(event) => onProject(event.target.value)}><option value="">选择目标项目</option>{projects?.map((project) => <option key={project.id} value={project.id}>{project.name}（{project.code}）</option>)}</select></label>{error ? <p className="ad-field-error">{error}</p> : null}{projects && !projects.length ? <p className="ad-muted">暂无可导入项目。</p> : null}</Modal>;
}
