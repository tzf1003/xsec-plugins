import { useCallback, useEffect, useMemo, useState } from "react";
import type { AssetDiscoveryApi } from "./host";
import type { CollectionStatusFilter, CollectorProvider, CollectorSettings, ExecutionDefaults, PluginHost } from "./types";
import { collectionMetrics, validateCollectorScope } from "./utils";
import { AssetPool } from "./asset-pool";
import { useDashboardState } from "./dashboard-state";
import { RunsPanel } from "./runs-panel";
import { Button, Modal, Notice } from "./ui";

type DashboardProps = { api: AssetDiscoveryApi; host: PluginHost };
type DashboardTab = "runs" | "assets";
type StartInput = { prompt: string; name?: string; provider: CollectorProvider; workdir?: string };
type CollectModalProps = {
  settings?: CollectorSettings;
  settingsError?: string;
  defaults?: ExecutionDefaults;
  defaultsError?: string;
  onClose: () => void;
  onOpenSettings: () => Promise<void>;
  onStart: (input: StartInput) => Promise<void>;
};

function providerConfigured(settings: CollectorSettings, provider: CollectorProvider): boolean {
  return provider === "fofa"
    ? settings.fofaApiKeyConfigured && Boolean(settings.fofaApiBaseUrl.trim())
    : settings.hunterApiKeyConfigured && Boolean(settings.hunterApiBaseUrl.trim());
}

function useColorMode(host: PluginHost) {
  const [colorMode, setColorMode] = useState(document.documentElement.style.getPropertyValue("--xsec-color-mode") || "dark");
  useEffect(() => {
    const subscription = host.onTheme((theme) => setColorMode(theme["color-mode"] || "dark"));
    return () => subscription.dispose();
  }, [host]);
  return colorMode;
}

function DashboardHeader({ onOpenCollect, onRefresh }: { onOpenCollect: () => void; onRefresh: () => void }) {
  return <header className="ad-header">
    <div>
      <p className="ad-eyebrow">ASSET DISCOVERY CONSOLE</p>
      <h1 className="ad-title">资产发现</h1>
      <p className="ad-description">管理资产收集任务、执行过程和跨项目资产池。</p>
    </div>
    <div className="ad-actions">
      <Button className="primary" onClick={onOpenCollect}>启动资产收集</Button>
      <Button onClick={onRefresh}>刷新</Button>
    </div>
  </header>;
}

function DashboardTabs({ tab, metrics, onTab }: {
  tab: DashboardTab;
  metrics: Record<string, number>;
  onTab: (tab: DashboardTab) => void;
}) {
  return <div className="ad-tab-row">
    <div className="ad-tabs" role="tablist">
      <button className={`ad-tab ${tab === "runs" ? "active" : ""}`} type="button" role="tab" aria-selected={tab === "runs"} onClick={() => onTab("runs")}>
        收集操作台{metrics.running ? ` · ${metrics.running}` : ""}
      </button>
      <button className={`ad-tab ${tab === "assets" ? "active" : ""}`} type="button" role="tab" aria-selected={tab === "assets"} onClick={() => onTab("assets")}>
        资产池 · {metrics.assets}
      </button>
    </div>
    <div className="ad-kpis">
      <span>运行 <strong>{metrics.running}</strong></span><span>完成 <strong>{metrics.completed}</strong></span>
      <span>失败 <strong>{metrics.failed}</strong></span><span>资产 <strong>{metrics.assets}</strong></span>
    </div>
  </div>;
}

export function AssetDiscoveryApp({ api, host }: DashboardProps) {
  const dashboard = useDashboardState(api);
  const colorMode = useColorMode(host);
  const [tab, setTab] = useState<DashboardTab>("runs");
  const [selectedRunId, setSelectedRunId] = useState<string>();
  const [assetRunId, setAssetRunId] = useState<string>();
  const [filter, setFilter] = useState<CollectionStatusFilter>("all");
  const [query, setQuery] = useState("");
  const [collectOpen, setCollectOpen] = useState(false);
  const [notice, setNotice] = useState<string>();
  const metrics = useMemo(() => collectionMetrics(dashboard.runs), [dashboard.runs]);
  const openAssets = useCallback((runId: string) => {
    setAssetRunId(runId);
    setTab("assets");
  }, []);
  const openSettings = useCallback(async () => { await api.openSettings(); }, [api]);
  const startCollection = useCallback(async (input: StartInput) => {
    const result = await api.start(input);
    const runId = result.collection_run_id || result.run_id || result.process.id;
    setSelectedRunId(runId);
    setFilter("all");
    setTab("runs");
    setCollectOpen(false);
    await dashboard.loadRuns();
    setNotice(`资产收集已启动（任务 ID：${runId}）`);
  }, [api, dashboard.loadRuns]);

  return <main className="ad-app" data-color-mode={colorMode}>
    <DashboardHeader onOpenCollect={() => setCollectOpen(true)} onRefresh={() => void dashboard.refresh()} />
    {notice ? <p className="ad-muted">{notice}</p> : null}
    <DashboardTabs tab={tab} metrics={metrics} onTab={setTab} />
    {tab === "runs" ? <RunsPanel api={api} runs={dashboard.runs} loading={dashboard.runsLoading} error={dashboard.runsError} selectedRunId={selectedRunId} filter={filter} query={query} onSelect={setSelectedRunId} onFilter={setFilter} onQuery={setQuery} onRefresh={async () => { await dashboard.loadRuns(); }} onStart={() => setCollectOpen(true)} onOpenAssets={openAssets} onOpenSettings={openSettings} /> : null}
    {tab === "assets" ? <AssetPool api={api} runs={dashboard.runs} selectedRunId={assetRunId} onSelectedRunId={setAssetRunId} /> : null}
    {collectOpen ? <CollectModal settings={dashboard.settings} settingsError={dashboard.settingsError} defaults={dashboard.defaults} defaultsError={dashboard.defaultsError} onClose={() => setCollectOpen(false)} onOpenSettings={openSettings} onStart={startCollection} /> : null}
  </main>;
}

function CollectFields({ provider, prompt, name, workdir, saving, onProvider, onPrompt, onName, onWorkdir }: {
  provider: CollectorProvider;
  prompt: string;
  name: string;
  workdir: string;
  saving: boolean;
  onProvider: (provider: CollectorProvider) => void;
  onPrompt: (value: string) => void;
  onName: (value: string) => void;
  onWorkdir: (value: string) => void;
}) {
  return <>
    <label className="ad-field">任务名称（可选）<input className="ad-input" value={name} disabled={saving} onChange={(event) => onName(event.target.value)} placeholder="留空则自动生成" /></label>
    <label className="ad-field">收集数据源<select className="ad-select" value={provider} disabled={saving} onChange={(event) => onProvider(event.target.value as CollectorProvider)}><option value="hunter">鹰图 Hunter（通配符域名 / HackerOne）</option><option value="fofa">FOFA + 天眼查（企业名称 / 通配符域名）</option></select></label>
    <label className="ad-field">授权收集范围<textarea className="ad-textarea" value={prompt} disabled={saving} onChange={(event) => onPrompt(event.target.value)} placeholder={"https://hackerone.com/example\n*.example.com"} /></label>
    <label className="ad-field">工作目录（可选）<input className="ad-input" value={workdir} disabled={saving} onChange={(event) => onWorkdir(event.target.value)} placeholder="留空则使用全局配置" /></label>
  </>;
}

function CollectModal({ settings, settingsError, defaults, defaultsError, onClose, onOpenSettings, onStart }: CollectModalProps) {
  const [provider, setProvider] = useState<CollectorProvider>(settings?.provider === "fofa" ? "fofa" : "hunter");
  const [providerTouched, setProviderTouched] = useState(false);
  const [prompt, setPrompt] = useState("");
  const [name, setName] = useState("");
  const [workdir, setWorkdir] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string>();
  useEffect(() => {
    if (!providerTouched && settings) setProvider(settings.provider === "fofa" ? "fofa" : "hunter");
  }, [providerTouched, settings]);
  const incomplete = !settings || !providerConfigured(settings, provider);
  const start = async () => {
    const scopeError = validateCollectorScope(provider, prompt);
    if (scopeError) return setError(scopeError);
    if (incomplete) return setError("当前数据源配置不完整，请先完成插件设置。");
    if (!defaults) return setError(defaultsError || "任务默认设置尚未读取成功。");
    setSaving(true);
    setError(undefined);
    try {
      await onStart({ prompt, name: name.trim() || undefined, provider, workdir: workdir.trim() || undefined });
    } catch (reason) {
      setError(`启动资产收集失败：${String(reason)}`);
    } finally {
      setSaving(false);
    }
  };
  return <Modal title="启动资产收集" onClose={onClose} footer={<><Button disabled={saving} onClick={onClose}>取消</Button><Button className="primary" disabled={saving || incomplete || !defaults} onClick={() => void start()}>启动</Button></>}>
    <CollectFields provider={provider} prompt={prompt} name={name} workdir={workdir} saving={saving} onProvider={(value) => { setProviderTouched(true); setProvider(value); }} onPrompt={setPrompt} onName={setName} onWorkdir={setWorkdir} />
    <p className="ad-muted">访问模式：{defaults?.approval_mode === "full" ? "继承批量默认：完全访问" : defaults ? "继承批量默认：LLM 自动审批" : "正在读取任务默认设置…"}</p>
    {incomplete ? <Notice action={<Button className="compact" onClick={() => { onClose(); void onOpenSettings(); }}>前往插件设置</Button>}>当前数据源配置不完整，无法启动收集任务。</Notice> : null}
    {settingsError ? <p className="ad-field-error">{settingsError}</p> : null}{defaultsError ? <p className="ad-field-error">{defaultsError}</p> : null}{error ? <p className="ad-field-error">{error}</p> : null}
  </Modal>;
}
