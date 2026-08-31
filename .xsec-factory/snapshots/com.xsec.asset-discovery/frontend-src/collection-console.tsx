import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { AssetDiscoveryApi } from "./host";
import type { CollectionRun, ExecutionLogPage, ExecutionSnapshot } from "./types";
import { collectionBucket, collectionResultDescription, formatDuration, formatTime, providerLabel, runTitle } from "./utils";
import { ConfirmModal, Button, EmptyState, ErrorState, Notice, Section, StatusBadge } from "./ui";
import { ExecutionProcess } from "./execution-process";

const LIVE_REFRESH_INTERVAL_MS = 4_000;
type LoadState = "ok" | "error" | "stale";

type ConsoleProps = {
  api: AssetDiscoveryApi;
  run?: CollectionRun;
  onChanged: () => Promise<void>;
  onDeleted: () => void;
  onOpenAssets: (runId: string) => void;
  onOpenSettings: () => Promise<void>;
};

function flow(run: CollectionRun) {
  const bucket = collectionBucket(run.status);
  const terminal = bucket === "completed" || bucket === "failed" || bucket === "cancelled";
  const completed = bucket === "completed";
  const failed = bucket === "failed" || bucket === "cancelled";
  return [
    { title: "启动收集 Agent", state: "done", text: formatTime(run.created_at) },
    { title: `查询 ${providerLabel(run.provider)}`, state: bucket === "running" && !run.total ? "active" : completed || run.total ? "done" : failed ? "failed" : "pending", text: "按授权范围检索资产" },
    { title: "结果入库", state: completed || run.total ? "done" : bucket === "running" ? "pending" : failed ? "skipped" : "pending", text: `${run.total} 条资产` },
    { title: bucket === "cancelled" ? "收集已停止" : bucket === "failed" ? "收集失败" : "收集完成", state: terminal ? (failed ? "failed" : "done") : "pending", text: terminal ? formatTime(run.finished_at) : "等待任务结束" },
  ];
}

function Logs({ page, error, onMore, onRefresh }: { page?: ExecutionLogPage; error?: string; onMore: () => void; onRefresh: () => void }) {
  if (error) return <ErrorState error={error} onRetry={onRefresh} />;
  if (!page?.lines.length) return <EmptyState>暂无可用日志</EmptyState>;
  return <><pre className="ad-code">{page.lines.map((line) => line.text).join("\n")}</pre>{page.truncated ? <Notice>当前日志页已按隔离通道大小截断。</Notice> : null}{page.next_cursor ? <Button className="compact" onClick={onMore}>读取更多日志</Button> : null}</>;
}

function TaskDetails({ run }: { run: CollectionRun }) {
  return <Section title="任务信息"><dl className="ad-inspector"><dt>任务 ID</dt><dd title={run.id}>{run.id}</dd><dt>数据源</dt><dd>{providerLabel(run.provider)}</dd><dt>状态</dt><dd><StatusBadge status={run.status} /></dd><dt>资产数</dt><dd>{run.total}</dd><dt>创建时间</dt><dd>{formatTime(run.created_at)}</dd><dt>更新时间</dt><dd>{formatTime(run.updated_at)}</dd><dt>完成时间</dt><dd>{formatTime(run.finished_at)}</dd><dt>耗时</dt><dd>{formatDuration(run.created_at, run.finished_at)}</dd><dt>访问模式</dt><dd>{run.approval_mode === "full" ? "继承批量默认：完全访问" : "继承批量默认：LLM 自动审批"}</dd>{run.terminal_reason ? <><dt>结算原因</dt><dd>{run.terminal_reason}</dd></> : null}{run.session_id ? <><dt>会话 ID</dt><dd>{run.session_id}</dd></> : null}</dl></Section>;
}

function ConsoleHeader({ run, mutating, onStop, onOpenAssets, onRefresh, onDelete }: { run: CollectionRun; mutating: boolean; onStop: () => void; onOpenAssets: () => void; onRefresh: () => void; onDelete: () => void }) {
  const running = collectionBucket(run.status) === "running";
  return <header className="ad-console-header"><div><div className="ad-run-card-title"><h2>{runTitle(run)}</h2><StatusBadge status={run.status} /></div><p className="ad-description">{providerLabel(run.provider)} · {run.total} 条资产 · {formatDuration(run.created_at, run.finished_at)}</p></div><div className="ad-actions">{running ? <Button className="danger" disabled={mutating} onClick={onStop}>停止收集</Button> : null}<Button className="primary" onClick={onOpenAssets}>查看资产{run.total ? `（${run.total}）` : ""}</Button><Button onClick={onRefresh}>刷新</Button><Button className="danger" disabled={mutating} onClick={onDelete}>删除</Button></div></header>;
}

function mergeLogLines(current: ExecutionLogPage, next: ExecutionLogPage) {
  const lines = [...current.lines, ...next.lines];
  return lines.filter((line, index) => lines.findIndex((item) => item.timestamp === line.timestamp && item.direction === line.direction && item.text === line.text) === index);
}

function useRequestGuard(runId?: string) {
  const selection = useRef({ runId, generation: 0, request: 0 });
  if (selection.current.runId !== runId) selection.current = { runId, generation: selection.current.generation + 1, request: 0 };
  return useCallback(() => {
    const generation = selection.current.generation;
    const request = selection.current.request + 1;
    selection.current.request = request;
    return () => selection.current.runId === runId && selection.current.generation === generation && selection.current.request === request;
  }, [runId]);
}

function useTerminalSnapshot(runId: string | undefined, running: boolean, refreshDetails: () => Promise<boolean>) {
  const previous = useRef({ runId, running });
  useEffect(() => {
    const terminal = previous.current.runId === runId && previous.current.running && !running;
    previous.current = { runId, running };
    if (terminal) void refreshDetails();
  }, [refreshDetails, runId, running]);
}

function useConsoleContent(api: AssetDiscoveryApi, runId: string | undefined, running: boolean) {
  const [execution, setExecution] = useState<ExecutionSnapshot>();
  const [logs, setLogs] = useState<ExecutionLogPage>();
  const [executionError, setExecutionError] = useState<string>();
  const [logsError, setLogsError] = useState<string>();
  const [streamPolling, setStreamPolling] = useState(true);
  const logCursor = useRef<string>();
  const refreshInFlight = useRef(false);
  const beginRefreshRequest = useRequestGuard(runId);
  const beginExecutionRequest = useRequestGuard(runId);
  const beginLogsRequest = useRequestGuard(runId);
  const loadExecution = useCallback(async (isCurrent = beginExecutionRequest()): Promise<LoadState> => {
    if (!runId || !isCurrent()) return "stale";
    setExecutionError(undefined);
    try { const next = await api.execution(runId); if (!isCurrent()) return "stale"; setExecution(next); return "ok"; } catch (reason) { if (!isCurrent()) return "stale"; setExecutionError(`读取执行过程失败：${String(reason)}`); return "error"; }
  }, [api, beginExecutionRequest, runId]);
  const loadLogs = useCallback(async (cursor?: string, isCurrent = beginLogsRequest()): Promise<LoadState> => {
    if (!runId || !isCurrent()) return "stale";
    setLogsError(undefined);
    try {
      const next = await api.logs(runId, cursor);
      if (!isCurrent()) return "stale";
      logCursor.current = next.next_cursor ?? cursor;
      setLogs((current) => cursor && current
        ? { ...next, lines: mergeLogLines(current, next), truncated: Boolean(current.truncated || next.truncated) }
        : next);
      return "ok";
    } catch (reason) { if (!isCurrent()) return "stale"; setLogsError(`读取收集日志失败：${String(reason)}`); return "error"; }
  }, [api, beginLogsRequest, runId]);
  const refreshDetails = useCallback(async (supersede = true) => {
    if (!supersede && refreshInFlight.current) return true;
    const isCurrent = beginRefreshRequest();
    refreshInFlight.current = true;
    try {
      const result = await Promise.all([loadExecution(), loadLogs(logCursor.current)]);
      if (!isCurrent()) return false;
      const failed = result.includes("error");
      const succeeded = result.every((state) => state === "ok");
      if (failed) setStreamPolling(false);
      if (succeeded) setStreamPolling(true);
      return !failed;
    } finally {
      if (isCurrent()) refreshInFlight.current = false;
    }
  }, [beginRefreshRequest, loadExecution, loadLogs]);

  useEffect(() => {
    logCursor.current = undefined;
    setExecution(undefined); setLogs(undefined); setExecutionError(undefined); setLogsError(undefined); setStreamPolling(true);
    if (runId) void refreshDetails();
  }, [refreshDetails, runId]);
  useEffect(() => {
    if (!running || !streamPolling) return;
    const timer = window.setInterval(() => { void refreshDetails(false); }, LIVE_REFRESH_INTERVAL_MS);
    return () => window.clearInterval(timer);
  }, [refreshDetails, running, streamPolling]);
  useTerminalSnapshot(runId, running, refreshDetails);
  return { execution, logs, executionError, logsError, setLogsError, loadLogs, refreshDetails };
}

export function CollectionConsole({ api, run, onChanged, onDeleted, onOpenAssets, onOpenSettings }: ConsoleProps) {
  const [mutating, setMutating] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const runId = run?.id;
  const running = run ? collectionBucket(run.status) === "running" : false;
  const stages = useMemo(() => run ? flow(run) : [], [run]);
  const content = useConsoleContent(api, runId, running);
  if (!run) return <section className="ad-console"><EmptyState>选择左侧收集任务，查看范围、日志与任务详情</EmptyState></section>;
  const stop = async () => { setMutating(true); try { await api.stop(run.id); await onChanged(); } catch (reason) { content.setLogsError(`停止收集失败：${String(reason)}`); } finally { setMutating(false); } };
  const remove = async () => { setMutating(true); try { await api.deleteRun(run.id); setDeleteOpen(false); onDeleted(); await onChanged(); } catch (reason) { content.setLogsError(`删除收集任务失败：${String(reason)}`); } finally { setMutating(false); } };
  const failure = collectionResultDescription(run);

  return <section className="ad-console"><ConsoleHeader run={run} mutating={mutating} onStop={() => void stop()} onOpenAssets={() => onOpenAssets(run.id)} onRefresh={() => void content.refreshDetails()} onDelete={() => setDeleteOpen(true)} /><div className="ad-console-body">
    {failure ? <Notice action={run.failure_code === "missing_configuration" ? <Button className="compact" onClick={() => void onOpenSettings()}>打开资产发现设置</Button> : undefined}>{failure}</Notice> : null}
    <div className="ad-flow">{stages.map((stage) => <article className={`ad-flow-card ${stage.state}`} key={stage.title}><strong>{stage.title}</strong><small>{stage.text}</small></article>)}</div>
    <Section title="实时执行过程" actions={<span className="ad-muted">{running ? "实时更新" : "执行记录"}</span>}><ExecutionProcess execution={content.execution} error={content.executionError} live={running} onRefresh={() => void content.refreshDetails()} /></Section>
    <div className="ad-split"><Section title="授权收集范围"><pre className="ad-code">{run.scope_prompt || "未填写范围"}</pre></Section><Section title="进程日志" actions={<Button className="text compact" onClick={() => void content.refreshDetails()}>重新拉取</Button>}><Logs page={content.logs} error={content.logsError} onRefresh={() => void content.refreshDetails()} onMore={() => void content.loadLogs(content.logs?.next_cursor ?? undefined)} /></Section></div>
    <TaskDetails run={run} />
  </div>{deleteOpen ? <ConfirmModal title="删除收集任务" detail="会同时删除任务绑定的资产池条目，且不可恢复。" confirmLabel="删除" danger busy={mutating} onClose={() => setDeleteOpen(false)} onConfirm={() => void remove()} /> : null}</section>;
}
