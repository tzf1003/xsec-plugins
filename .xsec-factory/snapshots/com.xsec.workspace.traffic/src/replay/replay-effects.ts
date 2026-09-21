import { useEffect, useRef } from "preact/hooks";
import { getTraffic } from "../api/traffic";
import { ensureHost, requestRaw } from "../proxy";
import type { PluginHost, ReplayAttempt, TrafficDetail } from "../types";
import type { ReplayState } from "./replay-state";
import { replayScheme } from "./target";

const STACK_THRESHOLD = 780;
const EVENT_COALESCE_MS = 180;

/** Initialize replay target and request fields from the captured source flow. */
function applySource(options: {
  state: ReplayState; detail: TrafficDetail; history: ReplayAttempt[];
}) {
  const { state, detail, history } = options;
  const scheme = replayScheme(detail.scheme);
  const initial = ensureHost(requestRaw(detail), {
    host: detail.host,
    port: detail.port,
    scheme,
  });
  const latest = history.at(-1);
  const activeScheme = latest ? replayScheme(latest.scheme) : scheme;
  state.drafts.current = new Map([["draft", initial], ...history.map((item) => [item.id, item.request_raw] as const)]);
  state.setSource(detail); state.setScheme(activeScheme);
  state.setTargetHost(latest?.target_host || detail.host);
  state.setTargetPort(latest?.target_port ?? detail.port ?? (activeScheme === "https" ? 443 : 80));
  state.attemptsRef.current = history; state.selectedIdRef.current = latest?.id ?? null;
  state.setAttempts(history); state.setSelectedId(latest?.id ?? null);
  state.setRawRequest(latest?.request_raw ?? initial);
}

/** Load the source flow and replay history when the flow identifier changes. */
export function useReplaySource({ host, flowId, state, refreshHistory }: {
  host: PluginHost; flowId: string; state: ReplayState;
  refreshHistory: (selectLatest: boolean) => Promise<ReplayAttempt[]>;
}) {
  useEffect(() => {
    let active = true; state.setLoading(true); state.setError(undefined);
    void Promise.all([getTraffic(host, flowId), refreshHistory(false)])
      .then(([detail, history]) => { if (active) applySource({ state, detail, history }); })
      .catch((reason) => { if (active) state.setError(`加载重放请求失败：${String(reason)}`); })
      .finally(() => { if (active) state.setLoading(false); });
    return () => { active = false; };
  }, [flowId, host, refreshHistory, state.sourceRevision]);
}

/** Load the selected replay attempt's captured result flow. */
export function useReplayResult({ host, resultId, state }: {
  host: PluginHost; resultId: string | null | undefined; state: ReplayState;
}) {
  useEffect(() => {
    state.setResultError(undefined);
    if (!resultId) { state.setResult(undefined); state.setResultLoading(false); return; }
    let active = true; state.setResult(undefined); state.setResultLoading(true);
    void getTraffic(host, resultId).then((value) => { if (active) state.setResult(value); })
      .catch((reason) => { if (active) state.setResultError(`读取重放结果失败：${String(reason)}`); })
      .finally(() => { if (active) state.setResultLoading(false); });
    return () => { active = false; };
  }, [host, resultId, state.resultRevision]);
}

/** Track whether the replay layout should stack at the current width. */
export function useReplayLayout(state: ReplayState) {
  useEffect(() => {
    const element = state.exchangeRef.current;
    if (!element || typeof ResizeObserver === "undefined") return;
    const update = () => state.setStacked(element.getBoundingClientRect().width < STACK_THRESHOLD);
    update(); const observer = new ResizeObserver(update); observer.observe(element);
    return () => observer.disconnect();
  }, [state.source]);
}

/** Refresh visible replay history when the host reports a recorded attempt. */
export function useReplayEvents(options: {
  host: PluginHost; visible: boolean; refreshHistory: (selectLatest: boolean) => Promise<ReplayAttempt[]>;
  setHistoryError: ReplayState["setHistoryError"];
}) {
  const { host, visible, refreshHistory, setHistoryError } = options;
  const previousVisible = useRef(visible);
  useEffect(() => {
    let timer: number | undefined;
    const reconcile = () => {
      if (timer !== undefined) window.clearTimeout(timer);
      timer = window.setTimeout(() => {
        timer = undefined;
        void refreshHistory(false).catch((reason) => setHistoryError(`刷新重放历史失败：${String(reason)}`));
      }, EVENT_COALESCE_MS);
    };
    const becameVisible = visible && !previousVisible.current;
    previousVisible.current = visible;
    if (!visible) return;
    if (becameVisible) {
      void refreshHistory(false).catch((reason) => setHistoryError(`刷新重放历史失败：${String(reason)}`));
    }
    const subscription = host.onData("xsec.traffic.persisted", reconcile);
    return () => {
      subscription.dispose();
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [host, refreshHistory, visible]);
}
