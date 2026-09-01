import { useCallback, useEffect, useRef, useState } from "react";
import type { AssetDiscoveryApi } from "./host";
import type { CollectionRun, CollectorSettings, ExecutionDefaults } from "./types";
import { collectionBucket } from "./utils";

const RUN_REFRESH_INTERVAL_MS = 5_000;
type RunsLoadState = "ok" | "error" | "stale";

function useRuns(api: AssetDiscoveryApi) {
  const [runs, setRuns] = useState<CollectionRun[]>([]);
  const [runsLoading, setRunsLoading] = useState(true);
  const [runsError, setRunsError] = useState<string>();
  const requestGeneration = useRef(0);
  const requestInFlight = useRef<Promise<RunsLoadState>>();
  const queuedRefresh = useRef<Promise<RunsLoadState>>();
  const loadRuns = useCallback((queueAfterCurrent = false): Promise<RunsLoadState> => {
    const start = (): Promise<RunsLoadState> => {
      const generation = ++requestGeneration.current;
      setRunsLoading(true);
      setRunsError(undefined);
      const request = Promise.resolve().then(async () => {
        try {
          const next = await api.runs();
          if (generation !== requestGeneration.current) return "stale";
          setRuns(next);
          return "ok";
        } catch (reason) {
          if (generation !== requestGeneration.current) return "stale";
          setRunsError(`读取收集任务失败：${String(reason)}`);
          return "error";
        } finally {
          if (requestInFlight.current === request) requestInFlight.current = undefined;
          if (generation === requestGeneration.current) setRunsLoading(false);
        }
      });
      requestInFlight.current = request;
      return request;
    };
    const current = requestInFlight.current;
    if (!current) return start();
    if (!queueAfterCurrent) return Promise.resolve("stale");
    if (queuedRefresh.current) return queuedRefresh.current;
    const queued = current.then(() => {
      queuedRefresh.current = undefined;
      return start();
    });
    queuedRefresh.current = queued;
    return queued;
  }, [api]);
  const removeRun = useCallback((runId: string) => {
    requestGeneration.current += 1;
    setRuns((current) => current.filter((run) => run.id !== runId));
  }, []);
  return { runs, runsLoading, runsError, loadRuns, removeRun };
}

function useCollectorSetup(api: AssetDiscoveryApi) {
  const [defaults, setDefaults] = useState<ExecutionDefaults>();
  const [defaultsReady, setDefaultsReady] = useState(false);
  const [defaultsError, setDefaultsError] = useState<string>();
  const defaultsGeneration = useRef(0);
  const [settings, setSettings] = useState<CollectorSettings>();
  const [settingsReady, setSettingsReady] = useState(false);
  const [settingsError, setSettingsError] = useState<string>();
  const settingsGeneration = useRef(0);
  const loadDefaults = useCallback(async () => {
    const generation = ++defaultsGeneration.current;
    setDefaultsReady(false);
    setDefaultsError(undefined);
    try {
      const next = await api.defaults();
      if (generation !== defaultsGeneration.current) return;
      setDefaults(next);
      setDefaultsReady(true);
    } catch (reason) {
      if (generation === defaultsGeneration.current) setDefaultsError(`读取任务默认设置失败：${String(reason)}`);
    }
  }, [api]);
  const loadSettings = useCallback(async () => {
    const generation = ++settingsGeneration.current;
    setSettingsReady(false);
    setSettingsError(undefined);
    try {
      const next = await api.settings();
      if (generation !== settingsGeneration.current) return;
      setSettings(next);
      setSettingsReady(true);
    } catch (reason) {
      if (generation === settingsGeneration.current) setSettingsError(`读取资产发现设置失败：${String(reason)}`);
    }
  }, [api]);
  return { defaults, defaultsReady, defaultsError, settings, settingsReady, settingsError, loadDefaults, loadSettings };
}

function useActiveRunRefresh(runs: CollectionRun[], loadRuns: () => Promise<RunsLoadState>) {
  useEffect(() => {
    if (!runs.some((run) => collectionBucket(run.status) === "running")) return;
    const timer = window.setInterval(() => {
      void loadRuns().then((state) => {
        if (state === "error") window.clearInterval(timer);
      });
    }, RUN_REFRESH_INTERVAL_MS);
    return () => window.clearInterval(timer);
  }, [loadRuns, runs]);
}

export function useDashboardState(api: AssetDiscoveryApi) {
  const runs = useRuns(api);
  const setup = useCollectorSetup(api);
  const refresh = useCallback(async () => {
    await Promise.all([runs.loadRuns(true), setup.loadDefaults(), setup.loadSettings()]);
  }, [runs.loadRuns, setup.loadDefaults, setup.loadSettings]);
  useEffect(() => { void refresh(); }, [refresh]);
  useActiveRunRefresh(runs.runs, runs.loadRuns);
  return { ...runs, ...setup, refresh };
}
