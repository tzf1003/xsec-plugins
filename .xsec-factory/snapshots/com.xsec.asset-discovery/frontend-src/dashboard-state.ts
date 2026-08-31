import { useCallback, useEffect, useState } from "react";
import type { AssetDiscoveryApi } from "./host";
import type { CollectionRun, CollectorSettings, ExecutionDefaults } from "./types";
import { collectionBucket } from "./utils";

const RUN_REFRESH_INTERVAL_MS = 5_000;

function useRuns(api: AssetDiscoveryApi) {
  const [runs, setRuns] = useState<CollectionRun[]>([]);
  const [runsLoading, setRunsLoading] = useState(true);
  const [runsError, setRunsError] = useState<string>();
  const loadRuns = useCallback(async (): Promise<boolean> => {
    setRunsLoading(true);
    setRunsError(undefined);
    try {
      setRuns(await api.runs());
      return true;
    } catch (reason) {
      setRunsError(`读取收集任务失败：${String(reason)}`);
      return false;
    } finally {
      setRunsLoading(false);
    }
  }, [api]);
  return { runs, runsLoading, runsError, loadRuns };
}

function useCollectorSetup(api: AssetDiscoveryApi) {
  const [defaults, setDefaults] = useState<ExecutionDefaults>();
  const [defaultsError, setDefaultsError] = useState<string>();
  const [settings, setSettings] = useState<CollectorSettings>();
  const [settingsError, setSettingsError] = useState<string>();
  const loadDefaults = useCallback(async () => {
    setDefaultsError(undefined);
    try {
      setDefaults(await api.defaults());
    } catch (reason) {
      setDefaultsError(`读取任务默认设置失败：${String(reason)}`);
    }
  }, [api]);
  const loadSettings = useCallback(async () => {
    setSettingsError(undefined);
    try {
      setSettings(await api.settings());
    } catch (reason) {
      setSettingsError(`读取资产发现设置失败：${String(reason)}`);
    }
  }, [api]);
  return { defaults, defaultsError, settings, settingsError, loadDefaults, loadSettings };
}

function useActiveRunRefresh(runs: CollectionRun[], loadRuns: () => Promise<boolean>) {
  useEffect(() => {
    if (!runs.some((run) => collectionBucket(run.status) === "running")) return;
    const timer = window.setInterval(() => {
      void loadRuns().then((healthy) => {
        if (!healthy) window.clearInterval(timer);
      });
    }, RUN_REFRESH_INTERVAL_MS);
    return () => window.clearInterval(timer);
  }, [loadRuns, runs]);
}

export function useDashboardState(api: AssetDiscoveryApi) {
  const runs = useRuns(api);
  const setup = useCollectorSetup(api);
  const refresh = useCallback(async () => {
    await Promise.all([runs.loadRuns(), setup.loadDefaults(), setup.loadSettings()]);
  }, [runs.loadRuns, setup.loadDefaults, setup.loadSettings]);
  useEffect(() => { void refresh(); }, [refresh]);
  useActiveRunRefresh(runs.runs, runs.loadRuns);
  return { ...runs, ...setup, refresh };
}
