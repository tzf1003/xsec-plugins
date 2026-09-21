import { useEffect } from "preact/hooks";
import { getTraffic, listTraffic } from "../api/traffic";
import { loadSettings } from "../api/settings";
import type { PluginHost, TrafficFilter } from "../types";
import { shouldClearNewTraffic, type WorkbenchState } from "./workbench-state";

const EVENT_COALESCE_MS = 180;

/** Load persisted traffic filters and refresh them after settings changes. */
export function useSettingsEffect({ host, state }: { host: PluginHost; state: WorkbenchState }) {
  useEffect(() => {
    let active = true;
    state.setError(null); state.setLoading(true);
    void loadSettings(host).then((value) => {
      if (!active) return;
      state.setDefaults(value); state.setFilter(value); state.resetPagination();
    }).catch((reason) => {
      if (!active) return;
      state.setError(`读取默认筛选失败：${String(reason)}`); state.setLoading(false);
    });
    return () => { active = false; };
  }, [host, state.resetPagination, state.settingsRevision]);
}

/** Serialize paginated traffic-list requests for the active filter and cursor. */
export function useTrafficListEffect(options: {
  host: PluginHost; visible: boolean; state: WorkbenchState; filter: TrafficFilter;
}) {
  const { host, visible, state, filter } = options;
  useEffect(() => {
    if (!state.defaults || !visible) return;
    const requestId = ++state.listRequest.current;
    state.setLoading(true); state.setListError(null);
    state.listQueue.current.schedule(async () => {
      try {
        const result = await listTraffic(host, state.cursor, filter);
        if (state.listRequest.current !== requestId) return;
        state.setRows(result.items); state.setNextCursor(result.next_cursor ?? null);
        if (shouldClearNewTraffic(state.cursor)) state.setHasNewTraffic(false);
        state.setSelectedId((current) => current && result.items.some((item) => item.flow_id === current) ? current : result.items[0]?.flow_id ?? null);
      } catch (reason) {
        if (state.listRequest.current === requestId) state.setListError(`读取抓包流量失败：${String(reason)}`);
      } finally {
        if (state.listRequest.current === requestId) state.setLoading(false);
      }
    });
    return () => {
      state.listRequest.current += 1;
      state.listQueue.current.clearPending();
    };
  }, [filter, host, state.cursor, state.defaults, state.revision, visible]);
}

/** Load the selected traffic detail while discarding stale responses. */
export function useTrafficDetailEffect(options: {
  host: PluginHost; visible: boolean; state: WorkbenchState;
}) {
  const { host, visible, state } = options;
  useEffect(() => {
    state.setDetailError(null);
    if (!visible || !state.selectedId) { state.setDetail(null); state.setDetailLoading(false); return; }
    const requestId = ++state.detailRequest.current;
    state.setDetail(null); state.setDetailLoading(true);
    void getTraffic(host, state.selectedId).then((value) => {
      if (state.detailRequest.current === requestId) state.setDetail(value);
    }).catch((reason) => { if (state.detailRequest.current === requestId) state.setDetailError(`读取流量详情失败：${String(reason)}`); })
      .finally(() => { if (state.detailRequest.current === requestId) state.setDetailLoading(false); });
    return () => { state.detailRequest.current += 1; };
  }, [host, state.selectedId, state.detailRevision, visible]);
}

/** Refresh the latest page or mark new traffic when persistence events arrive. */
export function useTrafficEvents({ host, visible, state }: {
  host: PluginHost; visible: boolean; state: WorkbenchState;
}) {
  useEffect(() => {
    if (!visible) return;
    const subscription = host.onData("xsec.traffic.persisted", () => {
      if (state.cursorRef.current !== undefined) { state.setHasNewTraffic(true); return; }
      if (state.refreshTimer.current !== undefined) window.clearTimeout(state.refreshTimer.current);
      state.refreshTimer.current = window.setTimeout(() => state.setRevision((value) => value + 1), EVENT_COALESCE_MS);
    });
    return () => {
      subscription.dispose();
      if (state.refreshTimer.current !== undefined) window.clearTimeout(state.refreshTimer.current);
    };
  }, [host, visible]);
}
