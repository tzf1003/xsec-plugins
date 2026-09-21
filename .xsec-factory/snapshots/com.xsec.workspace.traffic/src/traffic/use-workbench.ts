import { useCallback, useMemo } from "preact/hooks";
import type { TargetedPointerEvent } from "preact";
import { addTrafficReference, openTrafficTool } from "../api/traffic";
import { activeFilterCount, filterInput, sameFilterSettings } from "../filter";
import type { FilterSettings, PluginHost, TrafficSummary, WorkspaceToolContext } from "../types";
import { useDebounced } from "../use-debounced";
import { useSettingsEffect, useTrafficDetailEffect, useTrafficEvents, useTrafficListEffect } from "./workbench-effects";
import { useWorkbenchState, type WorkbenchState } from "./workbench-state";

const MIN_LIST_HEIGHT = 160;
const FILTER_DELAY_MS = 250;

/** Build previous, next, and latest-page transitions for cursor pagination. */
function paginationActions(state: WorkbenchState) {
  const previousPage = () => {
    const target = state.previous.at(-1); if (!state.previous.length) return;
    state.prepareListTransition();
    state.setPrevious((value) => value.slice(0, -1)); state.setCursor(target);
    state.setPage((value) => Math.max(1, value - 1));
  };
  const nextPage = () => {
    const target = state.nextCursor; if (!target) return;
    state.prepareListTransition();
    state.setPrevious((value) => [...value, state.cursor]); state.setCursor(target);
    state.setPage((value) => value + 1);
  };
  const latestPage = () => { state.resetPagination(); state.setRevision((value) => value + 1); };
  return { previousPage, nextPage, latestPage };
}

/** Debounce only search fields before constructing the traffic request filter. */
function useRequestFilter(filter: FilterSettings) {
  const search = useMemo(() => ({
    searchTerm: filter.searchTerm,
    searchRegex: filter.searchRegex,
    searchCaseSensitive: filter.searchCaseSensitive,
    searchNegative: filter.searchNegative,
  }), [filter.searchTerm, filter.searchRegex, filter.searchCaseSensitive, filter.searchNegative]);
  const debouncedSearch = useDebounced(search, FILTER_DELAY_MS);
  return useMemo(() => filterInput({ ...filter, ...debouncedSearch }), [
    debouncedSearch, filter.onlyInScope, filter.hideWithoutResponse, filter.onlyParameterized,
    filter.mimeCategories, filter.statusClasses, filter.sources, filter.showOnlyExtensionsEnabled,
    filter.showOnlyExtensionsText, filter.hideExtensionsEnabled, filter.hideExtensionsText,
  ]);
}

/** Create a pointer handler that resizes the traffic-list pane. */
function listResize(state: WorkbenchState) {
  return (event: TargetedPointerEvent<HTMLDivElement>) => {
    event.preventDefault(); const startY = event.clientY; const start = state.listHeight;
    const move = (next: PointerEvent) => {
      const available = state.workbenchRef.current?.getBoundingClientRect().height ?? 720;
      const maximum = Math.max(MIN_LIST_HEIGHT, Math.floor(available * .45));
      state.setListHeight(Math.min(maximum, Math.max(MIN_LIST_HEIGHT, start + next.clientY - startY)));
    };
    const up = () => { document.removeEventListener("pointermove", move); document.removeEventListener("pointerup", up); };
    document.addEventListener("pointermove", move); document.addEventListener("pointerup", up);
  };
}

/** Compose traffic loading, filters, pagination, tools, and reference actions. */
export function useWorkbench(host: PluginHost, context: WorkspaceToolContext) {
  const state = useWorkbenchState();
  const requestFilter = useRequestFilter(state.filter);
  const applyFilter = useCallback((value: FilterSettings) => {
    if (sameFilterSettings(value, state.filter)) return;
    state.setFilter(value); state.resetPagination();
  }, [state.filter, state.resetPagination]);
  state.cursorRef.current = state.cursor;
  useSettingsEffect({ host, state });
  useTrafficListEffect({ host, visible: context.visible, state, filter: requestFilter });
  useTrafficDetailEffect({ host, visible: context.visible, state });
  useTrafficEvents({ host, visible: context.visible, state });
  const pages = paginationActions(state);
  const openTool = async (row: TrafficSummary, toolId: "request-detail" | "traffic-replay") => {
    state.setError(null);
    const title = toolId === "request-detail" ? `${row.method} ${row.host}` : `重放 ${row.method} ${row.host}`;
    try { await openTrafficTool(host, { toolId, flowId: row.flow_id, title }); }
    catch (reason) { state.setError(`打开流量工具失败：${String(reason)}`); }
  };
  const openDetail = (row: TrafficSummary) => { void openTool(row, "request-detail"); };
  const openReplay = (row: TrafficSummary) => { void openTool(row, "traffic-replay"); };
  const addReference = async () => {
    if (!state.detail) return;
    state.setError(null);
    try { await addTrafficReference(host, state.detail.flow_id); }
    catch (reason) { state.setError(`引用流量失败：${String(reason)}`); }
  };
  return {
    ...state, ...pages, applyFilter, resizeList: listResize(state), openDetail, openReplay, addReference,
    selectedDetail: state.detail?.flow_id === state.selectedId ? state.detail : null,
    activeFilters: activeFilterCount(state.filter),
    canAddReference: context.workspace.canAddComposerReference === true,
  };
}

export type WorkbenchModel = ReturnType<typeof useWorkbench>;
