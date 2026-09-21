import type { PluginContext, PluginHost, WorkspaceToolContext } from "./types";
import { EmptyState, Notice } from "./ui/primitives";
import { DetailPage } from "./traffic/detail-page";
import { Workbench } from "./traffic/workbench";
import { ReplayPage } from "./replay/replay-page";
import { SettingsPage } from "./settings/settings-page";

/** Derive a stable render key from the active workspace-tool context. */
function workspaceInstanceKey(context: WorkspaceToolContext): string {
  return `${context.surface.bindingRevision}:${context.tool.entityId ?? context.tool.id}`;
}

/** Render the plugin app component. */
export function PluginApp({ host, context }: { host: PluginHost; context: PluginContext }) {
  if (context.kind === "settings-page") return <SettingsPage host={host} />;
  const instanceKey = workspaceInstanceKey(context);
  if (context.tool.kind === "traffic") return <Workbench key={instanceKey} host={host} context={context} />;
  const flowId = context.tool.entityId;
  if (!flowId) return <EmptyState>当前工具没有绑定流量</EmptyState>;
  if (context.tool.kind === "request-detail") return <DetailPage key={instanceKey} host={host} flowId={flowId} />;
  if (context.tool.kind === "traffic-replay") return <ReplayPage key={instanceKey} host={host} context={context} flowId={flowId} />;
  return <Notice>{`不支持的抓包工具：${context.tool.kind}`}</Notice>;
}
