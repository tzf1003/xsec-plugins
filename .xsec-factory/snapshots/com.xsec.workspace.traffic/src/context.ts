import type { PluginContext, SettingsContext, WorkspaceToolContext } from "./types";

/** Require a named plugin-context value to be a non-null, non-array object. */
function object(value: unknown, name: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${name}无效`);
  return value as Record<string, unknown>;
}

/** Require a named plugin-context field to be a non-empty string. */
function requiredString(value: unknown, name: string): string {
  if (typeof value !== "string" || !value) throw new Error(`${name}无效`);
  return value;
}

/** Parse the host context into a supported Traffic surface context. */
export function parseContext(value: unknown): PluginContext {
  const root = object(value, "插件上下文");
  if (root.kind === "settings-page") return parseSettings(root);
  if (root.kind === "workspace-tool") return parseWorkspace(root);
  throw new Error("插件上下文类型无效");
}

/** Parse the settings-page route and surface metadata. */
function parseSettings(root: Record<string, unknown>): SettingsContext {
  const settings = object(root.settings, "设置页上下文");
  return {
    kind: "settings-page",
    settings: {
      id: requiredString(settings.id, "设置页 ID"),
      page: requiredString(settings.page, "设置页路由"),
    },
  };
}

/** Parse public display state; traffic data is always retrieved through Host RPC. */
function parseWorkspace(root: Record<string, unknown>): WorkspaceToolContext {
  const tool = object(root.tool, "工作区工具");
  const workspace = object(root.workspace, "工作区绑定");
  const surface = object(root.surface, "工作区表面");
  const entityId = tool.entityId === undefined ? {} : { entityId: requiredString(tool.entityId, "实体 ID") };
  return {
    kind: "workspace-tool",
    visible: root.visible !== false,
    surface: { bindingRevision: requiredString(surface.bindingRevision, "表面版本") },
    tool: {
      id: requiredString(tool.id, "工具实例 ID"),
      kind: requiredString(tool.kind, "工具类型"),
      title: requiredString(tool.title, "工具标题"),
      ...entityId,
    },
    workspace: {
      mode: workspace.mode === "observe" ? "observe" : "interactive",
      dock: workspace.dock === "bottom" ? "bottom" : "side",
      canAddComposerReference: workspace.canAddComposerReference === true,
    },
  };
}
