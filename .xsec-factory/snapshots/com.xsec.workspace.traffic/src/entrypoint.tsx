import { render } from "preact";
import { PluginApp } from "./plugin-app";
import { parseContext } from "./context";
import { styles } from "./styles/index";
import type { Disposable, PluginContext, PluginHost } from "./types";

const THEME_TOKEN_NAME = /^[a-z0-9-]+$/iu;

/** Apply theme to the active plugin state. */
function applyTheme(theme: Record<string, string>): void {
  for (const [name, value] of Object.entries(theme)) {
    if (THEME_TOKEN_NAME.test(name)) document.documentElement.style.setProperty(`--xsec-${name}`, value);
  }
  const mode = theme["color-mode"];
  if (mode === "light" || mode === "dark") document.documentElement.style.colorScheme = mode;
}

/** Install styles for the active plugin surface. */
function installStyles(root: HTMLElement): HTMLStyleElement {
  const style = document.createElement("style");
  style.dataset.xsecTrafficStyles = ""; style.textContent = styles; root.before(style);
  return style;
}

type Controller = {
  mount(root: HTMLElement, context: unknown): void;
  update(context: unknown): void;
  dispose(): void;
};

/** Read initial context from the active plugin context. */
function readInitialContext(host: PluginHost): PluginContext | undefined {
  if (host.context?.kind === undefined) return undefined;
  return parseContext(host.context);
}

/** Activate the Traffic frontend controller against the Desktop host bridge. */
export function activate(host: PluginHost): Controller {
  if (host.apiVersion !== 2) throw new Error(`不支持的 Frontend API：${host.apiVersion}`);
  console.debug("traffic.frontend.activate", { apiVersion: host.apiVersion });
  let root: HTMLElement | undefined;
  let current = readInitialContext(host);
  let themeSubscription: Disposable | undefined;
  let style: HTMLStyleElement | undefined;
  const draw = () => {
    if (!root || !current) return;
    render(<PluginApp host={host} context={current} />, root);
  };
  return {
    mount(nextRoot, context) {
      root = nextRoot;
      current = parseContext(context);
      console.info("traffic.frontend.mount", {
        contextKind: current.kind,
        toolKind: current.kind === "workspace-tool" ? current.tool.kind : undefined,
      });
      style = installStyles(root);
      themeSubscription = host.onTheme(applyTheme);
      draw();
    },
    update(context) {
      current = parseContext(context);
      console.debug("traffic.frontend.update", {
        contextKind: current.kind,
        visible: current.kind === "workspace-tool" ? current.visible : undefined,
      });
      draw();
    },
    dispose() {
      console.debug("traffic.frontend.dispose");
      themeSubscription?.dispose(); themeSubscription = undefined;
      if (root) render(null, root);
      style?.remove(); style = undefined;
      root = undefined;
      current = undefined;
    },
  };
}
