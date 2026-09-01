import { createRoot, type Root } from "react-dom/client";
import { AssetDiscoveryApp } from "./app";
import { createAssetDiscoveryApi } from "./host";
import { SettingsPage } from "./settings";
import type { PluginHost } from "./types";
import { styles } from "./styles";

function page(host: PluginHost) {
  const api = createAssetDiscoveryApi(host);
  if (host.context?.kind === "settings-page") return <SettingsPage api={api} />;
  return <AssetDiscoveryApp api={api} host={host} />;
}

function pageKind(host: PluginHost): string {
  return typeof host.context?.kind === "string" ? host.context.kind : "asset-discovery";
}

export function activate(host: PluginHost) {
  let root: Root | undefined;
  let revision = 0;
  console.debug("asset-discovery.frontend.activate", { page: pageKind(host) });
  const render = () => root?.render(<><style>{styles}</style><div key={revision}>{page(host)}</div></>);
  return {
    mount(element: HTMLElement) {
      root = createRoot(element);
      console.info("asset-discovery.frontend.mount", { page: pageKind(host) });
      render();
    },
    update() { revision += 1; console.debug("asset-discovery.frontend.update", { page: pageKind(host), revision }); render(); },
    dispose() { console.debug("asset-discovery.frontend.dispose", { page: pageKind(host) }); root?.unmount(); },
  };
}
