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

export function activate(host: PluginHost) {
  let root: Root | undefined;
  let revision = 0;
  const render = () => root?.render(<><style>{styles}</style><div key={revision}>{page(host)}</div></>);
  return {
    mount(element: HTMLElement) {
      root = createRoot(element);
      render();
    },
    update() { revision += 1; render(); },
    dispose() { root?.unmount(); },
  };
}
