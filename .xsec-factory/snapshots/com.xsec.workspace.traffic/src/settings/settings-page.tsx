import type { PluginHost } from "../types";
import { CaSection } from "./ca-section";
import { DefaultFilterSection } from "./filter-section";
import { RulesSection } from "./rules-section";

/** Render the settings page component. */
export function SettingsPage({ host }: { host: PluginHost }) {
  return <main className="traffic-settings"><div className="settings-shell"><header className="settings-title"><h1>抓包流量</h1><p>配置工作台默认过滤、MITM CA 和被动检测规则。</p></header><DefaultFilterSection host={host} /><CaSection host={host} /><RulesSection host={host} /></div></main>;
}
