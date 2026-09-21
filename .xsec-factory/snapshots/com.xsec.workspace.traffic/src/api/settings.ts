import { extensionList, parseFilterSettings } from "../filter";
import { loggedAction } from "../logging";
import type { CaStatus, FilterSettings, PassiveRule, PluginHost } from "../types";
import { array, boolean, object, optionalString, string } from "./value";

/** Convert host filter fields into the Traffic settings model. */
function domainToSettings(value: unknown): FilterSettings {
  const filter = object(value, "默认筛选");
  const extensions = object(filter.extensions, "扩展名筛选");
  return parseFilterSettings({
    version: 1,
    onlyInScope: filter.onlyInScope,
    hideWithoutResponse: filter.hideWithoutResponse,
    onlyParameterized: filter.onlyParameterized,
    mimeCategories: filter.mimeCategories,
    statusClasses: filter.statusClasses,
    sources: filter.sources,
    searchTerm: "",
    searchRegex: false,
    searchCaseSensitive: false,
    searchNegative: false,
    showOnlyExtensionsEnabled: extensions.showOnlyEnabled,
    showOnlyExtensionsText: array(extensions.showOnly, "仅显示扩展名").join(","),
    hideExtensionsEnabled: extensions.hideEnabled,
    hideExtensionsText: array(extensions.hide, "隐藏扩展名").join(","),
  });
}

/** Convert Traffic settings into the host filter payload. */
function settingsToDomain(value: FilterSettings) {
  return {
    onlyInScope: value.onlyInScope,
    hideWithoutResponse: value.hideWithoutResponse,
    onlyParameterized: value.onlyParameterized,
    mimeCategories: value.mimeCategories,
    statusClasses: value.statusClasses,
    sources: value.sources,
    search: null,
    extensions: {
      showOnlyEnabled: value.showOnlyExtensionsEnabled,
      showOnly: extensionList(value.showOnlyExtensionsText),
      hideEnabled: value.hideExtensionsEnabled,
      hide: extensionList(value.hideExtensionsText),
    },
  };
}

/** Parse the host settings response into the Traffic settings model. */
function settingsResponse(value: unknown): FilterSettings {
  return domainToSettings(object(value, "流量设置").filter);
}

/** Load settings through the host boundary. */
export async function loadSettings(host: PluginHost): Promise<FilterSettings> {
  return settingsResponse(await host.request("xsec.traffic.settings.get", {}));
}

/** Persist settings through the host boundary. */
export async function saveSettings(host: PluginHost, filter: FilterSettings): Promise<FilterSettings> {
  return loggedAction("traffic.settings.filter.save", {}, async () => (
    settingsResponse(await host.request("xsec.traffic.settings.set", { filter: settingsToDomain(filter) }))
  ));
}

/** Parse and validate the host CA status response. */
function caStatus(value: unknown): CaStatus {
  const row = object(value, "CA 状态");
  return {
    ca_exists: boolean(row.ca_exists, "CA 文件状态"),
    ca_cert_path: optionalString(row.ca_cert_path, "CA 路径"),
    ca_sha256: optionalString(row.ca_sha256, "CA 摘要"),
    trust_store_kind: optionalString(row.trust_store_kind, "证书存储") ?? undefined,
    trust_supported: row.trust_supported === undefined ? undefined : boolean(row.trust_supported, "证书存储支持状态"),
    trust_imported: boolean(row.trust_imported, "CA 导入状态"),
    trust_detail: optionalString(row.trust_detail, "CA 导入详情") ?? undefined,
  };
}

/** Load CA status through the host boundary. */
export async function loadCaStatus(host: PluginHost): Promise<CaStatus> {
  return caStatus(await host.request("xsec.traffic.ca.status", {}));
}

/** Import the interception CA through the host boundary. */
export async function importCa(host: PluginHost): Promise<CaStatus> {
  return loggedAction("traffic.settings.ca.import", {}, async () => (
    caStatus(await host.request("xsec.traffic.ca.import", {}))
  ));
}

/** Rotate the interception CA through the host boundary. */
export async function rotateCa(host: PluginHost): Promise<CaStatus> {
  return loggedAction("traffic.settings.ca.rotate", {}, async () => (
    caStatus(await host.request("xsec.traffic.ca.rotate", {}))
  ));
}

/** Parse and validate a passive scanning rule. */
function passiveRule(value: unknown): PassiveRule {
  const row = object(value, "被动规则");
  const severity = string(row.severity, "规则级别");
  if (!new Set(["low", "medium", "high", "critical"]).has(severity)) throw new Error("规则级别格式无效");
  return {
    rule_id: string(row.rule_id, "规则 ID"),
    severity: severity as PassiveRule["severity"],
    pattern: string(row.pattern, "规则表达式"),
    enabled: boolean(row.enabled, "规则启用状态"),
  };
}

/** Load rules through the host boundary. */
export async function loadRules(host: PluginHost): Promise<PassiveRule[]> {
  return array(await host.request("xsec.traffic.passive-rules.list", {}), "被动规则列表").map(passiveRule);
}

/** Persist rule through the host boundary. */
export async function saveRule(host: PluginHost, rule: PassiveRule): Promise<void> {
  await loggedAction("traffic.settings.passive-rule.save", {
    severity: rule.severity,
    enabled: rule.enabled,
  }, async () => {
    await host.request("xsec.traffic.passive-rules.upsert", {
      ruleId: rule.rule_id,
      severity: rule.severity,
      pattern: rule.pattern,
      enabled: rule.enabled,
    });
  });
}

/** Toggle rule through the host boundary. */
export async function toggleRule(host: PluginHost, ruleId: string, enabled: boolean): Promise<void> {
  await loggedAction("traffic.settings.passive-rule.toggle", { enabled }, async () => {
    await host.request("xsec.traffic.passive-rules.toggle", { ruleId, enabled });
  });
}

/** Delete rule through the host boundary. */
export async function deleteRule(host: PluginHost, ruleId: string): Promise<void> {
  await loggedAction("traffic.settings.passive-rule.delete", {}, async () => {
    await host.request("xsec.traffic.passive-rules.delete", { ruleId });
  });
}
