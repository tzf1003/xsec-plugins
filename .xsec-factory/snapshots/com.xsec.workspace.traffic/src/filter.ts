import type { FilterSettings, MimeCategory, StatusClass, TrafficFilter, TrafficSource } from "./types";

export const MIME_CATEGORIES: readonly MimeCategory[] = [
  "html", "script", "xml", "otherText", "css", "images", "otherBinary", "unknown",
];
export const STATUS_CLASSES: readonly StatusClass[] = [
  "informational", "success", "redirection", "clientError", "serverError",
];
export const TRAFFIC_SOURCES: readonly TrafficSource[] = ["proxy", "replay"];
export const DEFAULT_SHOW_ONLY_EXTENSIONS = "asp,aspx,jsp,php";
export const DEFAULT_HIDDEN_EXTENSIONS = "gif,jpg,png,ico,css,woff,woff2,ttf,svg";

/** Create the accepted default filter settings for HTTP history. */
export function defaultFilterSettings(): FilterSettings {
  return {
    version: 1,
    onlyInScope: false,
    hideWithoutResponse: false,
    onlyParameterized: false,
    mimeCategories: ["html", "script", "xml", "otherText", "unknown"],
    statusClasses: [...STATUS_CLASSES],
    sources: [...TRAFFIC_SOURCES],
    searchTerm: "",
    searchRegex: false,
    searchCaseSensitive: false,
    searchNegative: false,
    showOnlyExtensionsEnabled: false,
    showOnlyExtensionsText: DEFAULT_SHOW_ONLY_EXTENSIONS,
    hideExtensionsEnabled: false,
    hideExtensionsText: DEFAULT_HIDDEN_EXTENSIONS,
  };
}

/** Normalize a delimited extension field into a unique lowercase list. */
export function extensionList(value: string): string[] {
  const unique = new Set<string>();
  for (const item of value.split(/[,，;；\s]+/u)) {
    const normalized = item.trim().replace(/^\.+/u, "").toLowerCase();
    if (normalized) unique.add(normalized);
  }
  return [...unique];
}

/** Validate an enum-array field and remove duplicate values. */
function known<T extends string>(value: unknown, allowed: readonly T[], name: string): T[] {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string" || !allowed.includes(item as T))) {
    throw new Error(`${name}格式无效`);
  }
  return [...new Set(value)] as T[];
}

/** Validate a named filter field as a boolean. */
function bool(value: unknown, name: string): boolean {
  if (typeof value !== "boolean") throw new Error(`${name}格式无效`);
  return value;
}

/** Validate a named filter field as text. */
function text(value: unknown, name: string): string {
  if (typeof value !== "string") throw new Error(`${name}格式无效`);
  return value;
}

/** Parse stored filter settings and reject unsupported field values. */
export function parseFilterSettings(value: unknown): FilterSettings {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("默认筛选格式无效");
  const row = value as Record<string, unknown>;
  return {
    version: 1,
    onlyInScope: bool(row.onlyInScope, "范围筛选"),
    hideWithoutResponse: bool(row.hideWithoutResponse, "无响应筛选"),
    onlyParameterized: bool(row.onlyParameterized, "参数筛选"),
    mimeCategories: known(row.mimeCategories, MIME_CATEGORIES, "MIME 筛选"),
    statusClasses: known(row.statusClasses, STATUS_CLASSES, "状态码筛选"),
    sources: known(row.sources, TRAFFIC_SOURCES, "来源筛选"),
    searchTerm: text(row.searchTerm ?? "", "搜索词"),
    searchRegex: bool(row.searchRegex ?? false, "正则筛选"),
    searchCaseSensitive: bool(row.searchCaseSensitive ?? false, "大小写筛选"),
    searchNegative: bool(row.searchNegative ?? false, "反向筛选"),
    showOnlyExtensionsEnabled: bool(row.showOnlyExtensionsEnabled, "仅显示扩展名"),
    showOnlyExtensionsText: extensionList(text(row.showOnlyExtensionsText, "显示扩展名")).join(","),
    hideExtensionsEnabled: bool(row.hideExtensionsEnabled, "隐藏扩展名"),
    hideExtensionsText: extensionList(text(row.hideExtensionsText, "隐藏扩展名")).join(","),
  };
}

/** Convert persisted settings into a traffic-list request filter. */
export function filterInput(settings: FilterSettings): TrafficFilter {
  const term = settings.searchTerm.trim();
  return {
    onlyInScope: settings.onlyInScope,
    hideWithoutResponse: settings.hideWithoutResponse,
    onlyParameterized: settings.onlyParameterized,
    mimeCategories: settings.mimeCategories,
    statusClasses: settings.statusClasses,
    sources: settings.sources,
    search: term ? {
      term,
      regex: settings.searchRegex,
      caseSensitive: settings.searchCaseSensitive,
      negative: settings.searchNegative,
    } : null,
    extensions: {
      showOnlyEnabled: settings.showOnlyExtensionsEnabled,
      showOnly: extensionList(settings.showOnlyExtensionsText),
      hideEnabled: settings.hideExtensionsEnabled,
      hide: extensionList(settings.hideExtensionsText),
    },
  };
}

/** Compare ordered filter arrays without coercion. */
function sameValues<T>(left: readonly T[], right: readonly T[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

const FILTER_SCALAR_KEYS = [
  "version", "onlyInScope", "hideWithoutResponse", "onlyParameterized", "searchTerm",
  "searchRegex", "searchCaseSensitive", "searchNegative", "showOnlyExtensionsEnabled",
  "showOnlyExtensionsText", "hideExtensionsEnabled", "hideExtensionsText",
] as const satisfies readonly (keyof FilterSettings)[];

/** Compare the complete persisted filter-settings contract. */
export function sameFilterSettings(left: FilterSettings, right: FilterSettings): boolean {
  return sameValues(left.mimeCategories, right.mimeCategories)
    && sameValues(left.statusClasses, right.statusClasses)
    && sameValues(left.sources, right.sources)
    && FILTER_SCALAR_KEYS.every((key) => left[key] === right[key]);
}

/** Determine whether an enum filter contains every accepted value. */
function isComplete<T extends string>(value: readonly T[], all: readonly T[]): boolean {
  return value.length === all.length && all.every((item) => value.includes(item));
}

/** Count filter groups that currently narrow or transform the traffic list. */
export function activeFilterCount(value: FilterSettings): number {
  return [
    value.onlyInScope,
    value.hideWithoutResponse,
    value.onlyParameterized,
    !isComplete(value.mimeCategories, MIME_CATEGORIES),
    !isComplete(value.statusClasses, STATUS_CLASSES),
    !isComplete(value.sources, TRAFFIC_SOURCES),
    Boolean(value.searchTerm.trim()),
    value.showOnlyExtensionsEnabled,
    value.hideExtensionsEnabled,
  ].filter(Boolean).length;
}
