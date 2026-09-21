import { Check, Field } from "../ui/primitives";
import { MIME_CATEGORIES, STATUS_CLASSES, TRAFFIC_SOURCES } from "../filter";
import type { FilterSettings, MimeCategory, StatusClass, TrafficSource } from "../types";

const MIME_LABELS: Record<MimeCategory, string> = { html: "HTML", otherText: "其他文本 / JSON", script: "脚本", images: "图片", xml: "XML", css: "CSS 样式表", otherBinary: "其他二进制", unknown: "未知类型" };
const STATUS_LABELS: Record<StatusClass, string> = { informational: "1xx（信息响应）", success: "2xx（成功）", redirection: "3xx（重定向）", clientError: "4xx（客户端错误）", serverError: "5xx（服务端错误）" };
const SOURCE_LABELS: Record<TrafficSource, string> = { proxy: "代理捕获", replay: "重放结果" };

/** Add or remove one enum value while preserving list order. */
function toggle<T extends string>(items: T[], value: T, checked: boolean): T[] {
  return checked ? [...new Set([...items, value])] : items.filter((item) => item !== value);
}

/** Render the filter fields component. */
export function FilterFields({ value, onChange, includeSearch = true, className = "filter-grid" }: {
  value: FilterSettings;
  onChange: (value: FilterSettings) => void;
  includeSearch?: boolean;
  className?: string;
}) {
  const set = (patch: Partial<FilterSettings>) => onChange({ ...value, ...patch });
  return <div className={className}>
    <fieldset className="filter-section"><legend>按请求类型筛选</legend>
      <Check checked={value.onlyInScope} onChange={(checked) => set({ onlyInScope: checked })}>仅显示范围内流量</Check>
      <Check checked={value.hideWithoutResponse} onChange={(checked) => set({ hideWithoutResponse: checked })}>隐藏无响应流量</Check>
      <Check checked={value.onlyParameterized} onChange={(checked) => set({ onlyParameterized: checked })}>仅显示带参数请求</Check>
      <span>流量来源</span><div className="filter-options">{TRAFFIC_SOURCES.map((item) => <Check checked={value.sources.includes(item)} onChange={(checked) => set({ sources: toggle(value.sources, item, checked) })}>{SOURCE_LABELS[item]}</Check>)}</div>
    </fieldset>
    <fieldset className="filter-section"><legend>按响应类型筛选</legend><div className="filter-options">
      {MIME_CATEGORIES.map((item) => <Check checked={value.mimeCategories.includes(item)} onChange={(checked) => set({ mimeCategories: toggle(value.mimeCategories, item, checked) })}>{MIME_LABELS[item]}</Check>)}
    </div></fieldset>
    <fieldset className="filter-section"><legend>按状态码筛选</legend><div className="filter-options">
      {STATUS_CLASSES.map((item) => <Check checked={value.statusClasses.includes(item)} onChange={(checked) => set({ statusClasses: toggle(value.statusClasses, item, checked) })}>{STATUS_LABELS[item]}</Check>)}
    </div></fieldset>
    {includeSearch ? <fieldset className="filter-section"><legend>按搜索词筛选</legend>
      <input className="x-input" value={value.searchTerm} placeholder="方法、主机、URL、状态码或 MIME" onInput={(event) => set({ searchTerm: event.currentTarget.value })} />
      <div className="filter-search-options"><Check checked={value.searchRegex} onChange={(checked) => set({ searchRegex: checked })}>正则表达式</Check><Check checked={value.searchCaseSensitive} onChange={(checked) => set({ searchCaseSensitive: checked })}>区分大小写</Check><Check checked={value.searchNegative} onChange={(checked) => set({ searchNegative: checked })}>反向匹配</Check></div>
    </fieldset> : null}
    <fieldset className="filter-section filter-span"><legend>按文件扩展名筛选</legend>
      <div className="filter-extension-row"><Check checked={value.showOnlyExtensionsEnabled} onChange={(checked) => set({ showOnlyExtensionsEnabled: checked })}>仅显示</Check><input className="x-input" value={value.showOnlyExtensionsText} onInput={(event) => set({ showOnlyExtensionsText: event.currentTarget.value })} /></div>
      <div className="filter-extension-row"><Check checked={value.hideExtensionsEnabled} onChange={(checked) => set({ hideExtensionsEnabled: checked })}>隐藏</Check><input className="x-input" value={value.hideExtensionsText} onInput={(event) => set({ hideExtensionsText: event.currentTarget.value })} /></div>
      <small>支持中英文逗号、分号或空格；匹配时忽略大小写和扩展名前的点。</small>
    </fieldset>
  </div>;
}
