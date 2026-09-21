import { useState } from "preact/hooks";
import { defaultFilterSettings, MIME_CATEGORIES, STATUS_CLASSES, TRAFFIC_SOURCES } from "../filter";
import type { FilterSettings } from "../types";
import { Button, Dialog } from "../ui/primitives";
import { FilterFields } from "./filter-fields";

/** Select every accepted enum category in the filter draft. */
function allVisible(value: FilterSettings): FilterSettings {
  return { ...value, onlyInScope: false, hideWithoutResponse: false, onlyParameterized: false, mimeCategories: [...MIME_CATEGORIES], statusClasses: [...STATUS_CLASSES], sources: [...TRAFFIC_SOURCES], searchTerm: "", searchRegex: false, searchCaseSensitive: false, searchNegative: false, showOnlyExtensionsEnabled: false, hideExtensionsEnabled: false };
}

/** Clear every enum category in the filter draft. */
function allHidden(value: FilterSettings): FilterSettings {
  return { ...value, onlyInScope: false, hideWithoutResponse: true, onlyParameterized: false, mimeCategories: [], statusClasses: [], sources: [], searchTerm: "", searchRegex: false, searchCaseSensitive: false, searchNegative: false, showOnlyExtensionsEnabled: false, hideExtensionsEnabled: false };
}

/** Render the filter dialog component. */
export function FilterDialog({ value, defaults, onClose, onApply }: {
  value: FilterSettings;
  defaults: FilterSettings;
  onClose: () => void;
  onApply: (value: FilterSettings, close: boolean) => void;
}) {
  const [draft, setDraft] = useState(value);
  return <Dialog title="HTTP 历史筛选" onClose={onClose} footer={<div className="filter-footer-groups">
    <div><Button onClick={() => setDraft(allVisible(draft))}>全部显示</Button><Button onClick={() => setDraft(allHidden(draft))}>全部隐藏</Button><Button onClick={() => setDraft(defaults ?? defaultFilterSettings())}>恢复默认</Button><Button onClick={() => setDraft(value)}>撤销更改</Button></div>
    <div><Button onClick={onClose}>取消</Button><Button onClick={() => onApply(draft, false)}>应用</Button><Button tone="primary" onClick={() => onApply(draft, true)}>应用并关闭</Button></div>
  </div>}>
    <p className="filter-intro">分组间按“且”、组内按“或”匹配。筛选仅影响列表显示，不会丢弃原始流量。</p>
    <FilterFields value={draft} onChange={setDraft} />
  </Dialog>;
}
