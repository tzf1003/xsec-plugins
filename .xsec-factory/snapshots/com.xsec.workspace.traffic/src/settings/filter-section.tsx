import { useEffect, useRef, useState } from "preact/hooks";
import { loadSettings, saveSettings } from "../api/settings";
import { sameFilterSettings } from "../filter";
import type { FilterSettings, PluginHost } from "../types";
import { Button, Notice, Spinner } from "../ui/primitives";
import { FilterFields } from "../traffic/filter-fields";

/** Render the default filter section component. */
export function DefaultFilterSection({ host }: { host: PluginHost }) {
  const [filter, setFilter] = useState<FilterSettings>();
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string>();
  const [saved, setSaved] = useState(false);
  const [revision, setRevision] = useState(0);
  const filterRef = useRef(filter); filterRef.current = filter;
  const editRevision = useRef(0);
  useEffect(() => {
    const startedAtEdit = editRevision.current;
    let active = true; setLoading(true); setError(undefined); setSaved(false);
    void loadSettings(host).then((value) => {
      if (active && editRevision.current === startedAtEdit) {
        filterRef.current = value; setFilter(value);
      }
    })
      .catch((reason) => { if (active) setError(`读取默认筛选失败：${String(reason)}`); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [host, revision]);
  const save = async () => {
    if (!filter) return;
    const submitted = filter;
    setSaving(true); setError(undefined); setSaved(false);
    try {
      const response = await saveSettings(host, submitted);
      if (filterRef.current && sameFilterSettings(filterRef.current, submitted)) {
        filterRef.current = response; setFilter(response); setSaved(true);
      }
    }
    catch (reason) { setError(`保存默认筛选失败：${String(reason)}`); }
    finally { setSaving(false); }
  };
  return <section className="settings-section"><header><div><h2>默认过滤</h2><p>用于之后新打开的抓包流量工作台。</p></div>{filter ? <Button tone="primary" disabled={saving || loading} onClick={() => void save()}>{saving ? "保存中…" : "保存默认过滤"}</Button> : null}</header>
    {loading ? <Spinner label="正在读取默认过滤…" /> : null}
    {error ? <Notice action={<Button onClick={() => setRevision((value) => value + 1)}>重新读取</Button>}>{error}</Notice> : null}
    {saved ? <Notice tone="success" onClose={() => setSaved(false)}>默认过滤已保存</Notice> : null}
    {filter ? <FilterFields value={filter} onChange={(value) => { editRevision.current += 1; filterRef.current = value; setFilter(value); setSaved(false); }} includeSearch={false} className="settings-filter-grid" /> : null}
  </section>;
}
