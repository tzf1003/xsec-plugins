import { useEffect, useRef, useState } from "preact/hooks";
import { deleteRule, loadRules, saveRule, toggleRule } from "../api/settings";
import type { PassiveRule, PluginHost } from "../types";
import { Button, Check, Dialog, Field, Notice, Spinner } from "../ui/primitives";
import { samePassiveRule } from "./rule-state";

const EMPTY_RULE: PassiveRule = { rule_id: "", severity: "medium", pattern: "", enabled: true };

/** Render the rule editor component. */
function RuleEditor({ draft, disabled, onChange, onSave }: {
  draft: PassiveRule; disabled: boolean; onChange: (value: PassiveRule) => void; onSave: () => void;
}) {
  return <div className="rule-form"><Field label="规则 ID"><input value={draft.rule_id} onInput={(event) => onChange({ ...draft, rule_id: event.currentTarget.value })} /></Field><Field label="严重级别"><select value={draft.severity} onChange={(event) => onChange({ ...draft, severity: event.currentTarget.value as PassiveRule["severity"] })}><option value="low">low</option><option value="medium">medium</option><option value="high">high</option><option value="critical">critical</option></select></Field><Field className="rule-pattern-field" label="正则表达式"><input value={draft.pattern} onInput={(event) => onChange({ ...draft, pattern: event.currentTarget.value })} /></Field><Check checked={draft.enabled} onChange={(enabled) => onChange({ ...draft, enabled })}>启用</Check><Button tone="primary" disabled={disabled} onClick={onSave}>保存</Button></div>;
}

/** Render the rule table component. */
function RuleTable({ rules, disabled, onToggle, onEdit, onDelete }: {
  rules: PassiveRule[]; disabled: boolean; onToggle: (rule: PassiveRule, enabled: boolean) => void;
  onEdit: (rule: PassiveRule) => void; onDelete: (id: string) => void;
}) {
  return <div className="rule-table-wrap"><table className="rule-table"><thead><tr><th>启用</th><th>规则 ID</th><th>严重</th><th>正则</th><th>操作</th></tr></thead><tbody>{rules.map((rule) => <tr key={rule.rule_id}><td><Check checked={rule.enabled} disabled={disabled} onChange={(enabled) => onToggle(rule, enabled)}><span className="sr-only">启用 {rule.rule_id}</span></Check></td><td><code>{rule.rule_id}</code></td><td>{rule.severity}</td><td className="rule-pattern" title={rule.pattern}>{rule.pattern}</td><td><Button tone="ghost" onClick={() => onEdit(rule)}>编辑</Button><Button tone="ghost" icon="trash" disabled={disabled} onClick={() => onDelete(rule.rule_id)}>删除</Button></td></tr>)}</tbody></table></div>;
}

/** Reload passive rules and publish failures at the settings boundary. */
async function refreshRules(
  reload: () => Promise<void>,
  setError: (value: string | undefined) => void,
  completed: string,
) {
  try { await reload(); }
  catch (reason) { setError(`${completed}，但刷新列表失败：${String(reason)}`); }
}

/** Build serialized save, toggle, and delete operations for passive rules. */
function ruleMutations(options: {
  host: PluginHost; reload: () => Promise<void>; draftRef: { current: PassiveRule };
  updateDraft: (value: PassiveRule) => void; deleteId?: string;
  setDeleteId: (value: string | undefined) => void; setBusy: (value: boolean) => void;
  setError: (value: string | undefined) => void;
}) {
  const { host, reload, draftRef, updateDraft, deleteId, setDeleteId, setBusy, setError } = options;
  const save = async () => {
    const draftAtSubmit = { ...draftRef.current };
    if (!draftAtSubmit.rule_id.trim() || !draftAtSubmit.pattern.trim()) { setError("请输入规则 ID 和正则表达式"); return; }
    const submitted = { ...draftAtSubmit, rule_id: draftAtSubmit.rule_id.trim() };
    setBusy(true); setError(undefined);
    try {
      await saveRule(host, submitted);
      if (samePassiveRule(draftRef.current, draftAtSubmit)) updateDraft(EMPTY_RULE);
      await refreshRules(reload, setError, "规则已保存");
    } catch (reason) { setError(`保存被动规则失败：${String(reason)}`); }
    finally { setBusy(false); }
  };
  const toggle = async (rule: PassiveRule, enabled: boolean) => {
    setBusy(true); setError(undefined);
    try {
      await toggleRule(host, rule.rule_id, enabled);
      await refreshRules(reload, setError, "规则状态已更新");
    } catch (reason) { setError(`更新被动规则失败：${String(reason)}`); }
    finally { setBusy(false); }
  };
  const remove = async () => {
    if (!deleteId) return; const ruleId = deleteId; setBusy(true); setError(undefined);
    try {
      await deleteRule(host, ruleId); setDeleteId(undefined);
      await refreshRules(reload, setError, "规则已删除");
    } catch (reason) { setError(`删除被动规则失败：${String(reason)}`); }
    finally { setBusy(false); }
  };
  return { save, toggle, remove };
}

/** Render the rules section component. */
export function RulesSection({ host }: { host: PluginHost }) {
  const [rules, setRules] = useState<PassiveRule[]>();
  const [draft, setDraft] = useState<PassiveRule>(EMPTY_RULE);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [deleteId, setDeleteId] = useState<string>();
  const [revision, setRevision] = useState(0);
  const draftRef = useRef(draft); draftRef.current = draft;
  const updateDraft = (value: PassiveRule) => { draftRef.current = value; setDraft(value); };
  useEffect(() => {
    let active = true; setLoading(true); setError(undefined);
    void loadRules(host).then((value) => { if (active) setRules(value); })
      .catch((reason) => { if (active) setError(`读取被动规则失败：${String(reason)}`); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [host, revision]);
  const reload = async () => { setRules(await loadRules(host)); };
  const { save, toggle, remove } = ruleMutations({
    host, reload, draftRef, updateDraft, deleteId, setDeleteId, setBusy, setError,
  });
  const mutationDisabled = busy || loading;
  return <section className="settings-section"><header><div><h2>被动检测规则</h2><p>保存后应用于之后捕获的流量。</p></div></header>
    {error ? <Notice action={<Button onClick={() => { setLoading(true); setRevision((value) => value + 1); }}>重新读取</Button>} onClose={() => setError(undefined)}>{error}</Notice> : null}
    <RuleEditor draft={draft} disabled={mutationDisabled} onChange={updateDraft} onSave={() => void save()} />
    {loading ? <Spinner label="正在读取被动规则…" /> : null}
    {rules ? <RuleTable rules={rules} disabled={mutationDisabled} onToggle={(rule, enabled) => void toggle(rule, enabled)} onEdit={updateDraft} onDelete={setDeleteId} /> : null}
    {deleteId ? <Dialog title="删除被动规则？" width={440} onClose={() => setDeleteId(undefined)} footer={<><Button onClick={() => setDeleteId(undefined)}>取消</Button><Button tone="danger" disabled={mutationDisabled} onClick={() => void remove()}>删除</Button></>}><p>规则 <code>{deleteId}</code> 将从被动检测中移除。</p></Dialog> : null}
  </section>;
}
