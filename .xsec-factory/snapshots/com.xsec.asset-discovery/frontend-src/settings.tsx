import { useCallback, useEffect, useRef, useState } from "react";
import type { AssetDiscoveryApi } from "./host";
import type { CollectorProvider, CollectorSettings } from "./types";
import { Button, ConfirmModal } from "./ui";

type CredentialKind = "hunter" | "fofa" | "tianyan";
type Credentials = Record<CredentialKind, string>;
type SettingsDraft = {
  provider: CollectorProvider;
  hunterApiBaseUrl: string;
  fofaApiBaseUrl: string;
  hunterSkillPath: string;
  fofaSkillPath: string;
};

function draftFrom(settings: CollectorSettings): SettingsDraft {
  return {
    provider: settings.provider === "fofa" ? "fofa" : "hunter",
    hunterApiBaseUrl: settings.hunterApiBaseUrl ?? "",
    fofaApiBaseUrl: settings.fofaApiBaseUrl ?? "",
    hunterSkillPath: settings.hunterSkillPath ?? "",
    fofaSkillPath: settings.fofaSkillPath ?? "",
  };
}

function configured(value: boolean): string {
  return value ? "已配置（保存于系统密钥库）" : "未配置";
}

function normalizedDraft(draft: SettingsDraft): SettingsDraft {
  return {
    provider: draft.provider,
    hunterApiBaseUrl: draft.hunterApiBaseUrl.trim(),
    fofaApiBaseUrl: draft.fofaApiBaseUrl.trim(),
    hunterSkillPath: draft.hunterSkillPath.trim(),
    fofaSkillPath: draft.fofaSkillPath.trim(),
  };
}

function useSettingsReader(api: AssetDiscoveryApi) {
  const [settings, setSettings] = useState<CollectorSettings>();
  const [draft, setDraft] = useState<SettingsDraft>();
  const [isSettingsReady, setSettingsReady] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>();
  const [notice, setNotice] = useState<string>();
  const requestGeneration = useRef(0);
  const load = useCallback(async (replaceDraft = true) => {
    const generation = ++requestGeneration.current;
    let settingsReady = false;
    setLoading(true);
    setSettingsReady(false);
    setError(undefined);
    try {
      const next = await api.settings();
      if (generation !== requestGeneration.current) return false;
      setSettings(next);
      setDraft((current) => replaceDraft || !current ? draftFrom(next) : current);
      settingsReady = true;
    } catch (reason) {
      if (generation === requestGeneration.current) setError(`读取资产发现设置失败：${String(reason)}`);
    } finally {
      if (generation === requestGeneration.current) {
        setSettingsReady(settingsReady);
        setLoading(false);
      }
    }
    if (!settingsReady) return false;
    return true;
  }, [api]);
  useEffect(() => { void load(); }, [load]);
  const update = <K extends keyof SettingsDraft>(key: K, value: SettingsDraft[K]) => {
    setDraft((current) => current ? { ...current, [key]: value } : current);
  };
  return { settings, draft, isSettingsReady, loading, error, notice, load, update, setSettings, setDraft, setError, setNotice };
}

function useSettingsSave({ api, draft, settingsReady, setSettings, setDraft, setError, setNotice }: {
  api: AssetDiscoveryApi;
  draft?: SettingsDraft;
  settingsReady: boolean;
  setSettings: (value: CollectorSettings) => void;
  setDraft: (value: SettingsDraft) => void;
  setError: (value: string | undefined) => void;
  setNotice: (value: string) => void;
}) {
  const [saving, setSaving] = useState(false);
  const save = async () => {
    if (!settingsReady || !draft) return;
    setSaving(true);
    setError(undefined);
    try {
      const next = await api.saveSettings(normalizedDraft(draft));
      setSettings(next);
      setDraft(draftFrom(next));
      setNotice("设置已保存；新的收集任务将使用这些默认值。");
    } catch (reason) {
      setError(`保存资产发现设置失败：${String(reason)}`);
    } finally {
      setSaving(false);
    }
  };
  return { saving, save };
}

function useCredentials({ api, refresh, setError, setNotice }: {
  api: AssetDiscoveryApi;
  refresh: () => Promise<void>;
  setError: (value: string | undefined) => void;
  setNotice: (value: string) => void;
}) {
  const [credentials, setCredentials] = useState<Credentials>({ hunter: "", fofa: "", tianyan: "" });
  const [saving, setSaving] = useState(false);
  const [clearKind, setClearKind] = useState<CredentialKind>();
  const setCredential = (kind: CredentialKind, value: string) => setCredentials((current) => ({ ...current, [kind]: value }));
  const save = async (kind: CredentialKind) => {
    const value = credentials[kind].trim();
    if (!value) return setError("请输入要保存的密钥。");
    setSaving(true);
    setError(undefined);
    try {
      await api.saveCredential(kind, value);
      setCredentials((current) => ({ ...current, [kind]: "" }));
      await refresh();
      setNotice("密钥已保存到系统密钥库。");
    } catch (reason) {
      setError(`保存密钥失败：${String(reason)}`);
    } finally {
      setSaving(false);
    }
  };
  const clear = async () => {
    if (!clearKind) return;
    setSaving(true);
    setError(undefined);
    try {
      await api.clearCredential(clearKind);
      setClearKind(undefined);
      await refresh();
      setNotice("密钥已清除。");
    } catch (reason) {
      setError(`清除密钥失败：${String(reason)}`);
    } finally {
      setSaving(false);
    }
  };
  return { credentials, saving, clearKind, setCredential, save, clear, setClearKind };
}

function SettingsFields({ draft, saving, onUpdate }: {
  draft: SettingsDraft;
  saving: boolean;
  onUpdate: <K extends keyof SettingsDraft>(key: K, value: SettingsDraft[K]) => void;
}) {
  return <>
    <label className="ad-field">默认收集数据源
      <select className="ad-select" value={draft.provider} disabled={saving} onChange={(event) => onUpdate("provider", event.target.value as CollectorProvider)}>
        <option value="hunter">鹰图 Hunter</option><option value="fofa">FOFA + 天眼查</option>
      </select>
    </label>
    <label className="ad-field">鹰图 API Host<input className="ad-input" value={draft.hunterApiBaseUrl} disabled={saving} onChange={(event) => onUpdate("hunterApiBaseUrl", event.target.value)} /></label>
    <label className="ad-field">FOFA API Host<input className="ad-input" value={draft.fofaApiBaseUrl} disabled={saving} onChange={(event) => onUpdate("fofaApiBaseUrl", event.target.value)} /></label>
    <label className="ad-field">鹰图 Skill 路径（可选）<input className="ad-input" value={draft.hunterSkillPath} disabled={saving} onChange={(event) => onUpdate("hunterSkillPath", event.target.value)} /></label>
    <label className="ad-field">FOFA Skill 路径（可选）<input className="ad-input" value={draft.fofaSkillPath} disabled={saving} onChange={(event) => onUpdate("fofaSkillPath", event.target.value)} /></label>
  </>;
}

function Credential({ name, kind, value, isConfigured, saving, onChange, onSave, onClear }: {
  name: string;
  kind: CredentialKind;
  value: string;
  isConfigured: boolean;
  saving: boolean;
  onChange: (value: string) => void;
  onSave: (kind: CredentialKind) => void;
  onClear: (kind: CredentialKind) => void;
}) {
  return <label className="ad-field">{name}（{configured(isConfigured)}）
    <span className="ad-credential"><input className="ad-input" type="password" autoComplete="new-password" value={value} disabled={saving} onChange={(event) => onChange(event.target.value)} /><Button className="compact" disabled={saving} onClick={() => onSave(kind)}>保存</Button><Button className="compact danger" disabled={saving} onClick={() => onClear(kind)}>清除</Button></span>
  </label>;
}

function CredentialFields({ settings, credentials, saving, onChange, onSave, onClear }: {
  settings: CollectorSettings;
  credentials: Credentials;
  saving: boolean;
  onChange: (kind: CredentialKind, value: string) => void;
  onSave: (kind: CredentialKind) => void;
  onClear: (kind: CredentialKind) => void;
}) {
  return <>
    <Credential name="Hunter API 密钥" kind="hunter" value={credentials.hunter} isConfigured={settings.hunterApiKeyConfigured} saving={saving} onChange={(value) => onChange("hunter", value)} onSave={onSave} onClear={onClear} />
    <Credential name="FOFA API 密钥" kind="fofa" value={credentials.fofa} isConfigured={settings.fofaApiKeyConfigured} saving={saving} onChange={(value) => onChange("fofa", value)} onSave={onSave} onClear={onClear} />
    <Credential name="天眼查 API 密钥" kind="tianyan" value={credentials.tianyan} isConfigured={settings.tianyanApiKeyConfigured} saving={saving} onChange={(value) => onChange("tianyan", value)} onSave={onSave} onClear={onClear} />
  </>;
}

export function SettingsPage({ api }: { api: AssetDiscoveryApi }) {
  const reader = useSettingsReader(api);
  const retryButtonRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    const retryButton = retryButtonRef.current;
    if (!retryButton) return;
    retryButton.onclick = () => { void reader.load(); };
    if (reader.loading) retryButton.disabled = true;
    else retryButton.disabled = false;
    return () => { retryButton.onclick = null; };
  }, [reader.error, reader.loading, reader.load]);
  const settingsSave = useSettingsSave({ api, draft: reader.draft, settingsReady: reader.isSettingsReady, setSettings: reader.setSettings, setDraft: reader.setDraft, setError: reader.setError, setNotice: reader.setNotice });
  const credentials = useCredentials({ api, refresh: async () => { await reader.load(false); }, setError: reader.setError, setNotice: reader.setNotice });
  const saving = settingsSave.saving || credentials.saving;
  if (reader.loading && !reader.settings) return <div className="ad-app ad-settings"><p className="ad-muted">正在读取资产发现设置…</p></div>;
  if (reader.error && !reader.settings) return <div className="ad-app ad-settings"><div className="ad-error"><p>{reader.error}</p><button ref={retryButtonRef} className="ad-button compact" type="button" disabled={reader.loading}>重新读取</button></div></div>;
  if (!reader.settings || !reader.draft) throw new Error("资产发现设置状态不完整");
  return <main className="ad-app ad-settings">
    <p className="ad-eyebrow">ASSET DISCOVERY SETTINGS</p><h1 className="ad-title">资产发现</h1>
    <p className="ad-description">配置默认数据源、API Host 和 Skill 路径。密钥仅由宿主系统密钥库存储。</p>
    <div className="ad-runs">
      <SettingsFields draft={reader.draft} saving={saving} onUpdate={reader.update} />
      <CredentialFields settings={reader.settings} credentials={credentials.credentials} saving={saving} onChange={credentials.setCredential} onSave={(kind) => void credentials.save(kind)} onClear={credentials.setClearKind} />
      <p className="ad-muted">当前 Skill 解析：Hunter {reader.settings.resolvedHunterSkillPath || "—"}；FOFA {reader.settings.resolvedFofaSkillPath || "—"}</p>
      {reader.error ? <p className="ad-field-error">{reader.error}</p> : null}{reader.notice ? <p className="ad-muted">{reader.notice}</p> : null}
      <div className="ad-form-actions"><Button className="primary" disabled={saving || !reader.isSettingsReady} onClick={() => void settingsSave.save()}>保存设置</Button><Button disabled={saving || reader.loading} onClick={() => void reader.load()}>重新读取设置</Button></div>
    </div>
    {credentials.clearKind ? <ConfirmModal title="清除 API 密钥" detail="清除后新的收集任务将不能使用该密钥。" confirmLabel="清除" danger busy={saving} onClose={() => credentials.setClearKind(undefined)} onConfirm={() => void credentials.clear()} /> : null}
  </main>;
}
