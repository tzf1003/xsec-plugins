import { useEffect, useState } from "preact/hooks";
import { importCa, loadCaStatus, rotateCa } from "../api/settings";
import type { CaStatus, PluginHost } from "../types";
import { Button, Dialog, Notice, Spinner } from "../ui/primitives";

type CaModel = ReturnType<typeof useCaModel>;

/** Load CA status and expose import or rotation actions with visible failures. */
function useCaModel(host: PluginHost) {
  const [status, setStatus] = useState<CaStatus>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [confirmRotate, setConfirmRotate] = useState(false);
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    let active = true;
    setBusy(true);
    setError(undefined);
    void loadCaStatus(host).then((value) => { if (active) setStatus(value); })
      .catch((reason) => { if (active) setError(`读取 MITM CA 状态失败：${String(reason)}`); })
      .finally(() => { if (active) setBusy(false); });
    return () => { active = false; };
  }, [host, revision]);
  const run = async (action: () => Promise<CaStatus>, name: string) => {
    setBusy(true);
    setError(undefined);
    try { setStatus(await action()); }
    catch (reason) { setError(`${name}失败：${String(reason)}`); }
    finally { setBusy(false); }
  };
  return { status, busy, error, confirmRotate, setConfirmRotate, setRevision, run };
}

/** Render the CA loading component. */
function CaLoading({ model }: { model: CaModel }) {
  if (!model.busy) return null;
  if (model.status) return null;
  return <Spinner label="正在读取证书状态…" />;
}

/** Render the CA error component. */
function CaError({ model }: { model: CaModel }) {
  if (!model.error) return null;
  return <Notice action={<Button onClick={() => model.setRevision((value) => value + 1)}>检测状态</Button>}>{model.error}</Notice>;
}

/** Render the CA status details component. */
function CaStatusDetails({ host, model }: { host: PluginHost; model: CaModel }) {
  if (!model.status) return null;
  const status = model.status;
  const caState = status.ca_exists ? "已生成" : "未生成";
  const trustState = status.trust_imported ? "已正常导入" : "未正常导入";
  const actionsDisabled = [model.busy, status.trust_supported === false].some(Boolean);
  return <><dl className="ca-details"><dt>CA 文件</dt><dd>{caState} · {status.ca_cert_path || "—"}</dd><dt>{status.trust_store_kind || "系统证书存储"}</dt><dd>{trustState} · {status.trust_detail || "—"}</dd><dt>SHA-256</dt><dd><code>{status.ca_sha256 || "—"}</code></dd></dl>
    <div className="settings-actions"><Button disabled={actionsDisabled} onClick={() => void model.run(() => importCa(host), "导入 MITM CA")}>导入到系统证书存储</Button><Button tone="danger" disabled={actionsDisabled} onClick={() => model.setConfirmRotate(true)}>重新生成并导入</Button><Button disabled={model.busy} icon="refresh" onClick={() => model.setRevision((value) => value + 1)}>检测状态</Button></div></>;
}

/** Render the rotate confirmation component. */
function RotateConfirmation({ host, model }: { host: PluginHost; model: CaModel }) {
  if (!model.confirmRotate) return null;
  const close = () => model.setConfirmRotate(false);
  const confirm = () => { close(); void model.run(() => rotateCa(host), "重新生成 MITM CA"); };
  return <Dialog title="重新生成 MITM CA？" width={480} onClose={close} footer={<><Button onClick={close}>取消</Button><Button tone="danger" onClick={confirm}>重新生成并导入</Button></>}><p>已有浏览器会话仍使用旧证书。重新生成后请新建浏览器会话。</p></Dialog>;
}

/** Render the CA section component. */
export function CaSection({ host }: { host: PluginHost }) {
  const model = useCaModel(host);
  return <section className="settings-section"><header><div><h2>MITM CA 证书</h2><p>管理浏览器会话代理使用的根证书。</p></div></header>
    <CaLoading model={model} />
    <CaError model={model} />
    <CaStatusDetails host={host} model={model} />
    <RotateConfirmation host={host} model={model} />
  </section>;
}
