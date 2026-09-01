import { useEffect, type ButtonHTMLAttributes, type ReactNode } from "react";
import { collectionBucket, statusLabel } from "./utils";

export function Button({ className = "", children, ...props }: ButtonHTMLAttributes<HTMLButtonElement>) {
  return <button className={`ad-button ${className}`.trim()} type="button" {...props}>{children}</button>;
}

export function StatusBadge({ status }: { status: string }) {
  const bucket = collectionBucket(status);
  return <span className={`ad-status ${bucket}`}>{statusLabel(status)}</span>;
}

export function EmptyState({ children }: { children: ReactNode }) {
  return <div className="ad-empty">{children}</div>;
}

export function ErrorState({ error, onRetry }: { error: string; onRetry: () => void }) {
  return (
    <div className="ad-error">
      <p>{error}</p>
      <Button className="compact" onClick={onRetry}>重新读取</Button>
    </div>
  );
}

export function Notice({ children, action }: { children: ReactNode; action?: ReactNode }) {
  return <div className="ad-notice"><span>{children}</span>{action}</div>;
}

export function Modal({
  title,
  children,
  onClose,
  footer,
}: {
  title: string;
  children: ReactNode;
  onClose: () => void;
  footer: ReactNode;
}) {
  useEffect(() => {
    const close = (event: KeyboardEvent) => { if (event.key === "Escape") onClose(); };
    window.addEventListener("keydown", close);
    return () => window.removeEventListener("keydown", close);
  }, [onClose]);
  return (
    <div className="ad-modal-backdrop" role="presentation" onMouseDown={onClose}>
      <section className="ad-modal" role="dialog" aria-modal="true" aria-label={title} onMouseDown={(event) => event.stopPropagation()}>
        <header>{title}</header>
        <main>{children}</main>
        <footer>{footer}</footer>
      </section>
    </div>
  );
}

export function ConfirmModal({
  title,
  detail,
  confirmLabel,
  danger = false,
  busy = false,
  onClose,
  onConfirm,
}: {
  title: string;
  detail: string;
  confirmLabel: string;
  danger?: boolean;
  busy?: boolean;
  onClose: () => void;
  onConfirm: () => void;
}) {
  const close = () => { if (!busy) onClose(); };
  return <Modal title={title} onClose={close} footer={<><Button disabled={busy} onClick={close}>取消</Button><Button className={danger ? "danger" : "primary"} disabled={busy} onClick={onConfirm}>{confirmLabel}</Button></>}><p className="ad-confirm-detail">{detail}</p></Modal>;
}

export function Section({ title, actions, children }: { title: string; actions?: ReactNode; children: ReactNode }) {
  return (
    <section className="ad-section">
      <div className="ad-section-title"><strong>{title}</strong><span>{actions}</span></div>
      <div className="ad-section-body">{children}</div>
    </section>
  );
}
