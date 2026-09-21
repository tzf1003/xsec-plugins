import type { ComponentChildren, JSX } from "preact";
import { Icon, type IconName } from "./icon";

/** Render the button component. */
export function Button({ icon, children, tone = "default", className = "", ...props }: {
  icon?: IconName;
  children?: ComponentChildren;
  tone?: "default" | "primary" | "danger" | "ghost";
  className?: string;
} & Omit<JSX.ButtonHTMLAttributes<HTMLButtonElement>, "icon">) {
  return <button type="button" className={`x-button is-${tone} ${className}`} {...props}>
    {icon ? <Icon name={icon} /> : null}{children}
  </button>;
}

/** Render the icon button component. */
export function IconButton({ label, icon, ...props }: {
  label: string;
  icon: IconName;
} & Omit<JSX.ButtonHTMLAttributes<HTMLButtonElement>, "label" | "title" | "aria-label">) {
  return <button {...props} type="button" className="x-button is-ghost x-icon-button" aria-label={label} title={label}><Icon name={icon} /></button>;
}

/** Render the spinner component. */
export function Spinner({ label }: { label: string }) {
  return <div className="x-loading" role="status"><span className="x-spinner" />{label}</div>;
}

/** Render the empty state component. */
export function EmptyState({ children }: { children: ComponentChildren }) {
  return <div className="x-empty"><span className="x-empty-mark">HTTP</span><p>{children}</p></div>;
}

/** Render the notice component. */
export function Notice({ tone = "error", children, onClose, action }: {
  tone?: "error" | "warning" | "success";
  children: ComponentChildren;
  onClose?: () => void;
  action?: ComponentChildren;
}) {
  return <div className={`x-notice is-${tone}`} role={tone === "error" ? "alert" : "status"}>
    <span>{children}</span><div>{action}{onClose ? <IconButton label="关闭" icon="close" onClick={onClose} /> : null}</div>
  </div>;
}

/** Render the field component. */
export function Field({ label, children, className = "" }: {
  label: string;
  children: ComponentChildren;
  className?: string;
}) {
  return <label className={`x-field ${className}`}><span>{label}</span>{children}</label>;
}

/** Render the check component. */
export function Check({ checked, children, onChange, disabled = false }: {
  checked: boolean;
  children: ComponentChildren;
  onChange: (checked: boolean) => void;
  disabled?: boolean;
}) {
  return <label className="x-check"><input type="checkbox" checked={checked} disabled={disabled} onChange={(event) => onChange(event.currentTarget.checked)} /><span>{children}</span></label>;
}

/** Render the dialog component. */
export function Dialog({ title, children, footer, onClose, width = 820 }: {
  title: string;
  children: ComponentChildren;
  footer: ComponentChildren;
  onClose: () => void;
  width?: number;
}) {
  return <div className="x-dialog-backdrop" role="presentation" onMouseDown={(event) => {
    if (event.currentTarget === event.target) onClose();
  }}>
    <section className="x-dialog" role="dialog" aria-modal="true" aria-label={title} style={{ "--dialog-width": `${width}px` }}>
      <header><h2>{title}</h2><IconButton label="关闭" icon="close" onClick={onClose} /></header>
      <div className="x-dialog-body">{children}</div><footer>{footer}</footer>
    </section>
  </div>;
}
