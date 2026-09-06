import { useState } from "preact/hooks";
import { headerPairs, prettyBody } from "../proxy";
import type { ComponentChildren } from "preact";
import type { FlowSection } from "../types";

type Mode = "raw" | "headers" | "body" | "pretty";
const MODES: { value: Mode; label: string }[] = [
  { value: "raw", label: "Raw" },
  { value: "headers", label: "Headers" },
  { value: "body", label: "Body" },
  { value: "pretty", label: "Pretty" },
];

/** Render the message pane component. */
export function MessagePane({ title, section, raw, meta }: {
  title: string;
  section?: FlowSection;
  raw: string;
  meta?: ComponentChildren;
}) {
  const [mode, setMode] = useState<Mode>("raw");
  const headers = headerPairs(section?.headers);
  const content = mode === "raw" ? raw : mode === "pretty" ? prettyBody(section?.body) : section?.body ?? "";
  const bodyMode = mode === "body" || mode === "pretty";
  return <article className="traffic-message-pane">
    <header><div><strong>{title}</strong>{meta ? <span>{meta}</span> : null}</div><div className="message-modes">
      {MODES.map((item) => <button type="button" className={mode === item.value ? "is-active" : ""} onClick={() => setMode(item.value)}>{item.label}</button>)}
    </div></header>
    {mode === "headers" ? <div className="message-headers">
      {section?.line ? <div className="message-header-row"><strong>起始行</strong><span>{section.line}</span></div> : null}
      {headers.map(([name, value], index) => <div className="message-header-row" key={`${name}-${index}`}><strong>{name}</strong><span>{value}</span></div>)}
      {!section?.line && headers.length === 0 ? <span>没有可显示的 Header</span> : null}
    </div> : bodyMode ? <div className="message-body-view">
      {section?.bodyTruncated ? <div className="message-truncation-warning" role="status">正文内容已截断，当前仅显示已捕获的部分。</div> : null}
      <pre className="message-content">{content || "没有可显示的内容"}</pre>
    </div> : <pre className="message-content">{content || "没有可显示的内容"}</pre>}
  </article>;
}
