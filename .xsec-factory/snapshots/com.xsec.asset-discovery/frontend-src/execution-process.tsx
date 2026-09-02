import { useLayoutEffect, useMemo, useRef, useState, type UIEvent } from "react";
import type { ExecutionSnapshot, SessionMessage, ToolCall } from "./types";
import { printableToolValue, toolLabel } from "./utils";
import { Button, EmptyState, ErrorState, Notice } from "./ui";

const BOTTOM_TOLERANCE_PX = 28;
const ENTRY_FINGERPRINT_SEPARATOR = "\n--- xsec-entry ---\n";

type StreamEntry =
  | { key: string; sequence: number; kind: "message"; message: SessionMessage }
  | { key: string; sequence: number; kind: "tool"; tool: ToolCall };

type ProcessProps = {
  execution?: ExecutionSnapshot;
  loading: boolean;
  error?: string;
  live: boolean;
  onRefresh: () => void;
};

function entriesFor(snapshot: ExecutionSnapshot | undefined): StreamEntry[] {
  const session = snapshot?.session;
  if (!session) return [];
  const messages = (session.messages ?? [])
    .filter((message) => message.role === "assistant" && Boolean(message.text?.trim() || message.thought?.trim()))
    .map((message, index) => ({ key: `message:${message.message_id}`, sequence: message.sequence ?? index * 2, kind: "message" as const, message }));
  const tools = Object.values(session.active_tool_calls ?? {})
    .map((tool, index) => ({ key: `tool:${tool.tool_call_id}`, sequence: tool.sequence ?? index * 2 + 1, kind: "tool" as const, tool }));
  return [...messages, ...tools].sort((left, right) => left.sequence - right.sequence);
}

function isNearBottom(node: HTMLElement): boolean {
  return node.scrollHeight - node.clientHeight - node.scrollTop <= BOTTOM_TOLERANCE_PX;
}

function displayedMessagePart(value: string | undefined): string | undefined {
  return value?.trim() || undefined;
}

function entryVersion(entry: StreamEntry): string {
  if (entry.kind === "message") {
    return JSON.stringify([displayedMessagePart(entry.message.thought), displayedMessagePart(entry.message.text)]);
  }
  const output = entry.tool.content ?? entry.tool.raw_output;
  return JSON.stringify([
    toolLabel(entry.tool),
    entry.tool.status?.trim() || "进行中",
    entry.tool.raw_input === undefined ? undefined : printableToolValue(entry.tool.raw_input),
    output === undefined ? undefined : printableToolValue(output),
  ]);
}

function entryFingerprint(entries: StreamEntry[]): string {
  return entries.map((entry) => `${entry.key}\u0000${entryVersion(entry)}`).join(ENTRY_FINGERPRINT_SEPARATOR);
}

function prunePendingKeys(pendingKeys: Set<string>, entries: StreamEntry[]): boolean {
  const currentKeys = new Set(entries.map((entry) => entry.key));
  const count = pendingKeys.size;
  pendingKeys.forEach((key) => {
    if (!currentKeys.has(key)) pendingKeys.delete(key);
  });
  return pendingKeys.size !== count;
}

function ToolDisclosure({ tool }: { tool: ToolCall }) {
  const output = tool.content ?? tool.raw_output;
  const status = tool.status?.trim() || "进行中";
  return <details className="ad-tool"><summary>{toolLabel(tool)} · {status}</summary>
    {tool.raw_input !== undefined ? <ToolValue label="输入" value={tool.raw_input} /> : null}
    {output !== undefined ? <ToolValue label="结果" value={output} /> : null}
  </details>;
}

function ToolValue({ label, value }: { label: string; value: unknown }) {
  return <div className="ad-tool-value"><strong>{label}</strong><pre className="ad-code">{printableToolValue(value)}</pre></div>;
}

function MessageEntry({ message }: { message: SessionMessage }) {
  return <article className="ad-message"><header>Agent 执行过程</header>
    {message.thought?.trim() ? <pre>{message.thought.trim()}</pre> : null}
    {message.text?.trim() ? <pre>{message.text.trim()}</pre> : null}
  </article>;
}

function useFollowLatest(entries: StreamEntry[], fingerprint: string, sessionId: string | undefined, live: boolean) {
  const streamRef = useRef<HTMLDivElement>(null);
  const followingRef = useRef(true);
  const priorFingerprintRef = useRef<string>();
  const priorVersionsRef = useRef<Map<string, string>>(new Map());
  const pendingKeysRef = useRef(new Set<string>());
  const [pendingCount, setPendingCount] = useState(0);

  useLayoutEffect(() => {
    followingRef.current = true;
    priorFingerprintRef.current = undefined;
    priorVersionsRef.current = new Map();
    pendingKeysRef.current = new Set();
    setPendingCount(0);
  }, [sessionId]);

  useLayoutEffect(() => {
    const changed = priorFingerprintRef.current !== fingerprint;
    const initial = priorFingerprintRef.current === undefined;
    const updatedKeys = entries
      .filter((entry) => priorVersionsRef.current.get(entry.key) !== entryVersion(entry))
      .map((entry) => entry.key);
    priorFingerprintRef.current = fingerprint;
    priorVersionsRef.current = new Map(entries.map((entry) => [entry.key, entryVersion(entry)]));
    const pruned = prunePendingKeys(pendingKeysRef.current, entries);
    if (!changed) {
      if (pruned) setPendingCount(pendingKeysRef.current.size);
      return;
    }
    if (!entries.length) {
      if (pruned) setPendingCount(0);
      return;
    }
    const stream = streamRef.current;
    if (live && followingRef.current && stream) stream.scrollTop = stream.scrollHeight;
    const shouldCountUpdates = live && !initial && !followingRef.current;
    if (shouldCountUpdates && updatedKeys.length) {
      updatedKeys.forEach((key) => pendingKeysRef.current.add(key));
    }
    if (pruned || (shouldCountUpdates && updatedKeys.length)) {
      setPendingCount(pendingKeysRef.current.size);
    }
  }, [entries, fingerprint, live]);

  const jumpToLatest = () => {
    if (streamRef.current) streamRef.current.scrollTop = streamRef.current.scrollHeight;
    followingRef.current = true;
    pendingKeysRef.current = new Set();
    setPendingCount(0);
  };
  const onScroll = (event: UIEvent<HTMLDivElement>) => {
    followingRef.current = isNearBottom(event.currentTarget);
  };
  return { streamRef, pendingCount, jumpToLatest, onScroll };
}

function ProcessStream({ entries, live, process }: {
  entries: StreamEntry[];
  live: boolean;
  process: ReturnType<typeof useFollowLatest>;
}) {
  return <>
    <div ref={process.streamRef} className="ad-process" aria-live="polite" aria-label="资产发现实时执行过程" onScroll={process.onScroll}>
      {entries.map((entry) => entry.kind === "tool"
        ? <ToolDisclosure key={entry.key} tool={entry.tool} />
        : <MessageEntry key={entry.key} message={entry.message} />)}
      {live ? <p className="ad-process-live">实时更新中</p> : null}
    </div>
    {process.pendingCount ? <Button className="compact ad-new-records" onClick={process.jumpToLatest}>有 {process.pendingCount} 条新执行记录，查看最新</Button> : null}
  </>;
}

export function ExecutionProcess({ execution, loading, error, live, onRefresh }: ProcessProps) {
  const entries = useMemo(() => entriesFor(execution), [execution]);
  const fingerprint = useMemo(() => entryFingerprint(entries), [entries]);
  const sessionId = execution?.session?.session_id ?? execution?.run.session_id ?? undefined;
  const process = useFollowLatest(entries, fingerprint, sessionId, live);

  if (error && !entries.length) return <ErrorState error={error} onRetry={onRefresh} />;
  if (loading && !execution) return <EmptyState>正在读取执行记录…</EmptyState>;
  if (!execution?.session) return <EmptyState>{live ? "正在创建执行会话…" : "该任务未生成可用的执行会话。"}</EmptyState>;
  if (!entries.length) return <EmptyState>{live ? "会话已连接，等待执行过程…" : "暂无可用执行记录"}</EmptyState>;
  return <div className="ad-process-wrap">
    {error ? <ErrorState error={error} onRetry={onRefresh} /> : null}
    {execution?.truncated ? <Notice>执行记录已按隔离通道大小截断；刷新或读取日志可查看后续内容。</Notice> : null}
    <ProcessStream entries={entries} live={live} process={process} />
  </div>;
}
