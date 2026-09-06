import { useCallback, useRef, useState } from "preact/hooks";
import type { ReplayAttempt, TrafficDetail } from "../types";
import { replayScheme } from "./target";

export type ReplayConfirmation = {
  sourceFlowId: string;
  sourceHost: string;
  sourcePort: number | null | undefined;
  sourceScheme: string;
  rawRequest: string;
  scheme: "http" | "https";
  targetHost: string;
  targetPort: number;
};

/** Resolve the selected replay attempt after history replacement. */
export function replayHistorySelection(
  items: ReplayAttempt[], currentId: string | null, selectLatest: boolean,
): ReplayAttempt | undefined {
  if (selectLatest) return items.at(-1);
  return items.find((item) => item.id === currentId) ?? items.at(-1);
}

/** Own editable replay, history, confirmation, result, and pane-layout state. */
export function useReplayState() {
  const [source, setSource] = useState<TrafficDetail>();
  const [sourceRevision, setSourceRevision] = useState(0);
  const [rawRequest, setRawRequest] = useState("");
  const [scheme, setScheme] = useState<"http" | "https">("https");
  const [targetHost, setTargetHost] = useState("");
  const [targetPort, setTargetPort] = useState(443);
  const [attempts, setAttempts] = useState<ReplayAttempt[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [result, setResult] = useState<TrafficDetail>();
  const [resultRevision, setResultRevision] = useState(0);
  const [loading, setLoading] = useState(true);
  const [resultLoading, setResultLoading] = useState(false);
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string>();
  const [historyError, setHistoryError] = useState<string>();
  const [resultError, setResultError] = useState<string>();
  const [notice, setNotice] = useState<string>();
  const [connectionOpen, setConnectionOpen] = useState(false);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [panePercent, setPanePercent] = useState(50);
  const [stacked, setStacked] = useState(false);
  const exchangeRef = useRef<HTMLDivElement>(null);
  const drafts = useRef(new Map<string, string>());
  const confirmation = useRef<ReplayConfirmation>();
  const attemptsRef = useRef(attempts); attemptsRef.current = attempts;
  const selectedIdRef = useRef(selectedId); selectedIdRef.current = selectedId;
  const replaceAttempts = useCallback((items: ReplayAttempt[], selectLatest: boolean) => {
    const currentId = selectedIdRef.current;
    const selected = replayHistorySelection(items, currentId, selectLatest);
    attemptsRef.current = items; selectedIdRef.current = selected?.id ?? null;
    setAttempts(items); setSelectedId(selected?.id ?? null);
    if (!selected || (!selectLatest && selected.id === currentId)) return;
    setRawRequest(drafts.current.get(selected.id) ?? selected.request_raw);
    setScheme(replayScheme(selected.scheme)); setTargetHost(selected.target_host);
    setTargetPort(selected.target_port);
  }, []);
  return {
    source, setSource, sourceRevision, setSourceRevision, rawRequest, setRawRequest, scheme, setScheme, targetHost, setTargetHost,
    targetPort, setTargetPort, attempts, setAttempts, selectedId, setSelectedId, result, setResult,
    resultRevision, setResultRevision,
    loading, setLoading, resultLoading, setResultLoading, sending, setSending, error, setError,
    historyError, setHistoryError,
    resultError, setResultError, notice, setNotice, connectionOpen, setConnectionOpen, confirmOpen, setConfirmOpen, panePercent,
    setPanePercent, stacked, setStacked, exchangeRef, drafts, attemptsRef, selectedIdRef,
    confirmation, replaceAttempts,
  };
}

export type ReplayState = ReturnType<typeof useReplayState>;
