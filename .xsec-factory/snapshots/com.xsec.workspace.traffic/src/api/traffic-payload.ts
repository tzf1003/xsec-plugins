import { loggedAction } from "../logging";
import type { Disposable, PluginHost } from "../types";

export const TRAFFIC_PAYLOAD_STREAM = "xsec.traffic.payload";
export const TRAFFIC_PAYLOAD_STREAM_VERSION = 1;
const MAX_FLOW_ID_LENGTH = 256;
const MAX_PACKET_BYTES = 48 * 1024;
const MAX_PACKET_COUNT = 2_048;
const PAYLOAD_READ_TIMEOUT_MS = 10_000;
const encoder = new TextEncoder();

type TrafficPayloadPacket = {
  version: number;
  revision: number;
  index: number;
  count: number;
  flowId: string;
  payload: string;
};

type PayloadOpenResult = { status: "streamed"; flowId: string };
type CollectedPayload = { payload: unknown };

function record(value: unknown, name: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${name}无效`);
  return value as Record<string, unknown>;
}

function integer(value: unknown, name: string, max: number): number {
  if (!Number.isInteger(value) || Number(value) < 0 || Number(value) > max) throw new Error(`${name}无效`);
  return Number(value);
}

function string(value: unknown, name: string, max: number): string {
  if (typeof value !== "string" || !value || value.length > max) throw new Error(`${name}无效`);
  return value;
}

function parsePacket(value: ArrayBuffer): TrafficPayloadPacket {
  if (value.byteLength > MAX_PACKET_BYTES) throw new Error("抓包正文数据分片过大");
  let decoded: unknown;
  try {
    decoded = JSON.parse(new TextDecoder().decode(value));
  } catch {
    throw new Error("抓包正文数据分片不是 JSON");
  }
  const packet = record(decoded, "抓包正文数据分片");
  const fields = ["version", "revision", "index", "count", "flowId", "payload"];
  if (Object.keys(packet).some((field) => !fields.includes(field))) throw new Error("抓包正文数据分片包含未知字段");
  const count = integer(packet.count, "抓包正文分片数量", MAX_PACKET_COUNT);
  if (!count) throw new Error("抓包正文分片数量无效");
  const index = integer(packet.index, "抓包正文分片序号", count - 1);
  const revision = integer(packet.revision, "抓包正文版本", Number.MAX_SAFE_INTEGER);
  if (!revision || packet.version !== TRAFFIC_PAYLOAD_STREAM_VERSION) throw new Error("抓包正文数据版本无效");
  if (typeof packet.payload !== "string") throw new Error("抓包正文分片内容无效");
  return {
    version: packet.version as number,
    revision,
    index,
    count,
    flowId: string(packet.flowId, "流量 ID", MAX_FLOW_ID_LENGTH),
    payload: packet.payload,
  };
}

function parsePayloadDocument(value: string): unknown {
  let document: unknown;
  try {
    document = JSON.parse(value);
  } catch {
    throw new Error("抓包正文不是 JSON");
  }
  const result = record(document, "抓包正文");
  if (Object.keys(result).some((field) => field !== "payload")) throw new Error("抓包正文包含未知字段");
  return result.payload;
}

/** Reassembles one flow's revision and rejects mixed or incomplete packets. */
export class TrafficPayloadCollector {
  private revision?: number;
  private count?: number;
  private readonly chunks = new Map<number, string>();

  constructor(private readonly flowId: string) {}

  accept(value: ArrayBuffer): CollectedPayload | undefined {
    const packet = parsePacket(value);
    if (packet.flowId !== this.flowId) return undefined;
    if (this.revision === undefined) {
      this.revision = packet.revision;
      this.count = packet.count;
    }
    if (packet.revision !== this.revision) throw new Error("抓包正文版本不一致");
    if (packet.count !== this.count) throw new Error("抓包正文分片数量不一致");
    const previous = this.chunks.get(packet.index);
    if (previous !== undefined) throw new Error("抓包正文数据分片重复");
    this.chunks.set(packet.index, packet.payload);
    return this.chunks.size === this.count ? { payload: this.complete() } : undefined;
  }

  complete(): unknown {
    if (!this.count || this.chunks.size !== this.count) throw new Error("抓包正文数据分片不完整");
    return parsePayloadDocument(Array.from({ length: this.count }, (_value, index) => {
      const chunk = this.chunks.get(index);
      if (chunk === undefined) throw new Error("抓包正文数据分片不完整");
      return chunk;
    }).join(""));
  }
}

function payloadOpenResult(value: unknown, flowId: string): PayloadOpenResult {
  const result = record(value, "抓包正文响应");
  if (result.status !== "streamed" || result.flowId !== flowId) throw new Error("抓包正文响应无效");
  return { status: "streamed", flowId };
}

function payloadStream(host: PluginHost, flowId: string): { completion: Promise<unknown>; dispose(): void } {
  const collector = new TrafficPayloadCollector(flowId);
  let subscription: Disposable | undefined;
  let settled = false;
  let resolve!: (payload: unknown) => void;
  let reject!: (reason: unknown) => void;
  let timeout: number | undefined;
  const completion = new Promise<unknown>((nextResolve, nextReject) => { resolve = nextResolve; reject = nextReject; });
  const finish = (result: { payload?: unknown; error?: unknown }) => {
    if (settled) return;
    settled = true;
    if (timeout !== undefined) window.clearTimeout(timeout);
    subscription?.dispose();
    if ("error" in result) reject(result.error);
    else resolve(result.payload);
  };
  timeout = window.setTimeout(() => {
    try { finish({ payload: collector.complete() }); } catch (error) { finish({ error }); }
  }, PAYLOAD_READ_TIMEOUT_MS);
  subscription = host.onData(TRAFFIC_PAYLOAD_STREAM, (packet) => {
    try {
      const payload = collector.accept(packet);
      if (payload) finish(payload);
    } catch (error) {
      finish({ error });
    }
  });
  return {
    completion,
    dispose: () => {
      if (settled) return;
      settled = true;
      if (timeout !== undefined) window.clearTimeout(timeout);
      subscription?.dispose();
    },
  };
}

/** Request a Host-bound body stream after installing the stream listener. */
export async function openTrafficPayload(host: PluginHost, flowId: string): Promise<unknown> {
  return loggedAction("traffic.payload.open", { flowId }, async () => {
    const stream = payloadStream(host, flowId);
    try {
      await host.request("xsec.traffic.payload.open", { flowId }).then((value) => payloadOpenResult(value, flowId));
      return await stream.completion;
    } finally {
      stream.dispose();
    }
  });
}
