import type { PluginHost, ReplayResult, TrafficDetail, TrafficFilter, TrafficPage } from "../types";
import { loggedAction } from "../logging";
import { openTrafficPayload } from "./traffic-payload";
import { replayAttempts, replayResult, trafficDetail, trafficPage } from "./traffic-parse";

const PAGE_SIZE = 100;

/** List traffic through the host boundary. */
export async function listTraffic(
  host: PluginHost,
  cursor: string | undefined,
  filter: TrafficFilter,
): Promise<TrafficPage> {
  const params = { limit: PAGE_SIZE, filter, ...(cursor ? { cursor } : {}) };
  return trafficPage(await host.request("xsec.traffic.list", params));
}

/** Load traffic through the host boundary. */
export async function getTraffic(host: PluginHost, flowId: string): Promise<TrafficDetail> {
  const detail = trafficDetail(await host.request("xsec.traffic.get", { flowId }));
  const payload = await openTrafficPayload(host, flowId);
  return payload === undefined ? detail : { ...detail, payload };
}

/** Load replay attempts through the host boundary. */
export async function getReplayAttempts(host: PluginHost, flowId: string) {
  return replayAttempts(await host.request("xsec.traffic.replay-attempts", { flowId }));
}

/** Submit a validated editable replay request through the host boundary. */
export async function replayTraffic(host: PluginHost, input: {
  sourceFlowId: string;
  rawRequest: string;
  scheme: "http" | "https";
  targetHost: string;
  targetPort: number;
  confirmSensitiveHostChange: boolean;
}): Promise<ReplayResult> {
  return loggedAction("traffic.replay", {
    scheme: input.scheme,
    targetPort: input.targetPort,
    sensitiveHostChangeConfirmed: input.confirmSensitiveHostChange,
  }, async () => replayResult(await host.request("xsec.traffic.replay", input)));
}

/** Open traffic tool through the host boundary. */
export async function openTrafficTool(
  host: PluginHost,
  options: {
    toolId: "request-detail" | "traffic-replay";
    flowId: string;
    title?: string;
  },
): Promise<void> {
  await loggedAction("traffic.tool.open", { toolId: options.toolId }, async () => {
    await host.request("xsec.workspace.tool.open", {
      toolId: options.toolId,
      entityId: options.flowId,
      ...(options.title ? { title: options.title } : {}),
    });
  });
}

/** Add traffic reference through the host boundary. */
export async function addTrafficReference(host: PluginHost, flowId: string): Promise<void> {
  await loggedAction("traffic.reference.add", {}, async () => {
    await host.request("xsec.traffic.reference.add", { flowId });
  });
}
