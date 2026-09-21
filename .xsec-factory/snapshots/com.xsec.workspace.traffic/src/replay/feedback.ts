import type { ReplayResult } from "../types";

type ReplayFeedback = { kind: "error" | "success"; message: string };

/** Derive user-visible completion or failure feedback from a replay result. */
export function replayFeedback(response: ReplayResult): ReplayFeedback {
  if (response.attempt?.status === "failed") {
    return { kind: "error", message: response.attempt.error?.trim() || "重放失败" };
  }
  if (response.capture_pending) {
    return { kind: "success", message: "请求已返回，响应流量仍在入库" };
  }
  const status = response.result?.status ?? response.response_status ?? "—";
  return { kind: "success", message: `重放完成：HTTP ${status}` };
}
