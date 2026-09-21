export const MIN_REPLAY_PORT = 1;
export const MAX_REPLAY_PORT = 65_535;

/** Normalize a replay transport scheme to the supported HTTP choices. */
export function replayScheme(value: string): "http" | "https" {
  return value === "http" ? "http" : "https";
}

/** Return the validation error for an unusable replay host or TCP port. */
export function replayTargetError(host: string, port: number): string | undefined {
  if (!host.trim()) return "请输入连接目标";
  if (!Number.isInteger(port) || port < MIN_REPLAY_PORT || port > MAX_REPLAY_PORT) {
    return `端口必须是 ${MIN_REPLAY_PORT}-${MAX_REPLAY_PORT} 之间的整数`;
  }
  return undefined;
}
