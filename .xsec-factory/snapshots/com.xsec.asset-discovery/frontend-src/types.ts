export type CollectorProvider = "hunter" | "fofa";
export type CollectionStatusFilter = "all" | "running" | "completed" | "failed" | "cancelled";

export type CollectionRun = {
  id: string;
  session_id?: string | null;
  name: string;
  provider: string;
  scope_prompt: string;
  approval_mode?: "auto" | "full";
  status: string;
  total: number;
  created_at: number;
  updated_at: number;
  finished_at: number | null;
  terminal_reason: string | null;
  failure_code: string | null;
  failure_message: string | null;
};

export type DiscoveredAsset = {
  id: string;
  run_id: string | null;
  type: string;
  raw_value: string;
  normalized_value: string;
  scheme: string | null;
  host: string | null;
  port: number | null;
  path_prefix: string | null;
  source_provider: string | null;
  imported_project_ids: string[];
  imported: boolean;
  imported_at: number | null;
  created_at: number;
};

export type AssetPage = {
  items: DiscoveredAsset[];
  total: number;
};

export type Project = {
  id: string;
  name: string;
  code: string;
  status: string;
};

export type CollectorSettings = {
  provider: CollectorProvider | string;
  hunterApiBaseUrl: string;
  fofaApiBaseUrl: string;
  hunterSkillPath: string;
  fofaSkillPath: string;
  resolvedHunterSkillPath?: string;
  resolvedFofaSkillPath?: string;
  hunterApiKeyConfigured: boolean;
  fofaApiKeyConfigured: boolean;
  tianyanApiKeyConfigured: boolean;
};

export type ExecutionDefaults = {
  approval_mode?: "auto" | "full";
};

export type ExecutionLine = {
  timestamp: number;
  direction: "client_to_agent" | "agent_to_client" | "process";
  text: string;
};

export type ExecutionLogPage = {
  lines: ExecutionLine[];
  next_cursor: string | null;
  truncated?: boolean;
};

export type ExecutionSnapshot = {
  run: CollectionRun;
  session: SessionSnapshot | null;
  /** The Host retained the most recent bounded projection for the sandbox. */
  truncated?: boolean;
};

export type SessionMessage = {
  message_id: string;
  sequence?: number;
  role: string;
  text?: string;
  thought?: string;
  completed?: boolean;
};

export type ToolCall = {
  tool_call_id: string;
  sequence?: number;
  name?: string;
  status?: string;
  raw_input?: unknown;
  content?: unknown;
  raw_output?: unknown;
};

export type SessionSnapshot = {
  session_id?: string;
  cwd?: string;
  status?: string;
  messages?: SessionMessage[];
  active_tool_calls?: Record<string, ToolCall>;
};

export type AssetFilters = {
  runId?: string;
  provider?: string;
  query?: string;
  importedOnly: boolean;
  page: number;
  pageSize: number;
};

export type PluginHost = {
  context: Record<string, unknown> | null;
  request(method: string, params: Record<string, unknown>): Promise<unknown>;
  onTheme(listener: (theme: Record<string, string>) => void): { dispose(): void };
};
