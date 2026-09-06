export type Disposable = { dispose(): void };

export type PluginHost = {
  apiVersion: number;
  readonly context?: { readonly kind?: unknown } | null;
  request(method: string, params: unknown): Promise<unknown>;
  onContext(listener: (context: unknown) => void): Disposable;
  onTheme(listener: (theme: Record<string, string>) => void): Disposable;
  onData(stream: string, listener: (payload: ArrayBuffer) => void): Disposable;
};

export type WorkspaceToolContext = {
  kind: "workspace-tool";
  visible: boolean;
  surface: { bindingRevision: string };
  tool: { id: string; kind: string; title: string; entityId?: string };
  workspace: {
    mode: "interactive" | "observe";
    dock: "side" | "bottom";
    canAddComposerReference?: boolean;
  };
};

export type SettingsContext = {
  kind: "settings-page";
  settings: { id: string; page: string };
};

export type PluginContext = WorkspaceToolContext | SettingsContext;

export type MimeCategory =
  | "html" | "script" | "xml" | "otherText"
  | "css" | "images" | "otherBinary" | "unknown";
export type StatusClass = "informational" | "success" | "redirection" | "clientError" | "serverError";
export type TrafficSource = "proxy" | "replay";

export type TrafficFilter = {
  onlyInScope: boolean;
  hideWithoutResponse: boolean;
  onlyParameterized: boolean;
  mimeCategories: MimeCategory[];
  statusClasses: StatusClass[];
  sources: TrafficSource[];
  search: { term: string; regex: boolean; caseSensitive: boolean; negative: boolean } | null;
  extensions: { showOnlyEnabled: boolean; showOnly: string[]; hideEnabled: boolean; hide: string[] };
};

export type FilterSettings = {
  version: 1;
  onlyInScope: boolean;
  hideWithoutResponse: boolean;
  onlyParameterized: boolean;
  mimeCategories: MimeCategory[];
  statusClasses: StatusClass[];
  sources: TrafficSource[];
  searchTerm: string;
  searchRegex: boolean;
  searchCaseSensitive: boolean;
  searchNegative: boolean;
  showOnlyExtensionsEnabled: boolean;
  showOnlyExtensionsText: string;
  hideExtensionsEnabled: boolean;
  hideExtensionsText: string;
};

export type TrafficSummary = {
  flow_id: string;
  timestamp: number;
  scheme: string;
  host: string;
  port?: number | null;
  method: string;
  url: string;
  path: string;
  query?: string | null;
  request_body_size: number;
  status?: number | null;
  response_body_size: number;
  content_type?: string | null;
  mime_category?: MimeCategory | null;
  file_extension?: string | null;
  has_parameters?: boolean;
  duration_ms?: number | null;
  in_scope: boolean;
  capture_source: string;
  truncated: boolean;
};

export type FlowSection = {
  line?: string;
  headers?: [string, string][] | Record<string, string>;
  body?: string;
  bodyTruncated?: boolean;
};

export type FlowSnapshot = {
  request?: FlowSection;
  response?: FlowSection;
  raw_request?: string;
  raw_response?: string;
};

export type TrafficDetail = TrafficSummary & { payload?: unknown };
export type TrafficPage = { items: TrafficSummary[]; next_cursor?: string | null };

export type ReplayAttempt = {
  id: string;
  source_flow_id: string;
  result_flow_id?: string | null;
  scheme: string;
  target_host: string;
  target_port: number;
  host_header: string;
  sni: string;
  status: string;
  response_status?: number | null;
  duration_ms?: number | null;
  error?: string | null;
  created_at: number;
  request_raw: string;
};

export type ReplayResult = {
  attempt?: ReplayAttempt | null;
  result?: TrafficSummary | null;
  response_status?: number | null;
  capture_pending?: boolean;
};

export type PassiveRule = {
  rule_id: string;
  severity: "low" | "medium" | "high" | "critical";
  pattern: string;
  enabled: boolean;
};

export type TrafficSettingsView = { filter: FilterSettings };
export type CaStatus = {
  ca_exists: boolean;
  ca_cert_path?: string | null;
  ca_sha256?: string | null;
  trust_store_kind?: string;
  trust_supported?: boolean;
  trust_imported: boolean;
  trust_detail?: string;
};
