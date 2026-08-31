import type {
  AssetFilters,
  AssetPage,
  CollectionRun,
  CollectorProvider,
  CollectorSettings,
  ExecutionDefaults,
  ExecutionLogPage,
  ExecutionSnapshot,
  PluginHost,
  Project,
} from "./types";

const ASSET_PAGE_LIMIT = 100;

type StartInput = {
  prompt: string;
  name?: string;
  provider: CollectorProvider;
  workdir?: string;
};

type StartResult = {
  collection_run_id: string;
  run_id?: string;
  process: { id: string };
};

type CredentialKind = "hunter" | "fofa" | "tianyan";

function asArray<T>(value: unknown): T[] {
  if (Array.isArray(value)) return value as T[];
  if (value && typeof value === "object" && Array.isArray((value as { items?: unknown }).items)) {
    return (value as { items: T[] }).items;
  }
  throw new Error("Host RPC 返回了无效列表数据");
}

function asRecord<T>(value: unknown): T {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Host RPC 返回了无效对象数据");
  return value as T;
}

function createRunApi(host: PluginHost) {
  return {
    async defaults(): Promise<ExecutionDefaults> {
      return asRecord<ExecutionDefaults>(await host.request("xsec.asset-discovery.defaults.get", {}));
    },
    async runs(): Promise<CollectionRun[]> {
      return asArray<CollectionRun>(await host.request("xsec.asset-discovery.runs.list", {}));
    },
    async start(input: StartInput): Promise<StartResult> {
      return asRecord<StartResult>(await host.request("xsec.asset-discovery.runs.start", input));
    },
    async stop(runId: string) {
      return host.request("xsec.asset-discovery.runs.stop", { runId });
    },
    async deleteRun(runId: string) {
      return host.request("xsec.asset-discovery.runs.delete", { runId });
    },
    async execution(runId: string): Promise<ExecutionSnapshot> {
      return asRecord<ExecutionSnapshot>(await host.request("xsec.asset-discovery.runs.execution.get", { runId }));
    },
    async logs(runId: string, cursor?: string): Promise<ExecutionLogPage> {
      return asRecord<ExecutionLogPage>(await host.request("xsec.asset-discovery.runs.logs.list", {
        runId,
        cursor,
        limit: 50,
      }));
    },
  };
}

function createAssetApi(host: PluginHost) {
  return {
    async assets(filters: AssetFilters): Promise<AssetPage> {
      const offset = (filters.page - 1) * filters.pageSize;
      return asRecord<AssetPage>(await host.request("xsec.asset-discovery.assets.list", {
        runId: filters.runId,
        provider: filters.provider,
        query: filters.query,
        importedOnly: filters.importedOnly,
        offset,
        limit: Math.min(filters.pageSize, ASSET_PAGE_LIMIT),
      }));
    },
    async projects(): Promise<Project[]> {
      return asArray<Project>(await host.request("xsec.asset-discovery.projects.list", {}));
    },
    async importAssets(ids: string[], projectId: string) {
      return asRecord<{ created: number; skipped: number; failed: number }>(
        await host.request("xsec.asset-discovery.assets.import", { ids, projectId }),
      );
    },
    async deleteAssets(ids: string[]) {
      return asRecord<{ deleted: number }>(await host.request("xsec.asset-discovery.assets.delete", { ids }));
    },
  };
}

function createSettingsApi(host: PluginHost) {
  return {
    async settings(): Promise<CollectorSettings> {
      return asRecord<CollectorSettings>(await host.request("xsec.asset-discovery.settings.get", {}));
    },
    async saveSettings(input: Omit<CollectorSettings, "hunterApiKeyConfigured" | "fofaApiKeyConfigured" | "tianyanApiKeyConfigured">) {
      return asRecord<CollectorSettings>(await host.request("xsec.asset-discovery.settings.set", input));
    },
    async saveCredential(kind: CredentialKind, value: string) {
      return host.request("xsec.asset-discovery.credentials.set", { kind, value });
    },
    async clearCredential(kind: CredentialKind) {
      return host.request("xsec.asset-discovery.credentials.clear", { kind });
    },
    async openSettings() {
      return host.request("xsec.plugin.settings.open", {});
    },
  };
}

export function createAssetDiscoveryApi(host: PluginHost) {
  return {
    ...createRunApi(host),
    ...createAssetApi(host),
    ...createSettingsApi(host),
  };
}

export type AssetDiscoveryApi = ReturnType<typeof createAssetDiscoveryApi>;
