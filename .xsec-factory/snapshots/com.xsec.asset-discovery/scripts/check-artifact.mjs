import { readFile } from "node:fs/promises";

const SEMVER_PATTERN = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/;
const NATIVE_PERMISSIONS = ["mcp.servers.register", "native.execute"];
const MCP_SERVERS = ["asset-fofa", "asset-hunter", "asset-normalize"];
const artifact = new URL("../com.xsec.desktop/frontend/index.js", import.meta.url);
const manifestPath = new URL("../plugin.json", import.meta.url);
const codexManifestPath = new URL("../.codex-plugin/plugin.json", import.meta.url);
const packagePath = new URL("../package.json", import.meta.url);
const mcpPath = new URL("../mcp.json", import.meta.url);
const skillPath = new URL("../skills/asset-discovery/SKILL.md", import.meta.url);
const source = await readFile(artifact, "utf8");
const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
const codexManifest = JSON.parse(await readFile(codexManifestPath, "utf8"));
const packageMetadata = JSON.parse(await readFile(packagePath, "utf8"));
const mcp = JSON.parse(await readFile(mcpPath, "utf8"));
const skill = await readFile(skillPath, "utf8");

if (!source.includes("export function activate(host)") || /from\s*["']\.?\//.test(source)) {
  throw new Error("资产发现前端制品必须是单一 ESM 模块");
}
const releaseVersions = [manifest.version, codexManifest.version, packageMetadata.version];
if (!releaseVersions.every((version) => typeof version === "string" && SEMVER_PATTERN.test(version)) || new Set(releaseVersions).size !== 1) {
  throw new Error("资产发现发布元数据必须使用一致的有效 SemVer 版本");
}
const desktop = manifest.extensions?.["com.xsec.desktop"];
if (desktop?.schemaVersion !== 2 || !NATIVE_PERMISSIONS.every((permission) => desktop.permissions?.[permission])) {
  throw new Error("资产发现必须声明 schema v2 原生 MCP 权限");
}
const servers = Object.keys(mcp.mcpServers ?? {}).sort();
if (JSON.stringify(servers) !== JSON.stringify(MCP_SERVERS)) {
  throw new Error("资产发现 MCP server 集合不正确");
}
const agentTools = desktop.contributes?.agentTools ?? {};
if (!MCP_SERVERS.every((server) => Object.values(agentTools).some((tool) => tool?.mcpServer === server))) {
  throw new Error("资产发现必须公开每个 MCP server 的受限 Agent Tool");
}
if (!skill.startsWith("---\nname: asset-discovery\n")) {
  throw new Error("资产发现 Skill frontmatter 不正确");
}
