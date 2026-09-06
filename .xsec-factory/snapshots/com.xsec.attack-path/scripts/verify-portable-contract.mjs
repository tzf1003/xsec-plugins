import { readFile } from "node:fs/promises";

const ATTACK_PATH_PLUGIN = "com.xsec.attack-path";
const PLUGIN_ROOT = ".";
const EXPECTED_AGENT_TOOLS = [
  "attack-path-finding-add",
  "attack-path-findings-list",
  "attack-path-list",
  "attack-path-node-create",
  "attack-path-node-delete",
  "attack-path-node-get",
  "attack-path-node-update",
];
const EXPECTED_DEPENDENCY = "^1.2.3";
const EXPECTED_ACTIVATION = "onAgentTool:attack-path-node-create";
const EXPECTED_COMMAND = "./bin/attack-path-mcp";
const EXPECTED_CWD = "${PLUGIN_DATA}";

async function readJson(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

function requireContract(condition, message) {
  if (!condition) throw new Error(message);
}

function sameEntries(actual, expected) {
  return JSON.stringify([...actual].sort()) === JSON.stringify([...expected].sort());
}

const [manifest, catalog, mcp] = await Promise.all([
  readJson(`${PLUGIN_ROOT}/plugin.json`),
  readJson(`${PLUGIN_ROOT}/.codex-plugin/plugin.json`),
  readJson(`${PLUGIN_ROOT}/mcp.json`),
]);
const extension = manifest.extensions?.["com.xsec.desktop"];
const server = mcp.mcpServers?.["attack-path"];
const agentTools = Object.keys(extension?.contributes?.agentTools ?? {});

requireContract(/^2\.\d+\.\d+$/.test(manifest.version), "attack-path must publish a v2 release");
requireContract(catalog.version === manifest.version, "catalog version must match plugin version");
requireContract(extension?.schemaVersion === 2, "attack-path must use schema v2");
requireContract(extension?.activationEvents?.includes(EXPECTED_ACTIVATION), "agent tool activation must name its contribution");
requireContract(
  extension?.dependencies?.required?.["com.xsec.workspace.sub-agent"] === EXPECTED_DEPENDENCY,
  "attack-path must target the published sub-agent contract",
);
requireContract(sameEntries(agentTools, EXPECTED_AGENT_TOOLS), "agent tools must match the native sidecar contract");
requireContract(server?.command === EXPECTED_COMMAND, "attack-path must use the packaged native sidecar");
requireContract(server?.cwd === EXPECTED_CWD, "attack-path runtime data must stay outside the package");

const frontendSource = await readFile(`${PLUGIN_ROOT}/com.xsec.desktop/frontend/index.js`, "utf8");
requireContract(
  /^const\s+SUBAGENT_PLUGIN_ID\s*=\s*"com\.xsec\.workspace\.sub-agent";$/m.test(frontendSource),
  "attack-path frontend must declare the SUBAGENT_PLUGIN_ID contract constant",
);
requireContract(
  /^const\s+SUBAGENT_DETAIL_TOOL_ID\s*=\s*"subagent-detail";$/m.test(frontendSource),
  "attack-path frontend must declare the SUBAGENT_DETAIL_TOOL_ID contract constant",
);
const openSubagentSource = frontendSource.match(
  /^  const openSubagent = async \(subagent, title, button\) => \{[\s\S]*?^  \};$/m,
)?.[0];
requireContract(typeof openSubagentSource === "string", "attack-path frontend must define openSubagent");
requireContract(
  /pluginId:\s*SUBAGENT_PLUGIN_ID/.test(openSubagentSource),
  "attack-path openSubagent must pass pluginId: SUBAGENT_PLUGIN_ID",
);
requireContract(
  /toolId:\s*SUBAGENT_DETAIL_TOOL_ID/.test(openSubagentSource),
  "attack-path openSubagent must pass toolId: SUBAGENT_DETAIL_TOOL_ID",
);
