#!/usr/bin/env node

const readline = require("node:readline");

const tools = [
  ["attack_path_node_create", "Create an attack-path node"],
  ["attack_path_node_update", "Update an attack-path node"],
  ["attack_path_node_get", "Read an attack-path node"],
  ["attack_path_list", "List attack-path nodes"],
  ["attack_path_finding_add", "Attach a finding to an attack-path node"],
];
const hostMethods = {
  attack_path_node_create: "plugin.attack-path.node_create",
  attack_path_node_update: "plugin.attack-path.node_update",
  attack_path_node_get: "plugin.attack-path.node_get",
  attack_path_list: "plugin.attack-path.tree_list",
  attack_path_finding_add: "plugin.attack-path.finding_add",
};
const activeRequests = new Map();

function response(id, result, error) {
  return JSON.stringify({ jsonrpc: "2.0", id, ...(error ? { error } : { result }) });
}

function toolDescriptors() {
  return tools.map(([name, description]) => ({
    name,
    description,
    inputSchema: inputSchemaFor(name),
  }));
}

function inputSchemaFor(name) {
  const schemas = {
    attack_path_node_create: {
      properties: { parent_id: { type: "string" }, title: { type: "string" }, kind: { type: "string" }, target: { type: "string" }, test_value: { type: "string" }, brief: { type: "string" } },
      required: ["title"],
    },
    attack_path_node_update: {
      properties: { node_id: { type: "string" }, status: { type: "string" }, test_value: { type: "string" }, conclusion: { type: "string" }, subagent_id: { type: "string" }, expected_revision: { type: "integer" } },
      required: ["node_id", "expected_revision"],
    },
    attack_path_node_get: { properties: { node_id: { type: "string" } }, required: ["node_id"] },
    attack_path_finding_add: { properties: { node_id: { type: "string" }, fingerprint: { type: "string" }, kind: { type: "string" }, severity: { type: "string" }, title: { type: "string" }, data: { type: "object" } }, required: ["node_id", "fingerprint", "title"] },
    attack_path_list: { properties: {} },
  };
  return { type: "object", additionalProperties: true, ...(schemas[name] || {}) };
}

class HostDomainError extends Error {
  constructor(message) {
    super(message);
    this.name = "HostDomainError";
  }
}

class JsonRpcError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "JsonRpcError";
    this.code = code;
  }
}

function isJsonRpcRequestId(value) {
  return typeof value === "string" || Number.isInteger(value);
}

function isJsonRpcId(value) {
  return value === undefined || value === null || isJsonRpcRequestId(value);
}

function isJsonRpcRequest(value) {
  return value !== null
    && typeof value === "object"
    && !Array.isArray(value)
    && value.jsonrpc === "2.0"
    && typeof value.method === "string"
    && isJsonRpcId(value.id);
}

function responseId(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  const { id } = value;
  return id === null || isJsonRpcRequestId(id) ? id : null;
}

function hasOwn(value, key) {
  return Object.prototype.hasOwnProperty.call(value, key);
}

function isHostResponse(value, requestId) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  if (value.jsonrpc !== "2.0" || value.id !== requestId) return false;
  const hasResult = hasOwn(value, "result");
  const hasError = hasOwn(value, "error");
  if (hasResult === hasError) return false;
  if (hasResult) return true;
  const error = value.error;
  return error !== null
    && typeof error === "object"
    && !Array.isArray(error)
    && Number.isInteger(error.code)
    && typeof error.message === "string";
}

async function hostCall(method, params, signal) {
  const endpoint = process.env.XSEC_ATTACK_PATH_HOST_RPC;
  if (!endpoint) throw new Error("XSEC_ATTACK_PATH_HOST_RPC is not configured");
  const token = process.env.XSEC_ATTACK_PATH_HOST_TOKEN;
  if (!token) throw new Error("XSEC_ATTACK_PATH_HOST_TOKEN is not configured");
  const headers = { "content-type": "application/json" };
  headers.authorization = `Bearer ${token}`;
  const requestId = Date.now();
  const result = await fetch(endpoint, {
    method: "POST",
    headers,
    signal,
    body: JSON.stringify({ jsonrpc: "2.0", id: requestId, method, params }),
  });
  if (!result.ok) throw new Error(`XSec Host RPC failed: HTTP ${result.status}`);
  const payload = await result.json();
  if (!isHostResponse(payload, requestId)) throw new Error("XSec Host RPC returned an invalid JSON-RPC response");
  if (hasOwn(payload, "error")) throw new HostDomainError(payload.error.message || "XSec Host RPC error");
  return payload.result;
}

async function dispatch(request) {
  if (request.method === "initialize") {
    return { protocolVersion: "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "xsec-attack-path", version: "1.0.0" } };
  }
  if (request.method === "notifications/initialized") return null;
  if (request.method === "notifications/cancelled") {
    const requestId = request.params?.requestId;
    if (requestId !== undefined) activeRequests.get(requestId)?.abort();
    return null;
  }
  if (request.method === "tools/list") return { tools: toolDescriptors() };
  if (request.method === "ping") return {};
  if (request.method !== "tools/call") throw new JsonRpcError(-32601, "Method not found");
  if (!isJsonRpcRequestId(request.id)) throw new JsonRpcError(-32600, "Invalid Request");
  const name = request.params?.name;
  const args = request.params?.arguments === undefined ? {} : request.params.arguments;
  if (!tools.some(([tool]) => tool === name)) throw new JsonRpcError(-32602, "Unknown attack-path tool");
  if (args === null || typeof args !== "object" || Array.isArray(args)) throw new JsonRpcError(-32602, "Tool arguments must be an object");
  const controller = new AbortController();
  activeRequests.set(request.id, controller);
  try {
    const result = await hostCall(hostMethods[name], args, controller.signal);
    const structuredContent = structuredContentFor(name, result);
    return { content: [{ type: "text", text: JSON.stringify(result ?? {}) }], structuredContent };
  } catch (error) {
    if (error instanceof HostDomainError) {
      return { content: [{ type: "text", text: String(error.message || error) }], isError: true };
    }
    throw error;
  } finally {
    activeRequests.delete(request.id);
  }
}

function structuredContentFor(name, result) {
  if (result && typeof result === "object" && !Array.isArray(result)) return result;
  if (name === "attack_path_list" && Array.isArray(result)) return { nodes: result };
  return {};
}

const input = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
input.on("line", async (line) => {
  if (!line.trim()) return;
  let request;
  try {
    request = JSON.parse(line);
  } catch {
    process.stdout.write(`${response(null, null, { code: -32700, message: "Parse error" })}\n`);
    return;
  }
  if (!isJsonRpcRequest(request)) {
    process.stdout.write(`${response(responseId(request), null, { code: -32600, message: "Invalid Request" })}\n`);
    return;
  }
  if (request.method === "tools/call" && !isJsonRpcRequestId(request.id)) {
    process.stdout.write(`${response(responseId(request), null, { code: -32600, message: "Invalid Request" })}\n`);
    return;
  }
  try {
    const result = await dispatch(request);
    if (isJsonRpcRequestId(request.id)) process.stdout.write(`${response(request.id, result)}\n`);
  } catch (error) {
    if (!isJsonRpcRequestId(request.id)) return;
    const code = error instanceof JsonRpcError ? error.code : -32000;
    process.stdout.write(`${response(request.id, null, { code, message: String(error.message || error) })}\n`);
  }
});
